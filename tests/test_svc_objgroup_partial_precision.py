"""SVCGROUP-partial-precision: partial service object-group soundness tests.

When a service object-group (object-group service / object service) has SOME
unresolved members:
  (a) If any resolved member already proves a real forbidden-port leak, the
      verdict is CRITICAL (not INDETERMINATE) — the resolved member's space is
      exact, and adding more unresolved members can only expand reachability,
      never remove the already-proven leak.
  (b) If no resolved member covers the forbidden port, the verdict is still
      INDETERMINATE from the opaque ACE for the unresolved portion — no false
      sharpening.
  (c) A fully-resolved clean service group is unaffected and stays PASS
      (regression guard).
  (d) A service group whose ALL members are bad (entirely unresolvable) still
      falls to a single full-opaque ACE — no spurious PASS or CRITICAL.

Soundness contract: a CRITICAL verdict requires a concrete witness flow that a
precise (non-imprecise) ACE actually permits.  The opaque remainder ACE is
always present and marked imprecise, so it can never produce a CRITICAL on its
own — only INDETERMINATE.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls          # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# Canonical segmentation policy: CORP must not reach PCI on tcp/445.
_SEG = {
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}

_SRC = "10.20.0.0/16"
_DST = "10.10.0.0/16"


def _kinds(cfg):
    aces, _ = parse_acls(cfg)
    return {f.kind for f in check_segmentation(aces, _SEG)}


# (a) Partial service group whose resolved member covers the forbidden port ->
#     proven leak -> CRITICAL, not INDETERMINATE.
def test_partial_svc_group_resolved_member_proves_leak_emits_critical():
    cfg = (
        "object-group service MIXED_SVC tcp\n"
        " port-object eq 445\n"               # resolved: tcp:445
        " port-object eq BOGUS_SVC_NAME\n"    # bad: unknown service name
        "ip access-list extended CORP-OUT\n"
        f" permit tcp {_SRC} {_DST} object-group MIXED_SVC\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(cfg)

    # The resolved tcp:445 member is a proven CORP->PCI:445 violation.
    assert "segmentation-violation" in kinds, (
        "resolved tcp:445 member proves CORP->PCI:445 leak; expect CRITICAL"
    )
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"
    assert "segmentation-indeterminate" not in kinds, (
        "CRITICAL should be reported (segcheck breaks on first hit per assertion)"
    )

    # Structural check: exactly one precise ACE for tcp:445 + one opaque ACE.
    precise = [a for a in aces if not a.imprecise]
    opaque  = [a for a in aces if a.imprecise]
    assert len(precise) == 1, "exactly one precise ACE for resolved tcp:445"
    assert len(opaque) == 1, "exactly one opaque ACE for the unresolved remainder"
    assert precise[0].dst_port.lo == 445 and precise[0].dst_port.hi == 445

    # Notes must surface the partial resolution.
    assert any("partially resolved" in n for n in notes)


# (b) Partial service group whose resolved member does NOT cover the forbidden
#     port -> no proven leak -> INDETERMINATE, never false CRITICAL.
def test_partial_svc_group_resolved_member_not_covering_forbidden_port_stays_indeterminate():
    cfg = (
        "object-group service SAFE_SVC tcp\n"
        " port-object eq 80\n"                # resolved: tcp:80 (not forbidden)
        " port-object eq BOGUS_SVC_NAME\n"    # bad: unknown service name
        "ip access-list extended CORP-OUT\n"
        f" permit tcp {_SRC} {_DST} object-group SAFE_SVC\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(cfg)

    # Resolved member (tcp:80) does not cover port 445; the opaque ACE covers
    # the unresolved portion and correctly produces INDETERMINATE.
    assert "segmentation-indeterminate" in kinds, (
        "no resolved member covers port 445; unresolved remainder must stay INDETERMINATE"
    )
    assert "segmentation-violation" not in kinds, "must not invent a false CRITICAL"
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"

    # Structural check: one precise ACE (tcp:80) + one opaque ACE.
    precise = [a for a in aces if not a.imprecise]
    opaque  = [a for a in aces if a.imprecise]
    assert len(precise) == 1, "one precise ACE for tcp:80"
    assert len(opaque) == 1, "one opaque ACE for the unresolved remainder"
    assert precise[0].dst_port.lo == 80 and precise[0].dst_port.hi == 80
    assert any("partially resolved" in n for n in notes)


# (c) Fully-resolved clean service group (no bad members, no forbidden port)
#     stays PASS. Regression guard: partial resolution must not disturb the
#     normal path.
def test_fully_resolved_svc_group_no_forbidden_port_stays_pass():
    cfg = (
        "object-group service WEBONLY tcp\n"
        " port-object eq 80\n"
        " port-object eq 443\n"
        "ip access-list extended CORP-OUT\n"
        f" permit tcp {_SRC} {_DST} object-group WEBONLY\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(cfg)

    # Neither port 80 nor 443 is forbidden; all members resolve exactly.
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds

    # All ACEs are precise (full resolution succeeded; no opaque fallback).
    assert all(not a.imprecise for a in aces)
    assert not any("partially resolved" in n for n in notes)


# (d) A service group defined but with ALL members bad (entirely unresolvable)
#     still produces a single full-opaque ACE — no spurious verdict.
def test_all_bad_svc_group_members_still_opaque():
    cfg = (
        "object-group service ALL_BAD tcp\n"
        " port-object eq BOGUS1\n"            # bad
        " port-object eq BOGUS2\n"            # bad
        "ip access-list extended OUT\n"
        f" permit tcp {_SRC} {_DST} object-group ALL_BAD\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(cfg)

    # _resolve_svcs_partial returns (None, True) -> _resolve_entry returns None
    # -> caller falls back to a single full-opaque ACE.
    assert len(aces) == 1 and aces[0].imprecise is True
    assert "segmentation-indeterminate" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" not in kinds
    # Note from the fallback path (not partial-resolution path).
    assert any("unmodeled (object-group)" in n for n in notes)
