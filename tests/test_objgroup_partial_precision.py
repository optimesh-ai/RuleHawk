"""OBJGROUP-partial-precision: partial object-group soundness tests.

When an object-group has SOME unresolved members:
  (a) If any resolved member already proves a real leak, the verdict is CRITICAL
      (not INDETERMINATE) — the resolved member's space is exact, and adding
      more members can only expand reachability, never remove the proven leak.
  (b) If no resolved member covers the forbidden flow, the verdict is still
      INDETERMINATE from the opaque ACE for the unresolved portion — no false
      sharpening.
  (c) A fully-resolved clean group is unaffected and stays PASS.

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


def _kinds(aces):
    return {f.kind for f in check_segmentation(aces, _SEG)}


# (a) Partial group whose resolved member IS in the source zone ->
#     proven leak -> CRITICAL, not INDETERMINATE.
def test_partial_group_resolved_member_proves_leak_emits_critical():
    cfg = (
        "object-group network CORP_NET\n"
        " network-object 10.20.0.1 255.255.255.255\n"  # host in CORP zone (resolved)
        " network-object UNDEFINED_OBJ\n"              # undefined reference -> bad member
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended CORP-OUT\n"
        " permit tcp object-group CORP_NET object-group PCI_NET eq 445\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(aces)

    # The resolved 10.20.0.1/32 host -> PCI:445 is a proven CORP->PCI violation.
    assert "segmentation-violation" in kinds, (
        "resolved member proves CORP->PCI:445 leak; expect CRITICAL"
    )
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"
    assert "segmentation-indeterminate" not in kinds, (
        "CRITICAL should be reported (segcheck breaks on first hit per assertion)"
    )

    # Structural check: precise ACE first, opaque ACE second.
    precise = [a for a in aces if not a.imprecise]
    opaque  = [a for a in aces if a.imprecise]
    assert len(precise) == 1, "exactly one precise ACE for the resolved member"
    assert len(opaque) == 1, "exactly one opaque ACE for the unresolved remainder"
    assert precise[0].src.prefixlen == 32        # host /32
    assert precise[0].dst_port.lo == 445 and precise[0].dst_port.hi == 445

    # Notes should surface the partial resolution.
    assert any("partially resolved" in n for n in notes)


# (b) Partial group whose resolved member is NOT in the source zone ->
#     no proven leak -> INDETERMINATE, never false CRITICAL.
def test_partial_group_resolved_member_not_in_source_zone_stays_indeterminate():
    cfg = (
        "object-group network MIXED_NET\n"
        " network-object 10.30.0.0 255.255.0.0\n"  # DMZ, NOT in CORP zone (resolved)
        " network-object UNDEFINED_OBJ\n"           # undefined -> bad member
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended MIXED-OUT\n"
        " permit tcp object-group MIXED_NET object-group PCI_NET eq 445\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(aces)

    # Resolved member (10.30/16, DMZ) has no intersection with CORP zone (10.20/16),
    # so it cannot prove a CORP->PCI leak. The opaque ACE covers the unresolved
    # portion and correctly produces INDETERMINATE.
    assert "segmentation-indeterminate" in kinds, (
        "no resolved member covers CORP zone; unresolved remainder must stay INDETERMINATE"
    )
    assert "segmentation-violation" not in kinds, "must not invent a false CRITICAL"
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"

    # Parser still emits precise + opaque ACEs (partial resolution happened).
    precise = [a for a in aces if not a.imprecise]
    opaque  = [a for a in aces if a.imprecise]
    assert len(precise) == 1   # 10.30/16 -> PCI:445
    assert len(opaque) == 1    # unresolved remainder
    assert any("partially resolved" in n for n in notes)


# (c) Fully-resolved clean group (no bad members, no forbidden path) stays PASS.
#     This is a regression guard: partial resolution must not disturb the normal path.
def test_fully_resolved_clean_group_stays_pass():
    cfg = (
        "object-group network DMZ_NET\n"
        " network-object 10.30.0.0 255.255.0.0\n"
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended DMZ-OUT\n"
        " permit tcp object-group DMZ_NET object-group PCI_NET eq 443\n"  # HTTPS, not 445
        " permit tcp object-group DMZ_NET object-group DMZ_NET eq 445\n"  # same-zone, not PCI
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(aces)

    # No CORP->PCI:445 path; full resolution took effect; nothing partial.
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds

    # All ACEs are precise (full resolution, no opaque fallback needed).
    assert all(not a.imprecise for a in aces)
    assert not any("partially resolved" in n for n in notes)


# Extra soundness guard: an entirely-undefined group (no members in defs at all)
# still falls fully to opaque — partial mode produces (None, True) -> None return
# -> opaque fallback.  No false CRITICAL, no false PASS.
def test_entirely_undefined_group_still_opaque_not_partial():
    cfg = (
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group NONEXISTENT object-group PCI_NET eq 445\n"
    )  # NONEXISTENT is never defined -> _resolve_nets_partial returns (None, True)
    aces, notes = parse_acls(cfg)
    kinds = _kinds(aces)

    # Should produce exactly one opaque ACE (the full-opaque fallback, not partial).
    assert len(aces) == 1 and aces[0].imprecise is True
    assert "segmentation-indeterminate" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" not in kinds
    # The fallback path, not partial resolution — note says "unmodeled (object-group)".
    assert any("unmodeled (object-group)" in n for n in notes)
