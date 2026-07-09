"""PAN-OS address partial-precision: soundness tests.

When a PAN-OS security rule's source/destination mixes resolved members
(address objects, static groups, literal CIDRs) with unresolvable ones
(fqdn, ip-wildcard, dynamic address-groups, undefined names), the parser now
applies the partial-precision pattern instead of keeping only the resolved
subset marked imprecise:

  (a) If a resolved member already proves a forbidden flow is permitted, the
      verdict is CRITICAL (not INDETERMINATE) — the resolved member's space is
      exact, and adding more unresolved members can only expand reachability,
      never remove the proven flow.
  (b) If the resolved members do NOT cover the forbidden flow, the verdict is
      INDETERMINATE from the opaque ACE for the unresolved portion — crucially
      NOT a false PASS: before this fix the modeled space was a SUBSET of the
      real match (the fqdn/dynamic members were dropped), so segcheck skipped
      the permit as a candidate and emitted `segmentation-ok` for a rule the
      firewall does not actually enforce that way.
  (c) A rule with fully resolvable addresses (no unresolved members) is
      unaffected and produces PASS when appropriate — regression guard.
  (d) A rule where ALL address values in a dimension are unresolved produces a
      single opaque any-net ACE, not a partial emission — no false CRITICAL
      from an unknown source/destination.
  (e) When another imprecision source (e.g. an unresolved service) blocks the
      partial path, the unresolved dimension is widened to ANY (not kept as the
      resolved subset) so the over-approximation invariant still holds — the
      verdict is INDETERMINATE, never a false PASS.

Soundness contract: a CRITICAL verdict requires a concrete witness flow that a
PRECISE (imprecise=False) ACE actually permits.  The trailing opaque ACE is
always imprecise, so it can never produce CRITICAL on its own — only
INDETERMINATE.  This is identical to the contract in
test_junos_addr_partial_precision.py (and test_objgroup_partial_precision.py
for Cisco), extended to PAN-OS address objects and groups.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_panos import parse_panos        # noqa: E402
from rulehawk.segcheck import check_segmentation    # noqa: E402

# Canonical segmentation policy: CORP must not reach PCI on tcp/445.
_SEG = {
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def _kinds(aces):
    return {f.kind for f in check_segmentation(aces, _SEG)}


# ── (a) Partial: resolved member IS in the CORP zone → proven leak → CRITICAL ──
def test_partial_addr_resolved_member_proves_leak_emits_critical():
    cfg = """
    set address corp-host ip-netmask 10.20.0.1/32
    set address ext-api fqdn api.example.com
    set address-group mixed static [ corp-host ext-api ]
    set service svc-smb protocol tcp port 445
    set rulebase security rules BAD from any to any source mixed destination 10.10.0.0/16 application any service svc-smb action allow
    """
    aces, notes = parse_panos(cfg)
    kinds = _kinds(aces)

    # The resolved corp-host (10.20.0.1/32) is inside CORP (10.20.0.0/16) and
    # the rule permits it toward PCI:445 — a proven violation.
    assert "segmentation-violation" in kinds, (
        "resolved 10.20.0.1/32 (CORP) proves CORP->PCI:445 leak; expect CRITICAL"
    )
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"

    # Structural check: one precise ACE for the resolved member, one opaque ACE.
    precise = [a for a in aces if not a.imprecise]
    opaque = [a for a in aces if a.imprecise]
    assert len(precise) == 1, "exactly one precise ACE for the resolved member"
    assert len(opaque) == 1, "exactly one opaque ACE for the unresolved remainder"
    assert str(precise[0].src) == "10.20.0.1/32"
    assert str(precise[0].dst) == "10.10.0.0/16"
    assert precise[0].dst_port.lo == 445 and precise[0].dst_port.hi == 445
    assert opaque[0].src_any and opaque[0].dst_any

    # Note must surface the partial resolution.
    assert any("partially resolved" in n for n in notes)


# ── (b) Partial: resolved member NOT in CORP → INDETERMINATE, never a false PASS ──
def test_partial_addr_resolved_member_outside_corp_no_false_pass():
    # The exact false-PASS scenario: a static group mixing a resolved subnet
    # OUTSIDE the CORP zone with an fqdn that (on the real firewall) may well
    # cover CORP. Pre-fix, only 192.168.1.0/24 was modeled, segcheck found no
    # intersecting permit, and emitted `segmentation-ok` — a PASS the firewall
    # does not enforce.
    cfg = """
    set address branch-net ip-netmask 192.168.1.0/24
    set address corp-portal fqdn portal.corp.example.com
    set address-group mixed static [ branch-net corp-portal ]
    set service svc-smb protocol tcp port 445
    set rulebase security rules MIXED from any to any source mixed destination 10.10.0.0/16 application any service svc-smb action allow
    """
    aces, notes = parse_panos(cfg)
    kinds = _kinds(aces)

    # The resolved 192.168.1.0/24 has no intersection with CORP (10.20.0.0/16),
    # so the precise ACE cannot prove a CORP->PCI:445 violation.  The opaque ACE
    # covers the unresolved fqdn remainder and yields INDETERMINATE.
    assert "segmentation-indeterminate" in kinds, (
        "unresolved fqdn remainder must keep the assertion INDETERMINATE"
    )
    assert "segmentation-violation" not in kinds, "must not invent a false CRITICAL"
    assert "segmentation-ok" not in kinds, (
        "the pre-fix bug: resolved-subset-only modeling produced a false PASS"
    )

    # Structural: one precise ACE (branch → PCI:445) + one opaque ACE.
    precise = [a for a in aces if not a.imprecise]
    opaque = [a for a in aces if a.imprecise]
    assert len(precise) == 1
    assert len(opaque) == 1
    assert str(precise[0].src) == "192.168.1.0/24"
    assert precise[0].dst_port.lo == 445 and precise[0].dst_port.hi == 445
    assert any("partially resolved" in n for n in notes)


# ── (c) Fully resolved clean rule is unaffected — regression guard ──────────
def test_fully_resolved_rule_stays_precise_no_opaque():
    cfg = """
    set address corp-net ip-netmask 10.20.0.0/16
    set address pci-net ip-netmask 10.10.0.0/16
    set service svc-tls protocol tcp port 443
    set rulebase security rules SAFE from any to any source corp-net destination pci-net application any service svc-tls action allow
    """
    aces, notes = parse_panos(cfg)
    kinds = _kinds(aces)

    # Exact rule: CORP->PCI on tcp/443 (not 445) — segcheck policy checks
    # tcp/445, so this is clean.
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds

    # All ACEs are precise; no opaque fallback added.
    assert all(not a.imprecise for a in aces), (
        "fully resolved rule must produce precise ACEs"
    )
    assert len(aces) == 1
    assert not any("partially resolved" in n for n in notes)


# ── (d) ALL source addresses unresolved → opaque fallback, not partial ──────
def test_all_unresolved_src_stays_fully_opaque():
    cfg = """
    set address-group dyn-corp dynamic filter "tag.corp"
    set service svc-smb protocol tcp port 445
    set rulebase security rules OPAQUE from any to any source dyn-corp destination 10.10.0.0/16 application any service svc-smb action allow
    """
    aces, notes = parse_panos(cfg)
    kinds = _kinds(aces)

    # dyn-corp is a dynamic group (no fixed member set) → nothing resolved →
    # any-net fallback → single opaque ACE.  No resolved src exists, so partial
    # precision cannot prove a CRITICAL.
    assert len(aces) == 1, "all-unresolved src must produce exactly one opaque ACE"
    assert aces[0].imprecise is True
    assert aces[0].src_any, "all-unresolved src falls back to any"

    assert "segmentation-indeterminate" in kinds
    assert "segmentation-violation" not in kinds, "must not emit a false CRITICAL"
    assert "segmentation-ok" not in kinds

    # The note surfaces the dynamic group; no 'partially resolved' note.
    assert not any("partially resolved" in n for n in notes)
    assert any("dyn-corp" in n for n in notes)


# ── (e) Other imprecision blocks partial → unresolved dim widens to ANY ─────
def test_blocked_partial_widens_unresolved_dim_no_false_pass():
    # An unresolved SERVICE taints every combo, so the partial path is blocked.
    # The source still contains an unresolved fqdn member: keeping only the
    # resolved 192.168.1.0/24 would under-approximate (segcheck would skip the
    # permit → false PASS).  The unresolved dimension must widen to ANY so the
    # imprecise ACE intersects the assertion and yields INDETERMINATE.
    cfg = """
    set address branch-net ip-netmask 192.168.1.0/24
    set address corp-portal fqdn portal.corp.example.com
    set address-group mixed static [ branch-net corp-portal ]
    set rulebase security rules R from any to any source mixed destination 10.10.0.0/16 application any service svc-undefined action allow
    """
    aces, notes = parse_panos(cfg)
    kinds = _kinds(aces)

    assert all(a.imprecise for a in aces), (
        "blocked partial (unresolved service) must keep every ACE imprecise"
    )
    assert all(a.src_any for a in aces), (
        "unresolved src members must widen the src dimension to ANY, not keep "
        "the resolved subset (under-approximation → false PASS)"
    )
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"
    assert "segmentation-violation" not in kinds, (
        "imprecise ACEs must never prove a CRITICAL"
    )
    assert "segmentation-indeterminate" in kinds
    assert not any("partially resolved" in n for n in notes)
