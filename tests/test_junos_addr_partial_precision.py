"""Junos address partial-precision: soundness tests.

When a Junos firewall-filter term has source-address or destination-address
values that mix resolvable CIDRs with unresolvable named address-book
references (entries absent from the config snippet), the parser now applies
the partial-precision pattern instead of collapsing the whole term to imprecise:

  (a) If the resolved CIDR member already proves a forbidden flow is permitted,
      the verdict is CRITICAL (not INDETERMINATE) — the resolved member's space
      is exact, and adding more unresolved members can only expand reachability,
      never remove the proven flow.
  (b) If the resolved member does NOT cover the forbidden flow, the verdict is
      INDETERMINATE from the opaque ACE for the unresolved portion — no false
      sharpening.
  (c) A term with fully resolvable addresses (no named references) is unaffected
      and produces PASS when appropriate — regression guard.
  (d) A term where ALL address values are unresolved names produces a single
      opaque ACE (the any-net fallback), not a partial emission — no false
      CRITICAL from an unknown source/destination.

Soundness contract: a CRITICAL verdict requires a concrete witness flow that a
PRECISE (imprecise=False) ACE actually permits.  The trailing opaque ACE is
always imprecise, so it can never produce CRITICAL on its own — only
INDETERMINATE.  This is identical to the contract in test_objgroup_partial_precision.py
for the Cisco object-group case, extended to Junos named address references.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_junos import parse_junos       # noqa: E402
from rulehawk.segcheck import check_segmentation   # noqa: E402

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
    firewall { family inet { filter F {
        term BAD {
            from {
                source-address [ 10.20.0.1/32 CORP-EXTRA ];
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 445;
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    kinds = _kinds(aces)

    # The resolved 10.20.0.1/32 host is inside CORP (10.20.0.0/16) and
    # the term permits it toward PCI:445 — a proven violation.
    assert "segmentation-violation" in kinds, (
        "resolved 10.20.0.1/32 (CORP) proves CORP->PCI:445 leak; expect CRITICAL"
    )
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"

    # Structural check: one precise ACE for the resolved member, one opaque ACE.
    precise = [a for a in aces if not a.imprecise]
    opaque  = [a for a in aces if a.imprecise]
    assert len(precise) == 1, "exactly one precise ACE for the resolved CIDR"
    assert len(opaque) == 1, "exactly one opaque ACE for the unresolved remainder"
    assert str(precise[0].src) == "10.20.0.1/32"
    assert str(precise[0].dst) == "10.10.0.0/16"
    assert precise[0].dst_port.lo == 445 and precise[0].dst_port.hi == 445
    assert opaque[0].src_any and opaque[0].dst_any

    # Note must surface the partial resolution.
    assert any("partially resolved" in n for n in notes)


# ── (b) Partial: resolved member is NOT in CORP zone → no proven leak → INDETERMINATE ──
def test_partial_addr_resolved_member_outside_corp_stays_indeterminate():
    cfg = """
    firewall { family inet { filter F {
        term MIXED {
            from {
                source-address [ 10.30.0.0/16 CORP-UNKNOWN ];
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 445;
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    kinds = _kinds(aces)

    # The resolved 10.30.0.0/16 (DMZ) has no intersection with CORP (10.20.0.0/16),
    # so the precise ACE cannot prove a CORP->PCI:445 violation.  The opaque ACE
    # covers the unresolved CORP-UNKNOWN remainder and yields INDETERMINATE.
    assert "segmentation-indeterminate" in kinds, (
        "resolved 10.30/16 (DMZ) does not cover CORP zone; unresolved remainder stays INDETERMINATE"
    )
    assert "segmentation-violation" not in kinds, "must not invent a false CRITICAL"
    assert "segmentation-ok" not in kinds, "must not produce a false PASS"

    # Structural: one precise ACE (DMZ → PCI:445) + one opaque ACE.
    precise = [a for a in aces if not a.imprecise]
    opaque  = [a for a in aces if a.imprecise]
    assert len(precise) == 1
    assert len(opaque) == 1
    assert str(precise[0].src) == "10.30.0.0/16"
    assert precise[0].dst_port.lo == 445 and precise[0].dst_port.hi == 445
    assert any("partially resolved" in n for n in notes)


# ── (c) Fully resolved clean term is unaffected — regression guard ──────────
def test_fully_resolved_term_stays_precise_no_opaque():
    cfg = """
    firewall { family inet { filter F {
        term SAFE {
            from {
                source-address 10.20.0.0/16;
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 443;
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    kinds = _kinds(aces)

    # Exact term: CORP->PCI on tcp/443 (not 445) — segcheck policy checks tcp/445,
    # so this is clean.
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds

    # All ACEs are precise; no opaque fallback added.
    assert all(not a.imprecise for a in aces), "fully resolved term must produce precise ACEs"
    assert len(aces) == 1
    assert not any("partially resolved" in n for n in notes)


# ── (d) ALL source addresses unresolved → opaque fallback, not partial ──────
def test_all_unresolved_src_stays_fully_opaque():
    cfg = """
    firewall { family inet { filter F {
        term OPAQUE {
            from {
                source-address CORP-UNKNOWN;
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 445;
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    kinds = _kinds(aces)

    # CORP-UNKNOWN cannot be resolved → m.srcs=[] → any-net fallback → single opaque ACE.
    # No resolved src exists, so partial precision cannot prove a CRITICAL.
    assert len(aces) == 1, "all-unresolved src must produce exactly one opaque ACE"
    assert aces[0].imprecise is True
    assert aces[0].src_any, "all-unresolved src falls back to any"

    assert "segmentation-indeterminate" in kinds
    assert "segmentation-violation" not in kinds, "must not emit a false CRITICAL"
    assert "segmentation-ok" not in kinds

    # The note from _addrs mentions the address and 'imprecise', NOT 'partially resolved'.
    assert not any("partially resolved" in n for n in notes)
    assert any("CORP-UNKNOWN" in n and "imprecise" in n for n in notes)
