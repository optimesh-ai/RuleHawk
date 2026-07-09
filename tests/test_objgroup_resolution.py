"""object-group / object RESOLUTION (two-pass) for the Cisco/ASA parser.

ASA object-groups are ubiquitous. The prior soundness fix made any object(-group)
reference a fail-closed opaque ACE -> segmentation INDETERMINATE (never a false
PASS, but imprecise). These tests pin the upgrade: when the group DEFINITIONS are
present in the config we expand the reference to the EXACT member ACEs and emit a
PRECISE verdict — while keeping the fail-closed guarantee for everything we cannot
fully resolve (undefined group, over-cap expansion).

SOUNDNESS is the invariant under test: resolution may turn an INDETERMINATE into a
precise PASS/CRITICAL, but must NEVER turn a real leak into a (false) PASS.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# CORP (10.20/16) must not reach PCI (10.10/16) on tcp/445 — the canonical leak.
_SEG = {
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def _kinds(aces):
    return {f.kind for f in check_segmentation(aces, _SEG)}


# (a) full resolution: network groups + a service group -> PRECISE CRITICAL.
def test_resolved_groups_report_precise_critical_not_indeterminate():
    cfg = (
        "object-group network CORP_NET\n"
        " network-object 10.20.0.0 255.255.0.0\n"
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "object-group service SMB tcp\n"
        " port-object eq 445\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_NET object-group PCI_NET object-group SMB\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(aces)
    assert "segmentation-violation" in kinds          # PRECISE critical
    assert "segmentation-indeterminate" not in kinds  # no longer fail-closed
    assert "segmentation-ok" not in kinds             # and never a false PASS
    # exactly one exact ACE (10.20/16 -> 10.10/16 tcp/445), not imprecise.
    leak = [a for a in aces if a.proto == "tcp"]
    assert len(leak) == 1 and leak[0].imprecise is False
    assert leak[0].dst_port.lo == 445 and leak[0].dst_port.hi == 445
    assert any("resolved object-group" in n for n in notes)


# MUTATION guard: break the resolver (definitions ignored) -> the precise verdict
# reverts to INDETERMINATE / loses precision. Asserting the resolver is what buys
# the precision: with no defs the SAME ACE line is the fail-closed opaque ACE.
def test_mutation_no_defs_reverts_to_indeterminate():
    cfg = (
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_NET object-group PCI_NET object-group SMB\n"
    )  # same ACE, definitions REMOVED -> cannot resolve
    aces, _ = parse_acls(cfg)
    kinds = _kinds(aces)
    assert "segmentation-violation" not in kinds      # precision lost...
    assert "segmentation-indeterminate" in kinds       # ...but still fail-closed
    assert aces[0].imprecise is True


# (b) nested group-object resolves transitively.
def test_nested_group_object_resolves():
    cfg = (
        "object-group network CORP_A\n"
        " network-object 10.20.0.0 255.255.0.0\n"
        "object-group network CORP_ALL\n"
        " group-object CORP_A\n"
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_ALL object-group PCI_NET eq 445\n"
    )
    aces, _ = parse_acls(cfg)
    kinds = _kinds(aces)
    assert "segmentation-violation" in kinds
    assert all(not a.imprecise for a in aces)


# (c) a reference to an UNDEFINED group stays INDETERMINATE (fail-closed).
def test_undefined_group_stays_indeterminate():
    cfg = (
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_NET object-group PCI_NET eq 445\n"
    )  # CORP_NET is never defined
    aces, _ = parse_acls(cfg)
    kinds = _kinds(aces)
    assert "segmentation-indeterminate" in kinds
    assert "segmentation-ok" not in kinds              # never a false PASS
    assert "segmentation-violation" not in kinds       # never invent a witness
    assert aces[0].imprecise is True


# (d) a clean config (groups that do NOT create a CORP->PCI:445 path) PASSes.
def test_clean_resolved_config_passes():
    cfg = (
        "object-group network CORP_NET\n"
        " network-object 10.20.0.0 255.255.0.0\n"
        "object-group network DMZ_NET\n"
        " network-object 10.30.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_NET object-group DMZ_NET eq 445\n"
        " permit tcp object-group CORP_NET object-group CORP_NET eq 443\n"
    )  # CORP can reach DMZ (not PCI) — no forbidden path
    aces, _ = parse_acls(cfg)
    kinds = _kinds(aces)
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds   # resolved precisely -> clean PASS
    assert all(not a.imprecise for a in aces)


# (e) over-cap expansion stays IMPRECISE (one widened ACE), not silently truncated.
def test_over_cap_expansion_stays_imprecise():
    hosts = "".join(f" network-object host 10.20.0.{i}\n" for i in range(1, 254))
    hosts += "".join(f" network-object host 10.20.1.{i}\n" for i in range(1, 60))
    cfg = (
        "object-group network BIG\n" + hosts +
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group BIG object-group PCI_NET eq 445\n"
    )  # >256 src members -> over cap
    aces, notes = parse_acls(cfg)
    # The referencing ACE collapses to ONE fail-closed opaque ACE (not 300+).
    assert len(aces) == 1 and aces[0].imprecise is True
    kinds = _kinds(aces)
    assert "segmentation-indeterminate" in kinds       # fail-closed, not truncated
    assert "segmentation-ok" not in kinds
    assert any("unmodeled (object-group)" in n for n in notes)


# ASA modern `object`/`object service` singular forms also resolve.
def test_asa_singular_object_forms_resolve():
    cfg = (
        "object network CORP\n"
        " subnet 10.20.0.0 255.255.0.0\n"
        "object network PCI\n"
        " subnet 10.10.0.0 255.255.0.0\n"
        "object service RDP\n"
        " service tcp destination eq 3389\n"
        "object-group service SMB tcp\n"
        " port-object eq 445\n"
        "access-list OUT extended permit tcp object CORP object PCI object-group SMB\n"
    )
    aces, _ = parse_acls(cfg)
    kinds = _kinds(aces)
    assert "segmentation-violation" in kinds
    assert all(not a.imprecise for a in aces)


# A partially-resolvable group (one unparseable member) with a resolved member
# that ALREADY proves the leak now produces CRITICAL rather than INDETERMINATE.
# The non-contiguous mask makes one member bad; the clean 10.20/16 member fully
# resolves and its space lies in the CORP zone -> provably CRITICAL.
def test_partial_group_proven_leak_is_critical():
    cfg = (
        "object-group network CORP_NET\n"
        " network-object 10.20.0.0 255.255.0.0\n"
        " network-object 10.21.0.0 0.0.255.128\n"   # non-contiguous mask -> bad member
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_NET object-group PCI_NET eq 445\n"
    )
    aces, notes = parse_acls(cfg)
    kinds = _kinds(aces)
    # Resolved member (10.20/16 -> PCI:445) is a proven CORP->PCI:445 violation.
    assert "segmentation-violation" in kinds          # CRITICAL, not suppressed
    assert "segmentation-ok" not in kinds             # no false PASS
    # Parser emits: one precise ACE for the resolved member + one opaque ACE.
    assert len(aces) == 2
    assert aces[0].imprecise is False                 # precise ACE for 10.20/16
    assert aces[1].imprecise is True                  # opaque ACE for unresolved member
    assert any("partially resolved" in n for n in notes)


# A reference cycle (A -> B -> A) must terminate and fail closed, not loop.
def test_cyclic_group_reference_fails_closed():
    cfg = (
        "object-group network A\n"
        " group-object B\n"
        "object-group network B\n"
        " group-object A\n"
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group A object-group PCI_NET eq 445\n"
    )
    aces, _ = parse_acls(cfg)
    kinds = _kinds(aces)
    assert "segmentation-indeterminate" in kinds       # cycle -> fail closed
    assert "segmentation-ok" not in kinds
    assert aces[0].imprecise is True
