"""Cisco/ASA parser regressions — every fix is pinned by the soundness contract
(model.py): an ACE's modeled space must be a SUPERSET of the true match space.
Each bug here was a narrowing (a subset), which let covers() prove live rules
dead or let segcheck FALSE-PASS a real leak; the fixes either model the form
exactly or widen it and mark imprecise.
"""

from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# CORP (10.20/16) must not reach PCI (10.10/16) on tcp/445 — the canonical leak.
_SEG = {
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def _seg_kinds(aces):
    return {f.kind for f in check_segmentation(aces, _SEG)}


def _kinds(aces):
    return {f.kind for f in analyze(aces)}


# --- IPv6 ACLs: host is /128, any is ::/0 ----------------------------------

def test_ipv6_host_is_slash128_and_any_is_v6():
    aces, _ = parse_acls(
        "ipv6 access-list V6\n"
        " permit tcp host 2001:db8::10 any eq 443\n")
    assert str(aces[0].src) == "2001:db8::10/128"   # NOT 2001:db8::/32
    assert str(aces[0].dst) == "::/0"               # NOT 0.0.0.0/0
    assert aces[0].imprecise is False


def test_ipv6_distinct_hosts_not_false_deny_dead():
    # Both hosts collapsed to 2001:db8::/32 -> the deny looked shadowed.
    aces, _ = parse_acls(
        "ipv6 access-list V6\n"
        " permit tcp host 2001:db8::10 any eq 443\n"
        " deny tcp host 2001:db8::20 any eq 443\n")
    assert aces[0].src != aces[1].src
    assert "intent-inversion-deny-dead" not in _kinds(aces)


def test_v6_context_clears_on_flat_access_list_line():
    aces, _ = parse_acls(
        "ipv6 access-list V6\n"
        " permit ip any any\n"
        "access-list OUT extended permit ip any any\n")
    assert str(aces[0].src) == "::/0"
    assert str(aces[1].src) == "0.0.0.0/0"


# --- 0.0.0.0 + dual-reading mask is the "any" idiom, exact -----------------

def test_ios_all_ones_wildcard_is_exact_any():
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255\n")
    assert aces[0].src_any and aces[0].dst_any and aces[0].imprecise is False
    assert "permit-any-any" in _kinds(aces)         # the any/any check now fires


def test_asa_zero_zero_mask_is_any_and_leak_is_caught():
    # Parsed as exact host 0.0.0.0/32, this permit missed the CORP witness
    # entirely -> segmentation FALSE PASS.
    aces, _ = parse_acls(
        "access-list OUT extended permit tcp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 eq 445\n")
    assert aces[0].src_any and aces[0].dst_any and aces[0].imprecise is False
    assert "segmentation-violation" in _seg_kinds(aces)


def test_nonzero_addr_with_dual_mask_stays_exact_host():
    # The real host idioms: IOS wildcard-0.0.0.0 / ASA /32 netmask.
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit ip 10.1.2.3 0.0.0.0 172.16.0.9 255.255.255.255\n")
    assert str(aces[0].src) == "10.1.2.3/32"
    assert str(aces[0].dst) == "172.16.0.9/32"
    assert aces[0].imprecise is False


# --- undefined service group in the port slot fails closed -----------------

def test_undefined_service_group_fails_closed_not_any_ports():
    # The undefined group used to be skipped as an inert trailer -> exact ANY
    # ports: falsely INDETERMINATE-free AND able to prove later rules redundant.
    cfg = (
        "object-group network CORP_NET\n"
        " network-object 10.20.0.0 255.255.0.0\n"
        "object-group network PCI_NET\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_NET object-group PCI_NET object-group NOSUCH\n"
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 443\n")
    aces, _ = parse_acls(cfg)
    assert aces[0].imprecise is True                # opaque, not exact any-port
    skinds = _seg_kinds(aces)
    assert "segmentation-indeterminate" in skinds
    assert "segmentation-ok" not in skinds
    assert "redundant" not in _kinds(aces)          # opaque ACE proves nothing dead


# --- icmp-type groups and literal icmp types through resolution ------------

def test_icmp_type_group_is_not_exact_all_icmp():
    # The icmp-type group restriction was dropped -> exact all-ICMP permit ->
    # the later typed deny was falsely proven dead.
    cfg = (
        "object-group icmp-type PING_ONLY\n"
        " icmp-object echo\n"
        "object-group network A\n"
        " network-object 10.20.0.0 255.255.0.0\n"
        "object-group network B\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit icmp object-group A object-group B object-group PING_ONLY\n"
        " deny icmp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 echo-reply\n")
    aces, _ = parse_acls(cfg)
    assert aces[0].imprecise is True                # fail-closed, not all-ICMP
    assert "intent-inversion-deny-dead" not in _kinds(aces)


def test_literal_icmp_type_survives_object_group_resolution():
    cfg = (
        "object-group network A\n"
        " network-object 10.20.0.0 255.255.0.0\n"
        "object-group network B\n"
        " network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit icmp object-group A object-group B echo\n"
        " deny icmp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 echo-reply\n")
    aces, _ = parse_acls(cfg)
    assert aces[0].icmp_type == "echo" and aces[0].imprecise is False
    assert "intent-inversion-deny-dead" not in _kinds(aces)


# --- match-narrowing trailers -> imprecise; inactive -> skipped -------------

def test_time_range_marks_imprecise_no_false_redundant():
    aces, notes = parse_acls(
        "ip access-list extended T\n"
        " permit tcp any any eq 443 time-range WORKHOURS\n"
        " permit tcp any any eq 443\n")
    assert aces[0].imprecise is True
    assert "redundant" not in _kinds(aces)          # narrowed rule proves nothing
    assert any("narrowed" in n for n in notes)


def test_fragments_marks_imprecise_no_false_permit_dead():
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " deny ip any any fragments\n"
        " permit ip any any\n")
    assert aces[0].imprecise is True
    assert "intent-inversion-permit-dead" not in _kinds(aces)


def test_dscp_and_ttl_mark_imprecise():
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit tcp any any eq 80 dscp ef\n"
        " permit tcp any any eq 80 ttl eq 10\n")
    assert all(a.imprecise for a in aces)


def test_trailer_argument_is_not_an_icmp_type():
    # `time-range WORK` used to yield icmp_type == "WORK".
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit icmp any any time-range WORK\n")
    assert aces[0].icmp_type is None
    assert aces[0].imprecise is True


def test_inactive_rule_is_skipped_and_masked_leak_surfaces():
    # ASA `inactive` = disabled on the device. Keeping the deny in the model let
    # it block the witness -> segmentation FALSE PASS of a live leak.
    aces, notes = parse_acls(
        "access-list OUT extended deny tcp 10.20.0.0 255.255.0.0"
        " 10.10.0.0 255.255.0.0 eq 445 inactive\n"
        "access-list OUT extended permit tcp 10.20.0.0 255.255.0.0"
        " 10.10.0.0 255.255.0.0 eq 445\n")
    assert len(aces) == 1 and aces[0].action == "permit"
    assert "segmentation-violation" in _seg_kinds(aces)
    assert any("inactive" in n for n in notes)


# --- ICMP type/code pairs stay distinct -------------------------------------

def test_icmp_type_code_pairs_are_distinct():
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit icmp any any 3 1\n"
        " deny icmp any any 3 4\n")
    assert aces[0].icmp_type == "3/1" and aces[1].icmp_type == "3/4"
    assert "intent-inversion-deny-dead" not in _kinds(aces)


# --- standard ACLs (ASA named, IOS numbered, IOS named) ---------------------

def test_asa_standard_acl_parses_exact_and_catches_leak():
    # Dropped with only a note before -> segmentation FALSE PASS.
    aces, notes = parse_acls(
        "access-list SPLIT standard permit 10.20.0.0 255.255.0.0\n")
    assert len(aces) == 1
    a = aces[0]
    assert str(a.src) == "10.20.0.0/16" and a.dst_any and a.proto == "ip"
    assert a.imprecise is False
    assert "segmentation-violation" in _seg_kinds(aces)  # dst any spans PCI
    assert not any("unparsed" in n for n in notes)


def test_ios_numbered_standard_wildcard_source():
    aces, _ = parse_acls("access-list 10 permit 10.20.0.0 0.0.255.255\n")
    assert str(aces[0].src) == "10.20.0.0/16"
    assert aces[0].dst_any and aces[0].proto == "ip"
    assert aces[0].imprecise is False


def test_ios_numbered_standard_bare_address_is_host():
    aces, _ = parse_acls("access-list 10 permit 10.1.2.3\n")
    assert str(aces[0].src) == "10.1.2.3/32" and aces[0].imprecise is False


def test_ios_named_standard_body():
    aces, _ = parse_acls(
        "ip access-list standard MGMT\n"
        " permit 10.20.0.0 0.0.255.255\n"
        " deny any\n")
    assert str(aces[0].src) == "10.20.0.0/16"
    assert aces[1].action == "deny" and aces[1].src_any


# --- non-contiguous wildcard must OVER-approximate ---------------------------

def test_noncontiguous_wildcard_covers_real_matches():
    # 10.0.0.0 0.255.0.255 truly matches 10.5.0.7; the old popcount length (/16)
    # excluded it, so the modeled space was a SUBSET. The covering prefix is the
    # mask's leading-zero run (/8) — a guaranteed superset, still imprecise.
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit ip 10.0.0.0 0.255.0.255 any\n")
    assert aces[0].imprecise is True
    assert ipaddress.ip_address("10.5.0.7") in aces[0].src


# --- malformed definitions must not crash ------------------------------------

def test_bare_group_object_does_not_crash():
    cfg = (
        "object-group network A\n"
        " group-object\n"
        " network-object host 10.20.0.1\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group A any eq 445\n")
    aces, _ = parse_acls(cfg)                       # must not raise
    assert aces and aces[0].imprecise is True       # bad member -> fail-closed


def test_mixed_family_object_range_does_not_crash():
    cfg = (
        "object network X\n"
        " range 10.0.0.1 2001:db8::5\n"
        "ip access-list extended OUT\n"
        " permit tcp object X any eq 445\n")
    aces, _ = parse_acls(cfg)                       # must not raise
    assert aces and aces[0].imprecise is True


# --- named-port table additions ----------------------------------------------

def test_new_named_ports_are_exact():
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit udp any any eq bootps\n"
        " permit tcp any any eq tacacs\n"
        " permit udp any any eq radius\n")
    ports = [(a.dst_port.lo, a.dst_port.hi) for a in aces]
    assert ports == [(67, 67), (49, 49), (1812, 1812)]
    assert all(not a.imprecise for a in aces)       # no longer ANY+imprecise
