"""Junos `source-prefix-list` / `destination-prefix-list` resolve against
`policy-options prefix-list` definitions in the same config.

They were always treated as unmodeled (term imprecise), so the most common
Junos management-plane filter shape (a protect-RE filter built on prefix
lists: 66 notes in 16 files of the public-config corpus) produced only
INDETERMINATE answers. Anything that cannot be replayed exactly (`apply-path`,
`except`, undefined or conflicting lists, no entries of the filter's family)
keeps the old imprecise treatment."""

from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_junos import parse_junos  # noqa: E402

_PL = """policy-options {
    prefix-list mgmt {
        10.1.0.0/16;
        192.0.2.7/32;
        2001:db8::/32;
    }
    prefix-list dyn {
        apply-path "interfaces <*> unit <*> family inet address <*>";
    }
}
"""


def _filter(cond: str, fam: str = "inet") -> str:
    return (_PL + "firewall { family %s { filter F {\n"
            "  term t1 { from { %s protocol tcp; } then accept; }\n"
            "  term t2 { then discard; }\n} } }\n" % (fam, cond))


def test_source_prefix_list_resolves_exactly():
    aces, notes = parse_junos(_filter("source-prefix-list { mgmt; }"))
    t1 = [a for a in aces if a.action == "permit"]
    assert {str(a.src) for a in t1} == {"10.1.0.0/16", "192.0.2.7/32"}   # v6 dropped in inet
    assert not any(a.imprecise for a in t1)


def test_destination_prefix_list_inet6_keeps_v6_only():
    aces, _ = parse_junos(_filter("destination-prefix-list { mgmt; }", "inet6"))
    t1 = [a for a in aces if a.action == "permit"]
    assert {str(a.dst) for a in t1} == {"2001:db8::/32"}
    assert not any(a.imprecise for a in t1)


def test_set_form_prefix_list_resolves():
    text = ("set policy-options prefix-list mgmt 10.1.0.0/16\n"
            "set policy-options prefix-list mgmt 192.0.2.7/32\n"
            "set firewall family inet filter F term t1 from source-prefix-list mgmt\n"
            "set firewall family inet filter F term t1 then accept\n"
            "set firewall family inet filter F term t2 then discard\n")
    aces, _ = parse_junos(text)
    t1 = [a for a in aces if a.action == "permit"]
    assert {str(a.src) for a in t1} == {"10.1.0.0/16", "192.0.2.7/32"}
    assert not any(a.imprecise for a in t1)


def test_apply_path_stays_imprecise():
    aces, _ = parse_junos(_filter("source-prefix-list { dyn; }"))
    assert all(a.imprecise for a in aces if a.action == "permit")


def test_except_stays_imprecise():
    aces, _ = parse_junos(_filter("source-prefix-list { mgmt except; }"))
    assert all(a.imprecise for a in aces if a.action == "permit")


def test_undefined_list_stays_imprecise():
    aces, _ = parse_junos(_filter("source-prefix-list { nosuch; }"))
    assert all(a.imprecise for a in aces if a.action == "permit")


def test_two_lists_union():
    text = _PL.replace("prefix-list dyn {", "prefix-list b { 198.51.100.0/24; }\n    prefix-list dyn {")
    text += "firewall { family inet { filter F {\n term t1 { from { source-prefix-list { mgmt; b; } } then accept; }\n} } }\n"
    aces, _ = parse_junos(text)
    assert {str(a.src) for a in aces} == {"10.1.0.0/16", "192.0.2.7/32", "198.51.100.0/24"}
    assert not any(a.imprecise for a in aces)


def test_prefix_list_and_source_address_together_is_imprecise():
    # Junos ANDs different match conditions; RuleHawk would union them.
    aces, _ = parse_junos(_filter("source-prefix-list { mgmt; } source-address { 10.1.2.0/24; }"))
    assert all(a.imprecise for a in aces if a.action == "permit")
    # and the modeled space is still a superset of the true match
    srcs = [a.src for a in aces if a.action == "permit"]
    assert any(ipaddress.ip_network("10.1.2.0/24").subnet_of(s) for s in srcs if s.version == 4)
