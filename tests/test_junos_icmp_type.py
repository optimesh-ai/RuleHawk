"""Junos `icmp-type` / `icmp-code` are modeled like Cisco ICMP types.

They were treated as unmodeled (term imprecise), so every ICMP term in a
Junos filter gave INDETERMINATE. Junos names (echo-request, timestamp, ...)
and numbers map to RuleHawk's canonical type names; a list of types becomes
one rule per type; one type with one numeric code becomes TYPE/CODE.
Anything else (icmp-type-except, a code with several types, an unknown name,
inet6 / icmp6 names, icmp-type without `protocol icmp`) stays imprecise."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_junos import parse_junos  # noqa: E402

_F = ("firewall { family %s { filter F {\n"
      "  term t1 { from { %s } then accept; }\n"
      "  term t2 { then discard; }\n} } }\n")


def _t1(cond, fam="inet"):
    aces, _ = parse_junos(_F % (fam, cond))
    return [a for a in aces if a.action == "permit"]


def test_single_named_type():
    t1 = _t1("protocol icmp; icmp-type echo-request;")
    assert [(a.icmp_type, a.imprecise) for a in t1] == [("echo", False)]


def test_type_list_becomes_one_rule_each():
    t1 = _t1("protocol icmp; icmp-type [ echo-reply unreachable 11 ];")
    assert sorted(a.icmp_type for a in t1) == ["echo-reply", "time-exceeded", "unreachable"]
    assert not any(a.imprecise for a in t1)


def test_type_and_code():
    t1 = _t1("protocol icmp; icmp-type unreachable; icmp-code 3;")
    assert [(a.icmp_type, a.imprecise) for a in t1] == [("unreachable/3", False)]


def test_code_with_several_types_is_imprecise():
    assert all(a.imprecise for a in _t1("protocol icmp; icmp-type [ echo-request unreachable ]; icmp-code 1;"))


def test_except_unknown_and_v6_stay_imprecise():
    assert all(a.imprecise for a in _t1("protocol icmp; icmp-type-except echo-request;"))
    assert all(a.imprecise for a in _t1("protocol icmp; icmp-type frobnicate;"))
    assert all(a.imprecise for a in _t1("next-header icmp6; icmp-type echo-request;", "inet6"))
    assert all(a.imprecise for a in _t1("icmp-type echo-request;"))
