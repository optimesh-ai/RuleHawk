"""Junos `show configuration | display set` firewall filters are audited.

The set form was the largest single cause of INCOMPLETE in a 437-file public
corpus: 40 of 92 Junos files were `set` statements and every one returned
"not yet supported". The set statements under `firewall` are now rebuilt into
the brace form in configuration order and read by the same parser (and the same
soundness guards). Anything that cannot be replayed exactly (an `insert` or
`delete` that names an unknown term, a partial delete) keeps the old
unsupported result rather than a guessed order.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.gate import _pick_parser  # noqa: E402
from rulehawk.parse_junos import parse_junos  # noqa: E402

SET = """set system host-name r1
set firewall family inet filter EDGE term ssh from source-address 10.0.0.0/8
set firewall family inet filter EDGE term ssh from protocol tcp
set firewall family inet filter EDGE term ssh from destination-port [ 22 443 ]
set firewall family inet filter EDGE term ssh then count C1
set firewall family inet filter EDGE term ssh then accept
set firewall family inet filter EDGE term udp from protocol udp
set firewall family inet filter EDGE term udp then discard
set firewall family inet filter EDGE term dup from source-address 10.1.0.0/16
set firewall family inet filter EDGE term dup from protocol tcp
set firewall family inet filter EDGE term dup from destination-port 22
set firewall family inet filter EDGE term dup then reject
deactivate firewall family inet filter EDGE term udp
"""


def _sig(aces):
    return [(a.acl, a.action, a.proto, str(a.src), str(a.dst_port), a.imprecise)
            for a in aces]


def test_set_form_is_routed_and_parsed():
    vendor, fn = _pick_parser(SET, "auto")
    assert vendor == "junos"
    aces, notes = fn(SET)
    assert _sig(aces) == [
        ("EDGE", "permit", "tcp", "10.0.0.0/8", "22", False),
        ("EDGE", "permit", "tcp", "10.0.0.0/8", "443", False),
        ("EDGE", "deny", "tcp", "10.1.0.0/16", "22", False),
    ], notes
    assert any("inactive" in n or "deactivated" in n for n in notes)


def test_set_form_line_numbers_point_at_the_set_statements():
    aces, _ = parse_junos(SET)
    assert [a.line for a in aces] == [2, 2, 9]


def test_set_form_matches_the_brace_form():
    brace = """firewall { family inet { filter EDGE {
    term ssh { from { source-address { 10.0.0.0/8; } protocol tcp; destination-port [ 22 443 ]; } then { count C1; accept; } }
    inactive: term udp { from { protocol udp; } then discard; }
    term dup { from { source-address { 10.1.0.0/16; } protocol tcp; destination-port 22; } then reject; }
} } }
"""
    assert _sig(parse_junos(SET)[0]) == _sig(parse_junos(brace)[0])


def test_set_form_findings_are_produced():
    aces, _ = parse_junos(SET)
    kinds = {f.kind for f in analyze(aces)}
    assert "intent-inversion-deny-dead" in kinds     # dup is shadowed by ssh


def test_insert_is_replayed():
    text = SET + "insert firewall family inet filter EDGE term dup before term ssh\n"
    aces, _ = parse_junos(text)
    assert aces[0].action == "deny"


def test_unreplayable_insert_stays_unsupported():
    text = ("set firewall family inet filter E term a then accept\n"
            "insert firewall family inet filter E term b before term a\n")
    aces, notes = parse_junos(text)
    assert aces == [] and any("not yet supported" in n for n in notes)


def test_groups_with_firewall_statements_fail_closed():
    text = SET + ("set groups G firewall family inet filter <*> term x then accept\n"
                  "set apply-groups G\n")
    aces, notes = parse_junos(text)
    assert any(a.imprecise for a in aces if a.acl == "EDGE")
    assert any("groups" in n for n in notes)
