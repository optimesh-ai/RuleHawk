"""A Junos term with no terminating action ACCEPTS matching packets.

Juniper: "if a term does not contain a then statement or if an action has not
been configured in the then statement, the term accepts any matching packets";
a term with only nonterminating actions (count/log/...) also accepts. The
parser used to SKIP such terms, so the packets fell through to later terms —
a later `discard` then made RuleHawk report a permitted flow as blocked (a
silent false PASS on must_not_reach). Found on the public-config corpus (45
terms in 15 files). Source: Juniper "Stateless Firewall Filter Components".
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_junos import parse_junos  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POL = {"zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
        "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}]}


def _cfg(then: str) -> str:
    return ("firewall { family inet { filter F {\n"
            "  term t1 { from { destination-address { 10.10.0.0/16; } protocol tcp; }%s }\n"
            "  term t2 { then discard; }\n"
            "} } }\n" % then)


def _kinds(text):
    aces, notes = parse_junos(text)
    return aces, {f.kind for f in check_segmentation(aces, _POL)}


def test_count_only_term_accepts():
    aces, kinds = _kinds(_cfg(" then { count c1; }"))
    assert aces[0].action == "permit" and not aces[0].imprecise
    assert "segmentation-violation" in kinds


def test_term_without_then_accepts():
    aces, kinds = _kinds(_cfg(""))
    assert aces[0].action == "permit"
    assert "segmentation-violation" in kinds


def test_next_term_still_falls_through():
    aces, kinds = _kinds(_cfg(" then { count c1; next term; }"))
    assert "segmentation-violation" not in kinds
    assert all(a.action == "deny" for a in aces)


def test_unknown_then_action_is_not_a_confident_verdict():
    aces, kinds = _kinds(_cfg(" then { frobnicate x; }"))
    assert aces[0].imprecise
    assert "segmentation-ok" not in kinds
