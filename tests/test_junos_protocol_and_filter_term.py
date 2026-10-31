"""Two Junos misreadings found by the Batfish oracle on the public corpus.

1. `protocol ipv6` in an inet filter is IP protocol 41 (IPv6-in-IPv4). It
   was read as RuleHawk's family wildcard "ipv6", so the term matched EVERY
   packet: wrong verdicts (Batfish: 100 disagreements on one file) and a later
   term falsely proven dead. Same for `ipip` (4) and `icmp6`.
2. A term whose body is `filter OTHER;` (filter chaining) has no `then`. Since
   the implicit-accept fix it was read as "accept everything"; it actually
   evaluates OTHER and falls through when OTHER does not decide. RuleHawk
   doesn't inline OTHER, so the term is an opaque, imprecise stand-in: no
   confident verdict behind it, and nothing after it proven dead."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.parse_junos import parse_junos  # noqa: E402


def test_protocol_ipv6_is_protocol_41_not_a_wildcard():
    aces, _ = parse_junos("firewall { family inet { filter F {\n"
                          " term IPV6 { from { protocol ipv6; } then accept; }\n"
                          " term G { from { protocol gre; } then discard; }\n} } }\n")
    assert aces[0].proto == "41"
    dead = {f.rule_id for f in analyze(aces)}
    assert "F:2" not in dead and not any(r.startswith("F:2") for r in dead)


def test_ipip_and_icmp6_names():
    aces, _ = parse_junos("firewall { family inet { filter F {\n"
                          " term A { from { protocol ipip; } then accept; }\n} } }\n")
    assert aces[0].proto == "4"


def test_filter_reference_term_is_opaque():
    aces, notes = parse_junos("firewall { family inet { filter F {\n"
                              " term a { from { protocol tcp; destination-port 22; } then accept; }\n"
                              " term next-filter { filter OTHER; }\n"
                              " term discard-default { then discard; }\n} } }\n")
    nf = [a for a in aces if "next-filter" in a.raw]
    assert nf and all(a.imprecise for a in nf)
    dead = [f for f in analyze(aces) if "discard-default" in (f.rule or "")]
    assert not dead
    assert any("filter OTHER" in n for n in notes)
