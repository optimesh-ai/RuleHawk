"""Junos `port X` matches the SOURCE OR the DESTINATION port.

It was treated as an unmodeled match (term imprecise: 45 notes in 11 corpus
files), so a protect-RE term like `from { protocol tcp; port bgp; }` never
gave a confident answer. A term with `port` and no other port condition is
now emitted as two exact rules (source-port X) and (destination-port X), whose
union is exactly the device's match space."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.model import PortRange  # noqa: E402
from rulehawk.parse_junos import parse_junos  # noqa: E402

_F = ("firewall { family inet { filter F {\n"
      "  term t1 { from { %s } then accept; }\n"
      "  term t2 { then discard; }\n} } }\n")


def test_port_becomes_source_or_destination():
    aces, _ = parse_junos(_F % "protocol tcp; port 179;")
    t1 = [a for a in aces if a.action == "permit"]
    assert len(t1) == 2 and not any(a.imprecise for a in t1)
    bgp = PortRange(179, 179)
    assert {(a.src_port == bgp, a.dst_port == bgp) for a in t1} == {(True, False), (False, True)}
    assert all(a.src_port.is_any() or a.dst_port.is_any() for a in t1)
    assert all(a.line == t1[0].line for a in t1)


def test_port_with_other_port_condition_stays_imprecise():
    aces, _ = parse_junos(_F % "protocol tcp; port 179; destination-port 1000-2000;")
    assert all(a.imprecise for a in aces if a.action == "permit")


def test_port_except_stays_imprecise():
    aces, _ = parse_junos(_F % "protocol tcp; port-except 179;")
    assert all(a.imprecise for a in aces if a.action == "permit")
