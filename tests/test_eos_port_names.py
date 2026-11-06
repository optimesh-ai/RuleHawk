"""Arista EOS service names used by its default control-plane ACL.

Before round 10 of the #42 review these names resolved to ports: bfd 3784,
bfd-echo 3785, multihop-bfd 4784, micro-bfd 6784, sbfd 7784, mlag 4432, ldp
646, msdp 639, lsp-ping 3503, netconf-ssh 830, checked against Batfish's EOS
frontend and the RFC ports, not against Arista (whose manual is behind a bot
challenge). Round 10 (R9-4): a port name is read only from the vendor's own
cited table, so on EOS every name is unresolved: the rule is imprecise and
the line is noted. `gnmi` was already imprecise (Arista's default gNMI port,
6030, and the IANA port, 9339, differ)."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_eos import parse_eos  # noqa: E402


def _ports(line):
    aces, notes = parse_eos("ip access-list A\n   " + line + "\n")
    return [a.imprecise for a in aces], notes


@pytest.mark.parametrize("line", [
    "10 permit udp any any eq bfd bfd-echo multihop-bfd micro-bfd sbfd",
    "10 permit tcp any any eq mlag ldp msdp netconf-ssh",
    "10 permit udp any any eq lsp-ping",
    "10 permit tcp any any eq gnmi",
    "10 permit tcp any any eq www",
])
def test_eos_port_names_are_not_read(line):
    imp, notes = _ports(line)
    assert imp and all(imp), (line, imp)
    assert notes, line


def test_eos_port_numbers_stay_exact():
    aces, notes = parse_eos("ip access-list A\n   10 permit udp any any eq 3784 3785\n")
    assert sorted(a.dst_port.lo for a in aces) == [3784, 3785]
    assert not any(a.imprecise for a in aces)
