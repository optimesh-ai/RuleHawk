"""Arista EOS service names used by its default control-plane ACL resolve to
ports instead of widening the rule to ANY port (46 notes in 5 corpus files,
plus 'unrecognized trailing qualifier' on multi-port `eq` lists).

bfd 3784, bfd-echo 3785, multihop-bfd 4784, micro-bfd 6784, sbfd 7784,
mlag 4432, ldp 646, msdp 639, lsp-ping 3503, netconf-ssh 830.
bfd, bfd-echo, micro-bfd, mlag, ldp and msdp were checked against Batfish's
EOS frontend (testFilters); Batfish does not know the others (RFC 5883 / 7880
/ 8029 / 6242 ports). `gnmi` is left unresolved on purpose: Arista's default
gNMI port (6030) and the IANA port (9339) differ, so it stays imprecise."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.model import PortRange  # noqa: E402
from rulehawk.parse import parse_acls  # noqa: E402


def _ports(line):
    aces, notes = parse_acls("ip access-list A\n   " + line + "\n")
    return sorted((a.dst_port.lo, a.dst_port.hi) for a in aces), [a.imprecise for a in aces], notes


def test_bfd_family():
    p, imp, _ = _ports("10 permit udp any any eq bfd bfd-echo multihop-bfd micro-bfd sbfd")
    assert p == [(3784, 3784), (3785, 3785), (4784, 4784), (6784, 6784), (7784, 7784)]
    assert not any(imp)


def test_control_plane_tcp_names():
    p, imp, _ = _ports("10 permit tcp any any eq mlag ldp msdp netconf-ssh")
    assert p == [(639, 639), (646, 646), (830, 830), (4432, 4432)]
    assert not any(imp)


def test_lsp_ping():
    p, imp, _ = _ports("10 permit udp any any eq lsp-ping")
    assert p == [(3503, 3503)] and not any(imp)
    assert PortRange(3503, 3503).contains(3503)


def test_gnmi_stays_imprecise():
    _, imp, _ = _ports("10 permit tcp any any eq gnmi")
    assert all(imp)
