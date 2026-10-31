"""Cisco ICMPv4 type names: every name maps to the device's type(/code), and
an unknown name is never treated as an exact type.

Found by the Batfish oracle on three NX-OS corpus configs (the default CoPP
policy): `permit icmp any any ttl-exceeded` was kept as an opaque name that
matches no packet, so RuleHawk said time-exceeded was DENIED (implicit deny)
where the device permits it. IOS/NX-OS: ttl-exceeded = 11/0,
reassembly-timeout = 11/1, net/host/protocol/port-unreachable = 3/0..3,
packet-too-big = 3/4, source-route-failed = 3/5,
administratively-prohibited = 3/13."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls  # noqa: E402


def _one(name):
    aces, notes = parse_acls(f"ip access-list A\n  10 permit icmp any any {name}\n")
    return aces[0], notes


def test_cisco_names_map_to_type_and_code():
    want = {"ttl-exceeded": "time-exceeded/0", "reassembly-timeout": "time-exceeded/1",
            "net-unreachable": "unreachable/0", "host-unreachable": "unreachable/1",
            "protocol-unreachable": "unreachable/2", "port-unreachable": "unreachable/3",
            "packet-too-big": "unreachable/4", "source-route-failed": "unreachable/5",
            "administratively-prohibited": "unreachable/13"}
    for name, canon in want.items():
        a, _ = _one(name)
        assert (a.icmp_type, a.imprecise) == (canon, False), name


def test_unknown_icmp_name_is_imprecise_any_type():
    a, notes = _one("frobnicate")
    assert a.icmp_type is None and a.imprecise
    assert any("frobnicate" in n for n in notes)


def test_iptables_icmp_names():
    from rulehawk.parse_iptables import parse_iptables
    want = {"destination-unreachable": "unreachable", "port-unreachable": "unreachable/3",
            "ttl-exceeded": "time-exceeded", "ttl-zero-during-transit": "time-exceeded/0",
            "host-prohibited": "unreachable/10", "pong": "echo-reply"}
    for name, canon in want.items():
        aces, _ = parse_iptables("*filter\n:FORWARD DROP [0:0]\n"
                                 f"-A FORWARD -p icmp --icmp-type {name} -j ACCEPT\nCOMMIT\n")
        a = [x for x in aces if x.action == "permit"][0]
        assert (a.icmp_type, a.imprecise) == (canon, False), name
    aces, _ = parse_iptables("*filter\n:FORWARD DROP [0:0]\n"
                             "-A FORWARD -p icmp --icmp-type frob -j ACCEPT\nCOMMIT\n")
    a = [x for x in aces if x.action == "permit"][0]
    assert a.icmp_type is None and a.imprecise
