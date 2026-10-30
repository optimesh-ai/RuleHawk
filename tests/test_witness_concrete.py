"""A segmentation witness must be a packet the ACL REALLY permits.

Found by the kernel differential oracle (tools/oracle/iptables_diff.py): the
witness string named only src, dst, dst-port and protocol. When the permitting
rule also constrains the SOURCE port or the ICMP TYPE, the packet as written
(any source port / an echo request) is not the one the rule permits — replayed
against the real kernel it was DROPPED, so the "concrete witness" was wrong:

  -A FORWARD -s 10.0.0.5/32 -p icmp --icmp-type echo-reply -j ACCEPT
      witness was "10.0.0.5 -> 10.0.0.1 (icmp)"   (an echo request: dropped)
  -A FORWARD -d 10.0.0.128/25 -p tcp --sport 1000:2000 -j ACCEPT
      witness was "10.0.0.1 -> 10.0.0.129:1 (tcp)" (any sport: dropped)

The witness now carries the source port and the ICMP type whenever the
permitted region constrains them, and path-grounding still parses it.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.parse_iptables import parse_iptables  # noqa: E402
from rulehawk.pathground import parse_witness  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POL = {"zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]}}


def _viol(aces, proto, ports=None):
    a = {"src": "CORP", "dst": "PCI", "proto": proto}
    if ports is not None:
        a["ports"] = ports
    pol = dict(_POL, must_not_reach=[a])
    v = [f for f in check_segmentation(aces, pol) if f.kind == "segmentation-violation"]
    assert v, "expected a violation"
    return v[0]


def test_icmp_witness_names_the_permitted_type():
    aces, _ = parse_acls("ip access-list extended E\n"
                         " permit icmp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 echo-reply\n")
    w = _viol(aces, "icmp").witness
    assert "echo-reply" in w, w


def test_icmp_witness_avoids_a_denied_type():
    aces, _ = parse_acls("ip access-list extended E\n"
                         " deny icmp any any echo\n"
                         " permit icmp any any\n")
    w = _viol(aces, "icmp").witness
    assert "(icmp " in w and "(icmp echo)" not in w, w


def test_icmp_witness_unconstrained_type_stays_plain():
    aces, _ = parse_acls("ip access-list extended E\n permit icmp any any\n")
    assert _viol(aces, "icmp").witness.endswith("(icmp)")


def test_witness_carries_a_constrained_source_port():
    aces, _ = parse_iptables("*filter\n:FORWARD DROP [0:0]\n"
                             "-A FORWARD -d 10.10.0.0/16 -p tcp --sport 1000:2000 -j ACCEPT\n"
                             "COMMIT\n")
    w = _viol(aces, "tcp").witness
    src = w.split(" -> ")[0]
    assert ":" in src and 1000 <= int(src.rsplit(":", 1)[1]) <= 2000, w


def test_witness_without_source_port_constraint_is_unchanged():
    aces, _ = parse_acls("ip access-list extended E\n permit tcp any any eq 445\n")
    assert _viol(aces, "tcp", [445]).witness == "10.20.0.1 -> 10.10.0.1:445 (tcp)"


def test_pathground_parses_the_richer_witness():
    w = parse_witness("10.20.0.1:1000 -> 10.10.0.1:445 (tcp)")
    assert (w.src, w.dst, w.proto, w.port) == ("10.20.0.1", "10.10.0.1", "tcp", 445)
    w = parse_witness("10.20.0.1 -> 10.10.0.1 (icmp echo-reply)")
    assert (w.src, w.dst, w.proto, w.port) == ("10.20.0.1", "10.10.0.1", "icmp", None)


def test_connectivity_ok_witness_carries_source_port():
    aces, _ = parse_iptables("*filter\n:FORWARD DROP [0:0]\n"
                             "-A FORWARD -p tcp --sport 1024:65535 -j ACCEPT\n"
                             "-A FORWARD -p tcp --sport 0:1023 -j ACCEPT\n"
                             "COMMIT\n")
    pol = dict(_POL, must_reach=[{"src": "CORP", "dst": "PCI", "proto": "tcp",
                                  "ports": [443]}])
    ok = [f for f in check_segmentation(aces, pol) if f.kind == "connectivity-ok"]
    assert ok
    src = ok[0].witness.split(" -> ")[0]
    assert ":" in src, ok[0].witness
