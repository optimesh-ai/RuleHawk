"""Regression: several resolvable transit jumps in ONE parent chain.

Kernel oracle, seed 4, ruleset random-4-78 (nightly run 41311382655): the
kernel ACCEPTed two forwarded packets RuleHawk called denied. Cause: every
`-j CHAIN` placeholder's slice was recorded before any jump was resolved, and
a jump can resolve to more (or fewer) ACEs than its placeholder. After the
first splice moved the rest of the chain, the second splice landed one slot
early: it overwrote the ACCEPT between the two jumps and left the real
placeholder behind as an imprecise ACE.

The minimized ruleset below is that kernel-confirmed case, verbatim.
"""

from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_iptables import parse_iptables  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

MINIMIZED = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:C0 - [0:0]
-A FORWARD -p tcp -m multiport --dports 22 -m conntrack --ctstate NEW -j C0
-A FORWARD -s 10.0.0.0/25 -d 10.0.0.128/25 -p tcp -m conntrack --ctstate NEW -j ACCEPT
-A FORWARD -s 192.168.1.10 -d 10.0.0.64/26 -p tcp -j C0
-A C0 -s 10.0.0.0/25 -p tcp --sport 3389 -m conntrack --ctstate NEW -j DROP
-A C0 -p tcp -j DROP
COMMIT
"""

# Both packets the kernel accepted (FORWARD) and RuleHawk denied.
PACKETS = [("10.0.0.1", 35632, "10.0.0.130", 27833),
           ("10.0.0.0", 0, "10.0.0.128", 3388)]


def _forward(text):
    aces, _ = parse_iptables(text)
    return sorted((a for a in aces if a.acl == "FORWARD"), key=lambda a: a.seq)


def _first_tcp_match(chain, src, sport, dst, dport):
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    for a in chain:
        if a.stateful or a.proto not in ("tcp", "ip"):
            continue
        if s in a.src and d in a.dst and a.src_port.contains(sport) \
                and a.dst_port.contains(dport):
            return a
    return None


def test_accept_between_two_resolved_jumps_survives():
    fw = _forward(MINIMIZED)
    assert [a.seq for a in fw] == list(range(1, len(fw) + 1))
    # both jumps resolve precisely: no placeholder is left behind
    assert not any(a.imprecise for a in fw), [a.raw for a in fw if a.imprecise]
    permits = [a for a in fw if a.action == "permit"
               and str(a.src) == "10.0.0.0/25" and str(a.dst) == "10.0.0.128/25"]
    assert len(permits) == 1
    # first jump: 2 ACEs (dport 22), then the ACCEPT, then the second jump: 1 ACE
    assert [a.action for a in fw] == ["deny", "deny", "permit", "deny", "deny"]
    assert fw[2] is permits[0]
    for src, sport, dst, dport in PACKETS:
        hit = _first_tcp_match(fw, src, sport, dst, dport)
        assert hit is permits[0] and hit.action == "permit", (src, dst, hit and hit.raw)


def test_segcheck_sees_the_forwarded_flow():
    policy = {"zones": {"LO": ["10.0.0.0/25"], "HI": ["10.0.0.128/25"]},
              "must_not_reach": [{"src": "LO", "dst": "HI", "proto": "tcp"}]}
    aces, _ = parse_iptables(MINIMIZED)
    kinds = [f.kind for f in check_segmentation(aces, policy)]
    assert "segmentation-violation" in kinds, kinds


def test_jump_resolving_to_zero_aces_does_not_eat_the_next_rule():
    # first jump is tcp, C1 only holds udp: resolves to 0 ACEs (chain shrinks)
    text = """\
*filter
:FORWARD DROP [0:0]
:C1 - [0:0]
-A FORWARD -p tcp -j C1
-A FORWARD -s 10.0.0.0/25 -d 10.0.0.128/25 -p tcp -j ACCEPT
-A FORWARD -s 10.0.0.0/25 -p udp -j C1
-A FORWARD -s 10.0.0.0/24 -d 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT
-A C1 -p udp --dport 53 -j DROP
COMMIT
"""
    fw = _forward(text)
    assert not any(a.imprecise for a in fw), [a.raw for a in fw if a.imprecise]
    assert [(a.action, a.proto) for a in fw] == [
        ("permit", "tcp"), ("deny", "udp"), ("permit", "tcp"), ("deny", "ip")]
    assert str(fw[0].src) == "10.0.0.0/25" and str(fw[0].dst) == "10.0.0.128/25"
    assert fw[2].dst_port.contains(22) and not fw[2].dst_port.contains(23)
