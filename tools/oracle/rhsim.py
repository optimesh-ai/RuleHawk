"""RuleHawk's own first-match verdict for ONE concrete packet.

The differential oracles (Linux kernel for iptables, Batfish for the vendor
ACL parsers) answer "what does the real device do with packet P?". This module
answers "what does RuleHawk's MODEL say about P?" so the two can be compared.

The model is the parsed ACE list (`rulehawk.model.ACE`) for one ACL, read in
match order, with the semantics the engine itself uses (segcheck._search):

  * a `stateful` ACE (Cisco `established`, iptables ESTABLISHED/RELATED) never
    matches a connection-INITIATING packet. The harnesses only send those
    (TCP SYN, UDP, ICMP echo), so a stateful ACE is skipped;
  * the first ACE whose modeled space contains P decides it. If that ACE is
    `imprecise` (its space was over-approximated), RuleHawk does NOT claim a
    verdict: the result is "unknown" (it would say INDETERMINATE);
  * no matching ACE: the implicit default deny (every supported vendor has one;
    iptables chain policies are already explicit trailing ACEs).

Packet: a `Pkt` (proto name, src, dst, sport, dport, icmp type number).
"""

from __future__ import annotations

import dataclasses
import ipaddress
from typing import List, Optional, Tuple

from rulehawk.model import ACE, _ICMP_PROTOS, _PORTED, _WILDCARD_PROTO

# ICMP type names RuleHawk canonicalises to (parse._ICMP_TYPE_CANON) -> number.
ICMP_NUM = {
    "echo-reply": 0, "unreachable": 3, "source-quench": 4, "redirect": 5,
    "echo": 8, "router-advertisement": 9, "router-solicitation": 10,
    "time-exceeded": 11, "parameter-problem": 12, "timestamp-request": 13,
    "timestamp-reply": 14,
}

# IANA numbers for the protocol names RuleHawk emits.
PROTO_NUM = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51,
             "icmpv6": 58, "eigrp": 88, "ospf": 89, "pim": 103, "vrrp": 112,
             "sctp": 132, "igmp": 2, "ipinip": 4, "udplite": 136, "dccp": 33}
NUM_PROTO = {v: k for k, v in PROTO_NUM.items()}


@dataclasses.dataclass(frozen=True)
class Pkt:
    proto: str                     # "tcp" | "udp" | "icmp" | other name
    src: str
    dst: str
    sport: int = 0
    dport: int = 0
    icmp_type: Optional[int] = None
    icmp_code: int = 0

    def __str__(self) -> str:
        if self.proto in _PORTED:
            return f"{self.proto} {self.src}:{self.sport} -> {self.dst}:{self.dport}"
        if self.proto == "icmp":
            return f"icmp {self.src} -> {self.dst} type {self.icmp_type}/{self.icmp_code}"
        return f"{self.proto} {self.src} -> {self.dst}"


def icmp_type_num(t: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    """RuleHawk's canonical icmp_type string -> (type, code-or-None)."""
    if t is None:
        return None, None
    ty, _, code = t.partition("/")
    n = ICMP_NUM.get(ty)
    if n is None:
        try:
            n = int(ty)
        except ValueError:
            return -1, None          # unknown name: matches nothing we send
    return n, (int(code) if code.isdigit() else None)


def _proto_hits(ace: ACE, p: Pkt) -> bool:
    if ace.proto in _WILDCARD_PROTO:
        return True
    a = ace.proto
    if a.isdigit():
        a = NUM_PROTO.get(int(a), a)
    return a == p.proto


def ace_matches(ace: ACE, p: Pkt) -> bool:
    """True iff P lies in the ACE's MODELED space (ignores stateful/imprecise)."""
    if not _proto_hits(ace, p):
        return False
    s, d = ipaddress.ip_address(p.src), ipaddress.ip_address(p.dst)
    if s.version != ace.src.version or s not in ace.src:
        return False
    if d.version != ace.dst.version or d not in ace.dst:
        return False
    if ace.proto in _PORTED:
        if not (ace.src_port.contains(p.sport) and ace.dst_port.contains(p.dport)):
            return False
    if ace.proto in _ICMP_PROTOS and ace.icmp_type is not None:
        ty, code = icmp_type_num(ace.icmp_type)
        if ty != p.icmp_type:
            return False
        if code is not None and code != p.icmp_code:
            return False
    return True


def first_match(aces: List[ACE], p: Pkt) -> Optional[ACE]:
    """The first non-stateful ACE whose modeled space contains P (or None)."""
    for a in aces:
        if a.stateful:
            continue
        if ace_matches(a, p):
            return a
    return None


def verdict(aces: List[ACE], p: Pkt) -> Tuple[str, Optional[ACE]]:
    """("permit" | "deny" | "unknown", deciding ACE or None for implicit deny)."""
    a = first_match(aces, p)
    if a is None:
        return "deny", None
    if a.imprecise:
        return "unknown", a
    return a.action, a


def by_acl(aces: List[ACE]):
    out = {}
    for a in aces:
        out.setdefault(a.acl, []).append(a)
    for k in out:
        out[k].sort(key=lambda x: x.seq)
    return out
