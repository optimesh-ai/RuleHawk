"""Normalized ACL model + packet-space containment (`covers`).

An ACE is reduced to a packet match-space:
(action, protocol, src-net, dst-net, src-port-range, dst-port-range, icmp-type).
The core primitive is `covers(a, b)`: True iff EVERY packet matching `b` also
matches `a` (a ⊇ b). Shadowing / redundancy / least-privilege all build on it.

SOUNDNESS RULE (the thing that keeps us from lying to a network engineer):
a rule may only be used to PROVE another rule dead if its match-space is exact.
Two cases make a rule's space inexact, and such a rule must NEVER act as the
covering rule:
  * `imprecise`  — we over-approximated the space (e.g. `neq` ports, a
                   non-contiguous / ambiguous mask). Claiming coverage from a
                   space we widened could recommend deleting a load-bearing rule.
  * `stateful`   — `established` matches only return traffic (ACK/RST), so it
                   does not "cover" a new-flow rule.
`covers()` returns False whenever `a` is imprecise or stateful.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from typing import Optional, Union

_IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

PORT_MIN, PORT_MAX = 0, 65535
_PORTED = frozenset({"tcp", "udp"})
_WILDCARD_PROTO = frozenset({"ip", "any", "ipv4", "ipv6"})


@dataclasses.dataclass(frozen=True)
class PortRange:
    lo: int = PORT_MIN
    hi: int = PORT_MAX

    def covers(self, other: "PortRange") -> bool:
        return self.lo <= other.lo and other.hi <= self.hi

    def is_any(self) -> bool:
        return self.lo == PORT_MIN and self.hi == PORT_MAX

    def contains(self, port: int) -> bool:
        return self.lo <= port <= self.hi

    def __str__(self) -> str:
        if self.is_any():
            return "*"
        return str(self.lo) if self.lo == self.hi else f"{self.lo}-{self.hi}"


ANY_PORTS = PortRange()


@dataclasses.dataclass(frozen=True)
class ACE:
    seq: int                      # 1-based match-order position within its ACL
    action: str                   # "permit" | "deny"
    proto: str                    # "ip" | "tcp" | "udp" | "icmp" | ...
    src: _IPNet
    dst: _IPNet
    src_port: PortRange = ANY_PORTS
    dst_port: PortRange = ANY_PORTS
    icmp_type: Optional[str] = None   # for proto == icmp (e.g. "echo")
    stateful: bool = False            # `established`
    imprecise: bool = False           # over-approximated space (neq / bad mask)
    raw: str = ""
    acl: str = ""
    transit: bool = True              # participates in INTER-ZONE (transit) segmentation.
    # True for vendors whose ACLs filter forwarded traffic (Cisco/Junos/PAN-OS,
    # and the iptables FORWARD chain). False for direction contexts that NEVER
    # see transit packets (the iptables INPUT/OUTPUT host hooks): a transit packet
    # traverses ONLY FORWARD, so one host hook's default-deny must never shadow a
    # FORWARD permit in the segmentation witness search. Non-transit ACEs stay
    # available for hygiene analysis (shadow/least-privilege), just not the
    # inter-zone witness. Default True keeps single-context vendors unchanged.

    @property
    def src_any(self) -> bool:
        return self.src.prefixlen == 0

    @property
    def dst_any(self) -> bool:
        return self.dst.prefixlen == 0


def _proto_covers(a: str, b: str) -> bool:
    return a in _WILDCARD_PROTO or a == b


def _net_covers(a: _IPNet, b: _IPNet) -> bool:
    if a.version != b.version:
        return False
    try:
        return b.subnet_of(a)
    except (TypeError, ValueError):
        return False


def covers(a: ACE, b: ACE) -> bool:
    """True iff a's match-space is a (sound) superset of b's (a ⊇ b)."""
    if a.imprecise or a.stateful:
        # a's space is not exact — refuse to prove anything dead from it.
        return False
    if not _proto_covers(a.proto, b.proto):
        return False
    # ICMP type: an exact-typed rule only covers the same type; a typeless icmp
    # rule (or an ip/any wildcard) covers all types.
    if a.proto == "icmp" and b.proto == "icmp":
        if a.icmp_type is not None and a.icmp_type != b.icmp_type:
            return False
    if not _net_covers(a.src, b.src):
        return False
    if not _net_covers(a.dst, b.dst):
        return False
    if a.proto in _PORTED:
        if not a.src_port.covers(b.src_port):
            return False
        if not a.dst_port.covers(b.dst_port):
            return False
    return True


# --- Cumulative / union shadowing support ----------------------------------
# `covers()` proves a rule dead from ONE earlier rule. A rule can also be dead
# under the UNION of several earlier rules (e.g. two /24 permits make a /23 deny
# unreachable). The helpers below let analyze.py detect that — soundly: we only
# combine EXACT (non-imprecise, non-stateful) earlier rules whose every non-IP
# dimension already covers the target, then prove the IP space is fully covered
# by exact `ipaddress` set subtraction. No over-approximation => no false positive.

def _union_covers(target: _IPNet, nets) -> bool:
    """True iff `target` is fully contained in the union of `nets` (exact).

    Two IP networks are always either disjoint or nested, so subtracting each
    coverer from the residual set and collapsing is exact and terminating."""
    residual = [target]
    for n in nets:
        if n.version != target.version:
            continue
        nxt = []
        for r in residual:
            if r.subnet_of(n):
                continue                      # r fully removed by n
            if n.subnet_of(r):
                nxt.extend(r.address_exclude(n))
            else:
                nxt.append(r)                 # disjoint — keep r
        residual = list(ipaddress.collapse_addresses(nxt)) if nxt else []
        if not residual:
            return True
    return not residual


def _compatible_coverer(a: ACE, b: ACE) -> bool:
    """True iff `a` may join a union that proves `b` dead: exact, and every
    dimension EXCEPT the IP rectangle already covers `b` (mirrors covers()'s
    soundness gates), so only IP coverage remains to prove."""
    if a.imprecise or a.stateful:
        return False
    if not _proto_covers(a.proto, b.proto):
        return False
    if a.proto == "icmp" and b.proto == "icmp":
        if a.icmp_type is not None and a.icmp_type != b.icmp_type:
            return False
    if b.proto in _PORTED:
        if not a.src_port.covers(b.src_port) or not a.dst_port.covers(b.dst_port):
            return False
    return True


def covered_dimensions(a: ACE, b: ACE) -> "tuple[bool, bool]":
    """(does a span all of b.src, does a span all of b.dst) — reuses _net_covers."""
    return _net_covers(a.src, b.src), _net_covers(a.dst, b.dst)
