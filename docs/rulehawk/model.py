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
  * `state_limited` — a conntrack state match that includes NEW but not every
                   state: exact for new flows, but other-state packets pass it.
`covers()` returns False whenever `a` is imprecise, stateful or state_limited.

PARSER CONTRACT (load-bearing for every frontend): an ACE's modeled space must
be a SUPERSET of the rule's true match space — parsers must WIDEN, never narrow.
An `imprecise` ACE may safely BE covered (real ⊆ modeled ⊆ coverer) and segcheck
treats any imprecise match as indeterminate, but both of those are sound ONLY
under the superset guarantee. A frontend that narrows a dimension (dropping a
negation's complement, truncating a member list, skipping an unresolvable
member) breaks it: `covers()` would then prove a live rule dead and segcheck
would false-PASS a witness that lives in the dropped part. When a construct
can't be modeled exactly, over-approximate that dimension to ANY and set
`imprecise` — never emit a subset.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from typing import Optional, Union

_IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

PORT_MIN, PORT_MAX = 0, 65535
# Protocols whose ACEs carry meaningful port ranges. sctp/dccp/udplite are here
# because iptables matches ports on them; a proto in this set gets its ports
# COMPARED by covers() — omitting one would let "permit sctp :5000" falsely
# cover "deny sctp :9".
_PORTED = frozenset({"tcp", "udp", "sctp", "dccp", "udplite"})
_WILDCARD_PROTO = frozenset({"ip", "any", "ipv4", "ipv6"})
# Protocols that carry an ICMP type dimension. covers() must respect icmp_type
# for BOTH families: ip6tables `--icmpv6-type` rules (proto "icmpv6") are typed
# exactly like v4 `--icmp-type` rules, and ignoring the type would let e.g. an
# RA-accept (type 134) falsely shadow the NS/NA rules (135/136) IPv6 neighbor
# discovery depends on.
_ICMP_PROTOS = frozenset({"icmp", "icmpv6"})


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
    line: int = 0                     # 1-based source line of this rule in its file
    # (0 = unknown). Set by the parser frontends so the CI gate can annotate the
    # exact line in a PR diff (SARIF). All expanded ACEs from one source line share
    # its line number; synthetic ACEs (e.g. an iptables chain default policy) carry
    # the line of the construct that implied them, or 0 if none.
    transit: bool = True              # participates in INTER-ZONE (transit) segmentation.
    # True for vendors whose ACLs filter forwarded traffic (Cisco/Junos/PAN-OS,
    # and the iptables FORWARD chain). False for direction contexts that NEVER
    # see transit packets (the iptables INPUT/OUTPUT host hooks): a transit packet
    # traverses ONLY FORWARD, so one host hook's default-deny must never shadow a
    # FORWARD permit in the segmentation witness search. Non-transit ACEs stay
    # available for hygiene analysis (shadow/least-privilege), just not the
    # inter-zone witness. Default True keeps single-context vendors unchanged.
    state_limited: bool = False       # matches only SOME connection-tracking
    # states, NEW among them (iptables `--ctstate NEW` / `--state
    # NEW,ESTABLISHED`). Exact for connection-initiating packets — the ones
    # segmentation asks about — but a strict SUBSET of all packets: packets in
    # the other states pass it and reach later rules. So, like `stateful`, it
    # must never prove another rule dead (covers() refuses it as the coverer).

    @property
    def src_any(self) -> bool:
        return self.src.prefixlen == 0

    @property
    def dst_any(self) -> bool:
        return self.dst.prefixlen == 0


def _proto_covers(a: str, b: str) -> bool:
    return a in _WILDCARD_PROTO or a == b


def _net_covers(a: _IPNet, b: _IPNet) -> bool:
    # Exact integer containment check: b ⊆ a iff a's [network, broadcast]
    # integer range encloses b's. Semantically identical to `b.subnet_of(a)`
    # for same-version networks (fuzz-verified over random v4/v6 pairs), but
    # avoids stdlib subnet_of's total_ordering comparison shims — this is the
    # hottest call in analyze() on large ACLs. Mixed versions never cover
    # (subnet_of would raise TypeError there; we keep the explicit False).
    if a.version != b.version:
        return False
    return (
        int(a.network_address) <= int(b.network_address)
        and int(b.broadcast_address) <= int(a.broadcast_address)
    )


def covers(a: ACE, b: ACE) -> bool:
    """True iff a's match-space is a (sound) superset of b's (a ⊇ b)."""
    if a.imprecise or a.stateful or a.state_limited:
        # a's space is not exact (or not all-state) — refuse to prove anything
        # dead from it.
        return False
    if b.imprecise and b.proto in _PORTED and not (
            b.src_port.is_any() and b.dst_port.is_any()):
        # An imprecise b whose ports are CONSTRAINED may be under-approximated
        # in exactly the port dimension: the partial-precision parsers keep the
        # known port(s) exact and flag imprecise for an unresolved extra (e.g.
        # `eq www <unknown-service>`), so the true space can include ports the
        # model doesn't show. Proving such a rule dead from its modeled ports
        # could delete a rule that still carries the unknown service. When the
        # imprecision lies elsewhere (ports ANY), being covered stays sound
        # (real ⊆ modeled ⊆ coverer) — only this shape is refused.
        return False
    if not _proto_covers(a.proto, b.proto):
        return False
    # ICMP type: an exact-typed rule only covers the same type; a typeless icmp
    # rule (or an ip/any wildcard) covers all types. Applies to both ICMP
    # families (v4 "icmp" and ip6tables "icmpv6").
    if a.proto in _ICMP_PROTOS and b.proto == a.proto:
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
    if a.imprecise or a.stateful or a.state_limited:
        return False
    if not _proto_covers(a.proto, b.proto):
        return False
    if a.proto in _ICMP_PROTOS and b.proto == a.proto:
        if a.icmp_type is not None and a.icmp_type != b.icmp_type:
            return False
    if b.proto in _PORTED:
        if not a.src_port.covers(b.src_port) or not a.dst_port.covers(b.dst_port):
            return False
    return True


def covered_dimensions(a: ACE, b: ACE) -> "tuple[bool, bool]":
    """(does a span all of b.src, does a span all of b.dst) — reuses _net_covers."""
    return _net_covers(a.src, b.src), _net_covers(a.dst, b.dst)


# --------------------------------------------------------------------------- #
# terminal pager artifacts
# --------------------------------------------------------------------------- #
# A config captured from an interactive session (`show running-config` without
# `terminal length 0`) carries the pager prompt and the backspaces that erased
# it, often on the same line as the next config line:
#     " --More-- \b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\b deny ip ..."
# Left in, that line is unparseable and its rule is lost (surfaced only as an
# unparsed note). Removing the prompt recovers the rule exactly. Only a prompt
# at the start of a line is touched, and never a newline, so every line number
# a finding cites is unchanged.
_PAGER = re.compile(
    r"^[ \t]*(?:-{2,}[ \t]*\(?[ \t]*more(?:[ \t]+\d+%)?[ \t]*\)?[ \t]*-{2,}"
    r"|<-{2,}[ \t]*more[ \t]*-{2,}>)[ \t\x08]*",
    re.IGNORECASE | re.MULTILINE)


def strip_pager(text: str) -> str:
    """Remove `--More--`-style pager prompts (Cisco, Arista, ASA `<--- More
    --->`, Junos `---(more 45%)---`) and their backspace runs."""
    if "more" not in text and "More" not in text and "MORE" not in text:
        return text

    def _sub(m: "re.Match") -> str:
        end = m.end()
        rest = m.string[end:end + 1]
        # Keep an entry indented (it continues a named ACL / policy block).
        return " " if rest and rest not in "\r\n" else ""
    return _PAGER.sub(_sub, text)
