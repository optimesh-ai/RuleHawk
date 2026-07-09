"""Segmentation-intent checking — the audit-evidence / compliance value.

Declare zones (named CIDR sets) and `must_not_reach` assertions, e.g. "CORP must
not reach PCI on tcp/445,3389". For each assertion we search the forbidden
packet space EXACTLY under first-match semantics: walking each ACL in order,
an exact deny SUBTRACTS its slice of the space and the search continues on the
remainder, so an earlier deny that blocks only part of the space can never hide
a permit that leaks the rest (and a deny that blocks all of it produces no false
alarm). A violation is reported with a CONCRETE WITNESS packet the ACL provably
permits; any imprecise (over-approximated) rule the search touches yields an
honest "indeterminate / review manually" instead of a possibly-wrong verdict.

A wildcard assertion (`proto: "ip"`) is probed per concrete protocol: a
tcp-only deny must not be allowed to "block" the udp/icmp part of the space.
ICMP-typed rules keep their type as a search dimension: a `deny icmp echo`
does not block an `echo-reply` witness.

Policy errors (unknown zone name, bad CIDR, bad port) FAIL CLOSED: they emit a
`segmentation-policy-error` finding and the affected assertion is never given a
PASS — a typo'd zone must not certify isolation over an empty search space.

Policy (JSON):
  {"zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
   "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                       "ports": [445, 3389]}]}
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

from .analyze import Finding
from .model import (ACE, ANY_PORTS, _ICMP_PROTOS, _IPNet, _PORTED,
                    _WILDCARD_PROTO, PortRange)

# Rule-visit budget per (assertion x zone-pair x port x probe x ACL) search.
# Exhaustion returns an INDETERMINATE (fail-closed), never a PASS. Generous:
# real configs use a tiny fraction; only an adversarial deny-lattice hits it.
_MAX_VISITS = 50_000

# The search space is a 5-rectangle: (src-net, dst-net, src-ports, dst-ports,
# icmp-type). The icmp-type dimension is symbolic: ("eq", t) = exactly type t,
# ("any", excluded) = every type NOT in `excluded`.
_IT_ANY = ("any", frozenset())


def _net(s: str) -> _IPNet:
    return ipaddress.ip_network(s, strict=False)


def _intersect(a: _IPNet, b: _IPNet) -> Optional[_IPNet]:
    if a.version != b.version:
        return None
    if a.subnet_of(b):
        return a
    if b.subnet_of(a):
        return b
    return None


def _net_minus(a: _IPNet, cover: _IPNet) -> List[_IPNet]:
    """The subnets of `a` outside `cover` — exact: two IP networks are always
    nested or disjoint."""
    if a.version != cover.version:
        return [a]
    if a.subnet_of(cover):
        return []
    if cover.subnet_of(a):
        return list(a.address_exclude(cover))
    return [a]


def _pr_intersect(a: PortRange, b: PortRange) -> Optional[PortRange]:
    lo, hi = max(a.lo, b.lo), min(a.hi, b.hi)
    return PortRange(lo, hi) if lo <= hi else None


def _pr_minus(a: PortRange, cover: PortRange) -> List[PortRange]:
    out = []
    if a.lo < cover.lo:
        out.append(PortRange(a.lo, min(a.hi, cover.lo - 1)))
    if a.hi > cover.hi:
        out.append(PortRange(max(a.lo, cover.hi + 1), a.hi))
    return out


def _it_intersect(it, rule_t: Optional[str]):
    """The part of icmp-type space `it` a rule with icmp_type `rule_t` matches."""
    if rule_t is None:
        return it
    tag, v = it
    if tag == "eq":
        return it if v == rule_t else None
    return None if rule_t in v else ("eq", rule_t)


def _it_minus(it, rule_t: Optional[str]):
    """The part of `it` the rule does NOT match."""
    if rule_t is None:
        return []
    tag, v = it
    if tag == "eq":
        return [] if v == rule_t else [it]
    return [it] if rule_t in v else [("any", v | {rule_t})]


def _proto_matches(rule_proto: str, probe: str) -> bool:
    # The "ip" probe stands for a protocol NO specific rule names (e.g. gre in a
    # tcp/udp ruleset) — only wildcard rules can match it. A concrete probe is
    # matched by the same protocol or a wildcard rule.
    if probe in _WILDCARD_PROTO:
        return rule_proto in _WILDCARD_PROTO
    return rule_proto in _WILDCARD_PROTO or rule_proto == probe


def _witness_host(net: _IPNet) -> str:
    return str(next(iter(net.hosts()), net.network_address))


class _Budget:
    __slots__ = ("left",)

    def __init__(self, n: int) -> None:
        self.left = n

    def spend(self) -> bool:
        self.left -= 1
        return self.left >= 0


def _rect_minus(rect, r: ACE, typed: bool):
    """`rect` minus rule r's match space — the standard disjoint orthotope
    decomposition (peel one dimension at a time). All intersections are known
    non-empty when this is called."""
    snet, dnet, spr, dpr, it = rect
    pieces = []
    for part in _net_minus(snet, r.src):
        pieces.append((part, dnet, spr, dpr, it))
    s_in = _intersect(snet, r.src)
    for part in _net_minus(dnet, r.dst):
        pieces.append((s_in, part, spr, dpr, it))
    d_in = _intersect(dnet, r.dst)
    for part in _pr_minus(spr, r.src_port):
        pieces.append((s_in, d_in, part, dpr, it))
    sp_in = _pr_intersect(spr, r.src_port)
    for part in _pr_minus(dpr, r.dst_port):
        pieces.append((s_in, d_in, sp_in, part, it))
    if typed:
        dp_in = _pr_intersect(dpr, r.dst_port)
        for part in _it_minus(it, r.icmp_type):
            pieces.append((s_in, d_in, sp_in, dp_in, part))
    return pieces


def _search(aces: List[ACE], i: int, probe: str, rect, budget: _Budget):
    """First-match search for a permitted (or undecidable) packet inside `rect`
    over aces[i:]. Returns ("permit"|"indeterminate", sub_rect, rule) or None
    (= every packet in rect is denied, incl. the implicit default deny)."""
    typed = probe in _ICMP_PROTOS
    while i < len(aces):
        if not budget.spend():
            return ("indeterminate", rect, None)   # too complex -> fail closed
        r = aces[i]
        i += 1
        if r.stateful:
            continue        # matches only return traffic; can't open a new flow
        if not _proto_matches(r.proto, probe):
            continue
        si, di = _intersect(rect[0], r.src), _intersect(rect[1], r.dst)
        if si is None or di is None:
            continue
        spi, dpi = _pr_intersect(rect[2], r.src_port), _pr_intersect(rect[3], r.dst_port)
        if spi is None or dpi is None:
            continue
        iti = _it_intersect(rect[4], r.icmp_type) if typed else rect[4]
        if iti is None:
            continue
        sub = (si, di, spi, dpi, iti)
        if r.imprecise:
            # Over-approximated space intersects the rectangle -> can't decide
            # that part either way. Fail closed.
            return ("indeterminate", sub, r)
        if r.action == "permit":
            return ("permit", sub, r)
        # Exact deny: it kills exactly its slice. Search the remainder pieces
        # against the REST of the ACL (each piece is disjoint from the slice).
        for piece in _rect_minus(rect, r, typed):
            res = _search(aces, i, probe, piece, budget)
            if res is not None:
                return res
        return None
    return None


def _policy_error(msg: str) -> Finding:
    return Finding(
        "policy", "segmentation-policy-error", "high",
        f"SEGMENTATION POLICY ERROR: {msg} — fail-closed: the affected "
        f"assertion gets no PASS until the policy is fixed.",
        "", fix="fix the segmentation policy file")


def _coerce_ports(raw) -> Optional[List[Optional[int]]]:
    """[445, "3389"] -> [445, 3389]; None/[] -> [None] (= any port);
    anything unusable -> None (caller emits a policy error)."""
    if not raw:
        return [None]
    if not isinstance(raw, (list, tuple)):
        raw = [raw]
    out: List[Optional[int]] = []
    for p in raw:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            return None
        if not 0 <= pi <= 65535:
            return None
        out.append(pi)
    return out


def check_segmentation(aces: List[ACE], policy: dict) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(policy, dict):
        return [_policy_error("policy must be a JSON object with 'zones' and "
                              "'must_not_reach'")]

    # Inter-zone (transit) segmentation is decided ONLY by ACEs that govern
    # forwarded traffic — iptables INPUT/OUTPUT host hooks never see a transit
    # packet and are flagged transit=False by the frontend (all other vendors
    # leave transit=True). Each ACL is an INDEPENDENT first-match context
    # (its own interface + direction): one ACL's catch-all deny must never
    # shadow a permit in a DIFFERENT ACL, so every context is searched on its
    # own and a violation in any one of them is a real leak.
    aces = [a for a in aces if a.transit]
    by_acl: Dict[str, List[ACE]] = {}
    for a in aces:
        by_acl.setdefault(a.acl, []).append(a)

    zones: Dict[str, List[_IPNet]] = {}
    bad_zones = set()
    zdef = policy.get("zones") or {}
    if not isinstance(zdef, dict):
        findings.append(_policy_error("'zones' must be an object of "
                                      "name -> [CIDR, ...]"))
        zdef = {}
    for name, cidrs in zdef.items():
        if not isinstance(cidrs, (list, tuple)):
            cidrs = [cidrs]
        nets = []
        for c in cidrs:
            try:
                nets.append(_net(str(c)))
            except ValueError:
                findings.append(_policy_error(f"zone '{name}': invalid CIDR '{c}'"))
                bad_zones.add(name)
        zones[name] = nets

    for assertion in (policy.get("must_not_reach") or []):
        if not isinstance(assertion, dict):
            findings.append(_policy_error(f"must_not_reach entry is not an "
                                          f"object: {assertion!r}"))
            continue
        sname, dname = assertion.get("src"), assertion.get("dst")
        proto = str(assertion.get("proto") or "ip").lower()
        if proto == "any":
            proto = "ip"
        ports = _coerce_ports(assertion.get("ports"))
        if ports is None:
            findings.append(_policy_error(
                f"assertion {sname}->{dname}: 'ports' must be integers in "
                f"0-65535 (got {assertion.get('ports')!r})"))
            continue
        if sname not in zones or dname not in zones:
            missing = ", ".join(repr(z) for z in (sname, dname) if z not in zones)
            findings.append(_policy_error(
                f"assertion {sname!r}->{dname!r} references undefined zone(s) "
                f"{missing} — an empty zone would falsely certify isolation"))
            continue

        # Probe protocols. A wildcard assertion must be checked per concrete
        # protocol — a tcp-only deny does not block the udp/icmp space — plus
        # the "ip" probe for protocols only wildcard rules match. A
        # port-constrained wildcard assertion is about ported protocols.
        if proto not in _WILDCARD_PROTO:
            probes = [proto]
        else:
            probes = sorted({a.proto for a in aces
                             if a.proto not in _WILDCARD_PROTO}) + ["ip"]
            if ports != [None]:
                probes = [p for p in probes if p in _PORTED] or ["tcp", "udp"]

        violation = None      # (sub_rect, rule, probe, port)
        indet = None          # (sub_rect, rule_or_None, acl_name)
        for sa in zones[sname]:
            for db in zones[dname]:
                for port in ports:
                    for probe in probes:
                        dpr = (PortRange(port, port)
                               if port is not None and probe in _PORTED
                               else ANY_PORTS)
                        rect = (sa, db, ANY_PORTS, dpr, _IT_ANY)
                        for acl_name, acl_aces in by_acl.items():
                            res = _search(acl_aces, 0, probe, rect,
                                          _Budget(_MAX_VISITS))
                            if res is None:
                                continue
                            kind, sub, rule = res
                            if kind == "permit":
                                violation = (sub, rule, probe, port)
                                break
                            if indet is None:
                                indet = (sub, rule, acl_name)
                        if violation:
                            break
                    if violation:
                        break
                if violation:
                    break
            if violation:
                break

        if violation:
            sub, rule, probe, port = violation
            swit, dwit = _witness_host(sub[0]), _witness_host(sub[1])
            portsfx = f":{port}" if port is not None else ""
            findings.append(Finding(
                f"{rule.acl}:{rule.seq}", "segmentation-violation", "critical",
                f"SEGMENTATION VIOLATION ({sname} must not reach {dname}): "
                f"the ACL PERMITS {swit} -> {dwit}{portsfx} ({probe}) via "
                f"rule {rule.seq}.",
                rule.raw,
                fix=f"deny {sname}->{dname}{portsfx} before rule {rule.seq}",
                witness=f"{swit} -> {dwit}{portsfx} ({probe})"))
            continue
        if indet:
            sub, rule, acl_name = indet
            if rule is not None:
                findings.append(Finding(
                    f"{rule.acl}:{rule.seq}", "segmentation-indeterminate",
                    "medium",
                    f"Cannot prove {sname} is isolated from {dname} — "
                    f"rule {rule.seq} uses an unmodeled form "
                    f"(neq/complex mask); review manually.",
                    rule.raw, fix="rewrite the rule with explicit ports/masks"))
            else:
                findings.append(Finding(
                    acl_name, "segmentation-indeterminate", "medium",
                    f"Cannot prove {sname} is isolated from {dname} — the "
                    f"{acl_name} ruleset is too complex to search exhaustively; "
                    f"review manually.",
                    "", fix="simplify the ruleset or split the assertion"))
            continue
        if sname in bad_zones or dname in bad_zones:
            # Part of the zone definition was dropped as invalid — a PASS over
            # the remaining subnets would be a false bill of health.
            findings.append(_policy_error(
                f"assertion {sname}->{dname}: zone definition has invalid "
                f"CIDR(s), isolation cannot be certified"))
            continue
        label = f"{sname}!->{dname}" + (f"/{proto}" if proto != "ip" else "")
        real_ports = [p for p in ports if p is not None]
        scope = ""
        if proto != "ip":
            scope = f" on {proto}" + (f"/{real_ports}" if real_ports else "")
        findings.append(Finding(
            label, "segmentation-ok", "info",
            f"PASS: {sname} cannot reach {dname}{scope}"
            " (no permitted witness flow found).", "",
            fix=""))
    return findings
