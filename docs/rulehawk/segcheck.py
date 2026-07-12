"""Segmentation-intent checking — the audit-evidence / compliance value.

Declare zones (named CIDR sets) and `must_not_reach` assertions, e.g. "CORP must
not reach PCI on tcp/445,3389". For each assertion we search the forbidden
packet space EXACTLY under first-match semantics: walking each ACL in order,
an exact deny SUBTRACTS its slice of the space and the search continues on the
remainder, so an earlier deny that blocks only part of the space (one host, one
port range, one source-port band, one ICMP type) can never hide a permit that
leaks the rest — and a deny that blocks all of it produces no false alarm. A
violation is reported with a CONCRETE WITNESS packet the ACL provably permits
(port included, even for portless assertions); any imprecise (over-approximated)
rule the search touches yields an honest "indeterminate / review manually"
instead of a possibly-wrong verdict.

A wildcard assertion (`proto: "ip"`) is probed per concrete protocol: a
tcp-only deny must not be allowed to "block" the udp/icmp part of the space.
ICMP-typed rules keep their type as a search dimension: a `deny icmp echo`
does not block an `echo-reply` witness.

Policy errors (unknown/omitted zone name, bad CIDR, bad port) FAIL CLOSED: they
emit a high-severity `segmentation-error` finding and the affected assertion is
never given a PASS — a typo'd zone must not certify isolation over an empty
search space.

Policy (JSON):
  {"zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
   "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                       "ports": [445, 3389]}]}
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

from .analyze import Finding
from .model import (ACE, ANY_PORTS, _ICMP_PROTOS, _IPNet, _PORTED,
                    _WILDCARD_PROTO, PortRange)

# Rule-visit budget per (assertion x zone-pair x port x probe x ACL) search.
# Exhaustion returns an INDETERMINATE (fail-closed), never a PASS. Sized for
# the expensive direction — PROVING a PASS on a large ACL of partial denies
# subdivides the space (~rules x pieces x rules visits; a 400-deny wall needs
# ~1.3M); a violation exits early and never approaches it. Each visit is a few
# integer compares, so the worst case stays low single-digit seconds.
_MAX_VISITS = 5_000_000

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


def _witness_port(dpr: PortRange) -> int:
    """A concrete, preferably ordinary representative of the leaking port range
    (0 reads as degenerate to auditors — avoid it when the range allows)."""
    return dpr.lo if dpr.lo > 0 else min(1, dpr.hi)


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


def _search(aces: List[ACE], i0: int, probe: str, rect0, budget: _Budget):
    """First-match search for a permitted (or undecidable) packet inside `rect0`
    over aces[i0:]. Returns ("permit"|"indeterminate", sub_rect, rule) or None
    (= every packet in the rectangle is denied, incl. the implicit default deny).

    Iterative DFS over (rule-index, rectangle) — an exact deny splits the
    rectangle into disjoint remainder pieces that each continue against the
    REST of the ACL. A worklist (not recursion) so a config that is one long
    wall of partial denies cannot hit the interpreter recursion limit."""
    typed = probe in _ICMP_PROTOS
    stack = [(i0, rect0)]
    while stack:
        i, rect = stack.pop()
        while i < len(aces):
            if not budget.spend():
                return ("indeterminate", rect, None)   # too complex -> fail closed
            r = aces[i]
            i += 1
            if r.stateful:
                continue    # matches only return traffic; can't open a new flow
            if not _proto_matches(r.proto, probe):
                continue
            si, di = _intersect(rect[0], r.src), _intersect(rect[1], r.dst)
            if si is None or di is None:
                continue
            if r.imprecise:
                # Fail closed BEFORE the port/type intersection: an imprecise
                # ACE's port range may be the under-approximated part (e.g.
                # `eq www <unknown-service>` keeps the known port exact and
                # flags imprecise for the unknown one), so "its ports don't
                # overlap the probe" proves nothing.
                return ("indeterminate",
                        (si, di, rect[2], rect[3], rect[4]), r)
            spi, dpi = _pr_intersect(rect[2], r.src_port), _pr_intersect(rect[3], r.dst_port)
            if spi is None or dpi is None:
                continue
            iti = _it_intersect(rect[4], r.icmp_type) if typed else rect[4]
            if iti is None:
                continue
            sub = (si, di, spi, dpi, iti)
            if r.action == "permit":
                return ("permit", sub, r)
            # Exact deny: it kills exactly its slice. Continue with the first
            # remainder piece inline; queue the rest at the same rule index.
            pieces = _rect_minus(rect, r, typed)
            if not pieces:
                break                     # rect fully denied by r
            rect = pieces[0]
            for piece in reversed(pieces[1:]):
                stack.append((i, piece))
        # inner loop exhausted the ACL: this rectangle falls to implicit deny
    return None


def _policy_error(rule_id: str, msg: str, fix: str) -> Finding:
    return Finding(rule_id, "segmentation-error", "high", msg, "", fix=fix)


def _coerce_ports(raw) -> Optional[List[Optional[int]]]:
    """[445, "3389"] -> [445, 3389]; None/[] -> [None] (= any port);
    anything unusable -> None (caller emits a segmentation-error)."""
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
        return [_policy_error(
            "policy",
            "CANNOT EVALUATE: policy must be a JSON object with 'zones' and "
            "'must_not_reach'. No assertion was checked — no isolation is proven.",
            "fix the segmentation policy file")]

    # Inter-zone (transit) segmentation is decided ONLY by ACEs that govern
    # forwarded traffic — iptables INPUT/OUTPUT are host in/out hooks that never
    # see a transit packet and are flagged transit=False by the frontend (all
    # other vendors leave transit=True). Each ACL is an INDEPENDENT first-match
    # context (its own interface + direction): one ACL's catch-all deny must
    # never shadow a permit in a DIFFERENT ACL, so every context is searched on
    # its own and a violation in any one of them is a real leak.
    aces = [a for a in aces if a.transit]
    by_acl: Dict[str, List[ACE]] = {}
    for a in aces:
        by_acl.setdefault(a.acl, []).append(a)

    zones: Dict[str, List[_IPNet]] = {}
    bad_zones = set()
    zdef = policy.get("zones") or {}
    if not isinstance(zdef, dict):
        findings.append(_policy_error(
            "policy", "SEGMENTATION POLICY ERROR: 'zones' must be an object of "
            "name -> [CIDR, ...] — fail-closed: no assertion gets a PASS until "
            "the policy is fixed.", "fix the segmentation policy file"))
        zdef = {}
    for name, cidrs in zdef.items():
        if not isinstance(cidrs, (list, tuple)):
            cidrs = [cidrs]
        nets = []
        for c in cidrs:
            try:
                nets.append(_net(str(c)))
            except ValueError:
                findings.append(_policy_error(
                    "policy",
                    f"SEGMENTATION POLICY ERROR: zone '{name}': invalid CIDR "
                    f"'{c}' — fail-closed: assertions over this zone get no "
                    f"PASS until the policy is fixed.",
                    "fix the segmentation policy file"))
                bad_zones.add(name)
        zones[name] = nets

    # Both assertion directions share the SAME exact search; only the labeling
    # flips. must_not_reach: a permitted packet is a VIOLATION and "all denied"
    # is the PASS. must_reach (deployment/vendor connectivity prechecks, e.g.
    # "hosts must reach the proxy egress ranges"): a permitted packet is the
    # connectivity PROOF and "all denied" means the flow is BROKEN at the
    # filter layer. Indeterminate fails closed in both: it never upgrades to a
    # PASS and never to a connectivity OK.
    for direction, rel in (("must_not_reach", "must not reach"),
                           ("must_reach", "must reach")):
        for assertion in (policy.get(direction) or []):
            if not isinstance(assertion, dict):
                findings.append(_policy_error(
                    "policy", f"SEGMENTATION POLICY ERROR: {direction} entry is "
                    f"not an object: {assertion!r} — this assertion was NOT "
                    f"checked.", "fix the segmentation policy file"))
                continue
            sname, dname = assertion.get("src"), assertion.get("dst")
            proto = str(assertion.get("proto") or "ip").lower()
            if proto == "any":
                proto = "ip"
            arrow = "!->" if direction == "must_not_reach" else "->"
            label = f"{sname}{arrow}{dname}" + (f"/{proto}" if proto != "ip" else "")
            # Fail closed on an assertion that names a zone we can't resolve. A
            # null (omitted key) or misspelled/undefined src/dst would make the
            # witness search iterate over an EMPTY zone and silently emit a
            # confident verdict for a check that never ran.
            _defined = sorted(zones.keys())
            _unknown = [role for role, nm in (("src", sname), ("dst", dname))
                        if nm is None or nm not in zones]
            if _unknown:
                _detail = "; ".join(
                    (f"missing {role} zone" if (sname if role == "src" else dname) is None
                     else f"unknown {role} zone "
                          f"'{sname if role == 'src' else dname}'")
                    for role in _unknown)
                findings.append(_policy_error(
                    label,
                    f"CANNOT EVALUATE ({sname} {rel} {dname}): {_detail}. "
                    f"Defined zones: {', '.join(_defined) or '(none)'}. "
                    f"This assertion was NOT checked — nothing is proven.",
                    ("define the named zone(s) in policy 'zones', or fix the "
                     "typo so src/dst reference existing zones")))
                continue
            ports = _coerce_ports(assertion.get("ports"))
            if ports is None:
                findings.append(_policy_error(
                    label,
                    f"SEGMENTATION POLICY ERROR: assertion {sname}->{dname}: "
                    f"'ports' must be integers in 0-65535 "
                    f"(got {assertion.get('ports')!r}) — this assertion was NOT "
                    f"checked.", "fix the segmentation policy file"))
                continue

            permit_hit, indet = _probe_space(aces, by_acl, zones[sname],
                                             zones[dname], proto, ports)

            # Portless assertions cover EVERY port, so say "on tcp" (any port),
            # not the abstract "on tcp/[None]".
            scope = ""
            if proto != "ip":
                scope = f" on {proto}" + ("" if ports == [None] else f"/{ports}")

            if permit_hit:
                sub, rule, probe, port = permit_hit
                swit, dwit = _witness_host(sub[0]), _witness_host(sub[1])
                # The witness must be a REAL packet, concrete in the port
                # dimension too: for a portless ported assertion, pick a
                # representative from the sub-rectangle PROVED permitted.
                wport = port
                if wport is None and probe in _PORTED:
                    wport = _witness_port(sub[3])
                portsfx = f":{wport}" if wport is not None else ""
                _line_part = f" (line {rule.line})" if rule.line else ""
                if direction == "must_not_reach":
                    # Paste-ready fix: the actual intersecting CIDRs
                    # (engine-proven, sub ⊆ zone ∩ rule), scoped to the ASSERTED
                    # ports — a portless assertion forbids EVERY port, so the
                    # deny must be portless too.
                    _port_part = f" port {port}" if port is not None else ""
                    findings.append(Finding(
                        f"{rule.acl}:{rule.seq}", "segmentation-violation",
                        "critical",
                        f"SEGMENTATION VIOLATION ({sname} must not reach "
                        f"{dname}): the ACL PERMITS {swit} -> {dwit}{portsfx} "
                        f"({probe}) via rule {rule.seq}.",
                        rule.raw,
                        fix=(f"deny {sub[0]} -> {sub[1]}{_port_part} "
                             f"before rule {rule.seq}{_line_part}"),
                        witness=f"{swit} -> {dwit}{portsfx} ({probe})",
                        line=rule.line))
                else:
                    findings.append(Finding(
                        f"{rule.acl}:{rule.seq}", "connectivity-ok", "info",
                        f"CONNECTIVITY OK ({sname} must reach {dname}{scope}): "
                        f"rule {rule.seq}{_line_part} permits the witness "
                        f"packet {swit} -> {dwit}{portsfx} ({probe}) — the "
                        f"filter layer does not block this deployment flow.",
                        rule.raw,
                        witness=f"{swit} -> {dwit}{portsfx} ({probe})",
                        line=rule.line))
                continue
            if indet:
                sub, rule, acl_name = indet
                goal = ("isolated from" if direction == "must_not_reach"
                        else "able to reach")
                if rule is not None:
                    findings.append(Finding(
                        f"{rule.acl}:{rule.seq}",
                        f"{_IND_KIND[direction]}", "medium",
                        f"Cannot prove {sname} is {goal} {dname} — "
                        f"rule {rule.seq} uses an unmodeled form "
                        f"(neq/complex mask); review manually.",
                        rule.raw,
                        fix="rewrite the rule with explicit ports/masks",
                        line=rule.line))
                else:
                    findings.append(Finding(
                        acl_name, f"{_IND_KIND[direction]}", "medium",
                        f"Cannot prove {sname} is {goal} {dname} — the "
                        f"{acl_name} ruleset is too complex to search "
                        f"exhaustively; review manually.",
                        "", fix="simplify the ruleset or split the assertion"))
                continue
            if sname in bad_zones or dname in bad_zones:
                # Part of the zone definition was dropped as invalid — a
                # verdict over the remaining subnets would be a false one.
                findings.append(_policy_error(
                    label,
                    f"SEGMENTATION POLICY ERROR: assertion {sname}->{dname}: "
                    f"zone definition has invalid CIDR(s), the assertion "
                    f"cannot be certified.",
                    "fix the segmentation policy file"))
                continue
            if direction == "must_not_reach":
                findings.append(Finding(
                    label, "segmentation-ok", "info",
                    f"PASS: {sname} cannot reach {dname}{scope}"
                    + " (no permitted witness flow found).", "",
                    fix=""))
            else:
                findings.append(Finding(
                    label, "connectivity-broken", "high",
                    f"CONNECTIVITY BROKEN ({sname} must reach {dname}{scope}): "
                    f"no parsed ruleset permits ANY packet of this flow — the "
                    f"deployment traffic will be dropped at the filter layer.",
                    "",
                    fix=f"permit {sname} -> {dname}{scope} in the ruleset "
                        f"governing this path"))
    return findings


_IND_KIND = {"must_not_reach": "segmentation-indeterminate",
             "must_reach": "connectivity-indeterminate"}


def _probe_space(aces: List[ACE], by_acl: Dict[str, List[ACE]],
                 sa_nets: List[_IPNet], db_nets: List[_IPNet],
                 proto: str, ports: List[Optional[int]]):
    """Search every (zone-net pair x port x probe proto x ACL context) for a
    permitted packet in the asserted flow space. Returns (permit_hit, indet):
    permit_hit = (sub_rect, rule, probe, port) for the first provably
    permitted packet, indet = (sub_rect, rule_or_None, acl_name) for the first
    undecidable slice. Shared by both assertion directions — a permit is the
    must_not_reach VIOLATION and the must_reach PROOF.

    A wildcard assertion is checked per concrete protocol — a tcp-only deny
    does not block the udp/icmp space — plus the "ip" probe for protocols only
    wildcard rules match. The "ip" probe goes FIRST: when a `permit ip` rule
    decides the boundary, the strongest witness is the any-protocol one. A
    port-constrained wildcard assertion is about ported protocols."""
    if proto not in _WILDCARD_PROTO:
        probes = [proto]
    else:
        probes = ["ip"] + sorted({a.proto for a in aces
                                  if a.proto not in _WILDCARD_PROTO})
        if ports != [None]:
            probes = [p for p in probes if p in _PORTED] or ["tcp", "udp"]

    indet = None
    for sa in sa_nets:
        for db in db_nets:
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
                            return (sub, rule, probe, port), indet
                        if indet is None:
                            indet = (sub, rule, acl_name)
    return None, indet
