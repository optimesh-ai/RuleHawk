"""Parse Cisco Umbrella Cloud-Delivered Firewall (CDFW) rules into RuleHawk `ACE`s.

SCOPE — CDFW L3/L4 ONLY. Umbrella has two distinct enforcement layers:
  * the DNS-layer domain/category filtering (Secure Internet Gateway), and
  * the Cloud-Delivered Firewall (CDFW), an ORDERED, first-match packet filter
    over (action, protocol, src/dst network, ports).
This frontend models the CDFW L3/L4 layer ONLY. The DNS-layer domain/category
policy is a name-space control, not a packet match-space, so it is NOT
representable in the (proto, src-net, dst-net, src-port, dst-port) model and is
deliberately out of scope — a packet auditor must never imply it reasoned about
domain filtering it never saw.

WHY THIS SHAPE FITS THE ENGINE. The downstream engine (`analyze.py`,
`segcheck.py`, `model.ACE`) reasons about ORDERED, first-match `permit`/`deny`
rules over an L3/L4 packet space. A CDFW policy is exactly that: an ordered list
of rules (by `rank`/`order`), first terminating match wins, ALLOW -> permit,
BLOCK -> deny. So the whole existing analysis is reused unchanged; this module
only adds a new *frontend* emitting the same `(List[ACE], notes)` IR.

ASSUMED EXPORT SCHEMA (the Umbrella CDFW export format is not perfectly
standardized publicly — this is the plausible shape, implemented tolerantly, to
be reconciled with a real export later). Either a top-level object with a
`rules` array, OR a bare top-level JSON array of rule objects. Each rule:
  {"name": str, "order"|"rank": int, "action": "ALLOW"|"BLOCK"|...,
   "protocol": "TCP"|"UDP"|"ICMP"|"ANY"|6|17|1|...,
   "sources":      [{"type": "CIDR"|"IP"|"ANY"|<ref>, "value": "<cidr>"}],
   "destinations": [{"type": "CIDR"|"IP"|"ANY"|<ref>, "value": "<cidr>"}],
   "ports": [{"from": N, "to": M}]  |  "port": N  |  (absent = all ports)}
Reasonable field-name variants are tolerated (source/src, destination/dst/dest,
proto, cidr/network/ip/address, from/start/low, to/end/high). A `policyId`/
`policy` field, when present, separates rules into per-policy first-match
contexts (`acl`); otherwise all rules share one global ordered context "cdfw".

SOUNDNESS (the parser contract in model.py): an ACE's modeled space must be a
SUPERSET of the rule's true match space — widen, never narrow. Anything not
exactly modelable (an unresolved source/destination REFERENCE — a network
object, tunnel, network-tunnel-group, site; an unrecognized protocol; an
unparsable CIDR or port; a source×destination cross-product past the cap) is
OVER-APPROXIMATED to ANY in that dimension and flagged `imprecise` + surfaced as
a note, so `covers()` never uses it to prove another rule dead and segcheck
yields an honest INDETERMINATE instead of a possibly-wrong verdict.

FAIL-CLOSED DEFAULT HANDLING (a soundness decision). Umbrella CDFW's default
action for traffic no rule matches is CONFIGURABLE and is NOT reliably present in
a rule export. Appending a synthetic default-PERMIT would let segcheck FALSE-PASS
a `must_not_reach` (a leak reported as isolated); appending a default-DENY would
FALSE-PASS a `must_reach` and could hide a real leak behind an assumed block. So
we never guess a terminating default. Instead:
  * if the export carries an explicit trailing catch-all / default rule (any
    src, any dst, any proto, no ports, or an explicit default flag) it is modeled
    as-is (it already decides the tail), and NO marker is added;
  * otherwise a trailing IMPRECISE marker ACE (`permit ip any any`, imprecise,
    one per address family) is appended per context, so any flow not decided by
    an explicit rule is segmentation-INDETERMINATE (fail closed) — never a clean
    PASS and never a silent leak. Provide the CDFW default action to make it
    precise.

Robustness: invalid JSON -> detect False, parse returns ([], [note]); missing or
odd fields degrade with a note, never a crash.
"""

from __future__ import annotations

import ipaddress
import json
from typing import List, Optional, Tuple

from .model import ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")

# Cap on the source×destination rectangle expansion. Past this, both dimensions
# widen to ANY + imprecise (a superset) rather than emit an ACE explosion.
_MAX_COMBOS = 256

# action value families (case-insensitive). ALLOW -> permit, BLOCK -> deny.
_ALLOW = frozenset({"ALLOW", "ALLOW_LIST", "ALLOWLIST", "ALLOW-LIST",
                    "PERMIT", "ACCEPT", "FORWARD"})
_DENY = frozenset({"BLOCK", "BLOCK_LIST", "BLOCKLIST", "BLOCK-LIST",
                   "DENY", "DENY_LIST", "DROP", "REJECT"})

# protocol name / number -> canonical proto. Absent or "any" -> "ip" (all protos).
_PROTO_NUM = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6",
              "47": "gre", "132": "sctp"}
_PROTO_NAME = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6",
               "icmp6": "icmpv6", "ipv6-icmp": "icmpv6", "gre": "gre",
               "sctp": "sctp", "ip": "ip", "any": "ip", "all": "ip", "*": "ip",
               "": "ip"}
# Protocols that carry a meaningful destination-port dimension (matches model._PORTED
# for the subset Umbrella emits). Ports on any other proto are ignored (any).
_PORTED = frozenset({"tcp", "udp", "sctp"})

# endpoint `type` families
_ANY_TYPES = frozenset({"ANY", "ALL", "ANY_ADDRESS", "ANYADDRESS", "*"})
_CIDR_TYPES = frozenset({"CIDR", "IP", "IPADDRESS", "IP_ADDRESS", "HOST",
                         "NETWORK", "SUBNET", "IPV4", "IPV6", "IPV4_ADDRESS",
                         "IPV6_ADDRESS", "IP_CIDR"})

# top-level keys that may hold the ordered rule array
_RULES_KEYS = ("rules", "Rules", "cdfwRules", "ruleList", "firewallRules")

# AWS Security Group markers — a CDFW frontend must NEVER claim these.
_AWS_TOP_MARKERS = frozenset({"SecurityGroups", "IpPermissions",
                              "IpPermissionsEgress", "GroupId"})
_AWS_RULE_MARKERS = ("IpPermissions", "IpPermissionsEgress", "GroupId",
                     "IpRanges", "UserIdGroupPairs")


# ── small tolerant helpers ─────────────────────────────────────────────────────

def _num(v) -> Optional[int]:
    """int from an int or numeric string; None otherwise. `bool` is NOT a number
    here (True/False must not read as 1/0 for an order/port)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip())
    except (ValueError, TypeError, RecursionError):
        return None


def _try_net(val) -> Optional[_IPNet]:
    try:
        return ipaddress.ip_network(str(val).strip(), strict=False)
    except (ValueError, TypeError, RecursionError):
        return None


def _dedup(nets: List[_IPNet]) -> List[_IPNet]:
    out: List[_IPNet] = []
    for n in nets:
        if n not in out:
            out.append(n)
    return out


def _as_list(raw) -> list:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    return [raw]


def _first(d: dict, *keys):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def _typ_val(item) -> Tuple[str, object]:
    """(TYPE upper-cased, value) for an endpoint item that may be a dict or a
    bare string CIDR/'ANY'."""
    if isinstance(item, dict):
        typ = str(item.get("type") or item.get("kind") or "").strip().upper()
        val = _first(item, "value", "cidr", "network", "ip", "address",
                     "subnet", "prefix")
        return typ, val
    if isinstance(item, str):
        return "", item
    return "", None


# ── field parsers (each widens + flags imprecise when not exactly modelable) ────

def _action(raw) -> Optional[str]:
    s = str(raw or "").strip().upper()
    if s in _ALLOW:
        return "permit"
    if s in _DENY:
        return "deny"
    return None


def _one_proto(raw, notes: List[str], label: str) -> Tuple[str, bool]:
    if raw is None:
        return "ip", False
    s = str(raw).strip().lower()
    if s in _PROTO_NUM:
        return _PROTO_NUM[s], False
    if s in _PROTO_NAME:
        return _PROTO_NAME[s], False
    notes.append(f"{label}: unrecognized protocol {raw!r} — widened to any "
                 f"protocol (marked imprecise; verify manually)")
    return "ip", True


def _protos(raw, notes: List[str], label: str) -> Tuple[List[str], bool]:
    """Normalize `protocol` (string, number, or list) to a de-duplicated proto
    list + an imprecise flag. A list is expanded to the exact union."""
    if isinstance(raw, list):
        protos: List[str] = []
        imp = False
        for x in raw:
            p, i = _one_proto(x, notes, label)
            protos.append(p)
            imp = imp or i
        seen: List[str] = []
        for p in protos:
            if p not in seen:
                seen.append(p)
        return (seen or ["ip"]), imp
    p, i = _one_proto(raw, notes, label)
    return [p], i


def _endpoints(raw, label: str, notes: List[str]) -> Tuple[List[_IPNet], bool]:
    """Expand a sources/destinations value to a list of nets + imprecise flag.

    type ANY (or absent/empty) -> both families [0.0.0.0/0, ::/0]. type CIDR/IP
    -> that network. Any UNRESOLVED reference (network-object/tunnel/
    network-tunnel-group/site/...) or unparsable value widens the WHOLE dimension
    to ANY (both families) + imprecise (a sound superset — never a subset)."""
    items = _as_list(raw)
    if not items:
        # Absent/empty selector = match any (the firewall default for an omitted
        # dimension); exact, not imprecise — mirrors an absent iptables -s/-d.
        return [_ANY4, _ANY6], False
    nets: List[_IPNet] = []
    imprecise = False
    for item in items:
        typ, val = _typ_val(item)
        is_any_str = isinstance(item, str) and item.strip().lower() in ("any", "all", "*")
        if typ in _ANY_TYPES or is_any_str:
            nets += [_ANY4, _ANY6]
        elif typ in _CIDR_TYPES and val is not None:
            net = _try_net(val)
            if net is None:
                imprecise = True
                notes.append(f"{label}: unparsable address {val!r} — widened to "
                             f"ANY (marked imprecise; verify manually)")
            else:
                nets.append(net)
        elif typ == "" and val is not None and _try_net(val) is not None:
            nets.append(_try_net(val))          # bare CIDR string, tolerated
        else:
            # A network object / tunnel / network-tunnel-group / site / unknown
            # type: an UNRESOLVED reference. Widen this dimension to ANY.
            ref = typ or (str(val) if val is not None else repr(item))
            imprecise = True
            notes.append(f"{label}: unresolved reference '{ref}' — not a CIDR/IP, "
                         f"widened to ANY (marked imprecise; verify manually)")
    if imprecise:
        return [_ANY4, _ANY6], True             # whole dimension over-approximated
    return (_dedup(nets) or [_ANY4, _ANY6]), False


def _one_port(entry) -> Optional[PortRange]:
    """One ports entry -> PortRange, or None if unparsable. Accepts
    {"from":N,"to":M}, {"port":N}/{"value":N}, or a bare number."""
    if isinstance(entry, dict):
        lo = _first(entry, "from", "start", "low", "min", "begin")
        hi = _first(entry, "to", "end", "high", "max", "finish")
        if lo is None and hi is None:
            p = _first(entry, "port", "value", "number")
            lo = hi = p
        if lo is None and hi is not None:
            lo = hi
        if hi is None and lo is not None:
            hi = lo
        ln, hn = _num(lo), _num(hi)
    else:
        ln = hn = _num(entry)
    if ln is None or hn is None:
        return None
    lo_i, hi_i = min(ln, hn), max(ln, hn)
    if lo_i < PORT_MIN or hi_i > PORT_MAX:
        return None
    return PortRange(lo_i, hi_i)


def _ports(rule: dict, proto: str, notes: List[str],
           label: str) -> Tuple[List[PortRange], bool]:
    """Destination-port ranges for one rule under one proto + imprecise flag.

    Ports apply to tcp/udp/sctp ONLY; on any other proto they are ignored (any)
    and never attached to icmp/ip. An unparsable entry widens ports to ANY +
    imprecise."""
    raw = _first(rule, "ports", "port", "destinationPorts", "dstPorts")
    if proto not in _PORTED:
        if raw is not None:
            notes.append(f"{label}: ports specified on non-ported protocol "
                         f"'{proto}' — ignored (matches any port)")
        return [ANY_PORTS], False
    entries = _as_list(raw)
    if not entries:
        return [ANY_PORTS], False               # absent = all ports (exact)
    ranges: List[PortRange] = []
    imprecise = False
    for e in entries:
        pr = _one_port(e)
        if pr is None:
            imprecise = True
            notes.append(f"{label}: unparsable port entry {e!r} — widened to ANY "
                         f"ports (marked imprecise; verify manually)")
        else:
            ranges.append(pr)
    if imprecise or not ranges:
        return [ANY_PORTS], imprecise
    return ranges, False


def _acl_of(rule: dict) -> str:
    """First-match context for a rule: 'cdfw' unless a policy id separates it."""
    pid = _first(rule, "policyId", "policy", "policyName", "rulesetId", "ruleset")
    if pid is None:
        return "cdfw"
    return f"cdfw:{pid}"


def _is_default_rule(rule: Optional[dict]) -> bool:
    """True iff `rule` is an ACTUAL trailing catch-all / default: a total
    match-all (any/absent src+dst, any/absent proto, no ports). Such a rule
    already decides the tail, so no fail-closed marker is appended after it.

    A self-declared `default`/`isDefault`/`type:"default"` flag is NOT trusted on
    its own (the earlier soundness hole): the flag on a NARROW rule — e.g. a
    specific-proto/host BLOCK carrying `"default": true` — does not decide the
    tail, yet suppressing the marker for it would let an unmatched forbidden flow
    fall to segcheck's implicit default-deny and false-PASS as `segmentation-ok`.
    Only the match-all shape below (which genuinely covers every unmatched
    packet) suppresses the marker; a flagged narrow rule keeps the marker and its
    unmatched flows stay INDETERMINATE."""
    if not isinstance(rule, dict):
        return False

    def _any_ep(raw) -> bool:
        items = _as_list(raw)
        if not items:
            return True
        for it in items:
            typ, _ = _typ_val(it)
            if typ in _ANY_TYPES or (isinstance(it, str)
                                     and it.strip().lower() in ("any", "all", "*")):
                continue
            return False
        return True

    proto_raw = _first(rule, "protocol", "proto")
    proto_any = str(proto_raw or "").strip().lower() in ("", "any", "all", "ip", "*")
    no_ports = _first(rule, "ports", "port", "destinationPorts", "dstPorts") is None
    return (proto_any and no_ports
            and _any_ep(_first(rule, "sources", "source", "src"))
            and _any_ep(_first(rule, "destinations", "destination", "dst", "dest")))


def _raw(acl: str, action: str, proto: str, s: _IPNet, d: _IPNet,
         pr: PortRange) -> str:
    base = f"[{acl}] {action} {proto} {s} -> {d}"
    if not pr.is_any():
        base += f" dport {pr}"
    return base


# ── detect / parse ─────────────────────────────────────────────────────────────

def _rules_list(data) -> Tuple[Optional[list], Optional[str]]:
    """Locate the ordered rule array. Returns (rules, error_note)."""
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict):
        for k in _RULES_KEYS:
            v = data.get(k)
            if isinstance(v, list):
                return v, None
        return None, ("JSON has no 'rules' array — not an Umbrella CDFW export "
                      "(nothing parsed).")
    return None, ("top-level JSON is neither an object with a 'rules' array nor a "
                  "bare array of rule objects — nothing parsed.")


def _has_aws_sg_markers(data) -> bool:
    """AWS Security Group disambiguation: a CDFW export must not carry SG markers."""
    if isinstance(data, dict):
        if any(k in data for k in _AWS_TOP_MARKERS):
            return True
    return False


def detect(text: str) -> bool:
    """Heuristic: does `text` look like an Umbrella CDFW rule export?

    Strict — valid JSON carrying the CDFW-specific triple (an item with BOTH a
    source AND a destination selector AND an ALLOW/BLOCK-family `action`), and
    the ABSENCE of AWS Security-Group markers (SecurityGroups / IpPermissions /
    GroupId). Arbitrary JSON, Cisco/Junos/PAN-OS text, and AWS SG JSON are all
    rejected.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return False
    if _has_aws_sg_markers(data):
        return False
    rules, _ = _rules_list(data)
    if not rules:
        return False
    found = False
    for r in rules:
        if not isinstance(r, dict):
            continue
        if any(m in r for m in _AWS_RULE_MARKERS):
            return False                        # an AWS SG rule object — not CDFW
        # DETECTION requires the full-word CDFW keys (`sources`/`destinations`,
        # the documented schema); the abbreviated `src`/`dst` are accepted by
        # the PARSER but are too generic to route on — a bare
        # {"rules":[{"action","src","dst"}]} is ambiguous garbage, not a
        # confident CDFW export, so it must fall through to the Cisco fallback.
        has_src = _first(r, "sources", "source") is not None
        has_dst = _first(r, "destinations", "destination") is not None
        if has_src and has_dst and _action(r.get("action")) is not None:
            found = True
    return found


def parse_umbrella(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse an Umbrella CDFW rule export in `text`; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation`
    consume the result unchanged. Rules are ordered first-match by `order`/`rank`
    (stable), grouped into per-policy contexts (`acl`), and each context gets a
    trailing fail-closed IMPRECISE marker unless it already ends in an explicit
    catch-all/default rule (see the module docstring).
    """
    notes: List[str] = []
    try:
        data = json.loads(text)
    except (ValueError, TypeError, RecursionError) as exc:
        return [], [f"input is not valid JSON ({exc}) — no Umbrella CDFW rules "
                    f"parsed."]

    if _has_aws_sg_markers(data):
        return [], ["input carries AWS Security-Group markers "
                    "(SecurityGroups/IpPermissions/GroupId) — this is not an "
                    "Umbrella CDFW export; nothing parsed."]

    rules, err = _rules_list(data)
    if rules is None:
        return [], [err]
    if not rules:
        return [], ["Umbrella CDFW export has an empty 'rules' array — nothing "
                    "to model."]

    # Per-rule AWS Security-Group guard (mirrors detect()): a bare array — or a
    # 'rules' array — of SG rule objects (GroupId / IpPermissions / IpRanges /
    # UserIdGroupPairs) is NOT a CDFW export. detect() already routes it away, so
    # this is defense-in-depth for a direct call: reject cleanly (as the dict
    # form is rejected above) instead of emitting fail-closed markers over an
    # AWS-shaped input.
    if any(isinstance(r, dict) and any(m in r for m in _AWS_RULE_MARKERS)
           for r in rules):
        return [], ["input carries AWS Security-Group markers "
                    "(GroupId/IpPermissions/IpRanges) — this is not an Umbrella "
                    "CDFW export; nothing parsed."]

    # Order first-match by `order`/`rank` ascending, stable. Rules missing an
    # explicit order keep document order and sort after ordered ones.
    indexed = list(enumerate(rules))

    def _has_order(r) -> bool:
        return (isinstance(r, dict)
                and (_num(r.get("order")) is not None
                     or _num(r.get("rank")) is not None))

    # If the array MIXES rules that carry an explicit order/rank with rules that
    # DON'T, the intended first-match evaluation order is AMBIGUOUS: sorting the
    # unordered rules after the ordered ones (below) can reposition a rule the
    # real device evaluates in document position — flipping a leak to a false
    # PASS. We can't recover the device's true order, so we over-approximate:
    # every emitted ACE is flagged imprecise (segcheck → INDETERMINATE, never a
    # false PASS). When ALL rules have an order — or NONE do (pure document
    # order) — the order is unambiguous and behavior stays exact.
    dict_rules = [r for _, r in indexed if isinstance(r, dict)]
    order_ambiguous = (any(_has_order(r) for r in dict_rules)
                       and any(not _has_order(r) for r in dict_rules))
    if order_ambiguous:
        notes.append(
            "rules array MIXES entries carrying an explicit order/rank with "
            "entries that don't — the first-match evaluation order is ambiguous; "
            "every rule is marked IMPRECISE so segmentation is INDETERMINATE "
            "(never a false PASS). Give every rule an explicit order/rank, or "
            "none (pure document order), to make this precise.")

    def _sortkey(t):
        idx, r = t
        o = None
        if isinstance(r, dict):
            o = _num(r.get("order"))
            if o is None:
                o = _num(r.get("rank"))
        return (0, o, idx) if o is not None else (1, idx, idx)

    indexed.sort(key=_sortkey)

    by_acl: "dict[str, List[ACE]]" = {}
    acl_order: List[str] = []
    last_valid_by_acl: "dict[str, dict]" = {}

    for idx, r in indexed:
        if not isinstance(r, dict):
            notes.append(f"rule #{idx + 1} is not a JSON object ({r!r}) — skipped.")
            continue
        acl = _acl_of(r)
        if acl not in by_acl:
            by_acl[acl] = []
            acl_order.append(acl)
        out = by_acl[acl]

        name = r.get("name") or r.get("id") or f"rule-{idx + 1}"
        label = f"umbrella rule '{name}'"

        action = _action(r.get("action"))
        if action is None:
            notes.append(f"{label}: unrecognized/absent action "
                         f"{r.get('action')!r} — rule NOT modeled (skipped).")
            continue

        protos, p_imp = _protos(_first(r, "protocol", "proto"), notes, label)
        src_nets, s_imp = _endpoints(_first(r, "sources", "source", "src"),
                                     f"{label} source", notes)
        dst_nets, d_imp = _endpoints(
            _first(r, "destinations", "destination", "dst", "dest"),
            f"{label} destination", notes)
        base_imp = p_imp or s_imp or d_imp

        combos = len(src_nets) * len(dst_nets)
        if combos > _MAX_COMBOS:
            notes.append(f"{label}: {combos} source×destination combinations "
                         f"exceed the cap {_MAX_COMBOS} — widened to ANY×ANY "
                         f"(marked imprecise; verify manually).")
            src_nets, dst_nets = [_ANY4, _ANY6], [_ANY4, _ANY6]
            base_imp = True

        line = _num(r.get("line")) or 0
        emitted_here = False
        for proto in protos:
            port_ranges, port_imp = _ports(r, proto, notes, label)
            imprecise = base_imp or port_imp or order_ambiguous
            for s in src_nets:
                for d in dst_nets:
                    if s.version != d.version:
                        continue            # cross-family combo matches no packet
                    for pr in port_ranges:
                        seq = len(out) + 1
                        out.append(ACE(
                            seq=seq, action=action, proto=proto, src=s, dst=d,
                            src_port=ANY_PORTS, dst_port=pr,
                            imprecise=imprecise,
                            raw=_raw(acl, action, proto, s, d, pr),
                            acl=acl, line=line, transit=True))
                        emitted_here = True
        if emitted_here:
            last_valid_by_acl[acl] = r
        else:
            notes.append(f"{label}: matched no address family (e.g. IPv4 source "
                         f"with IPv6 destination) — no ACE emitted.")

    # Fail-closed default handling, per context (see module docstring).
    entries: List[ACE] = []
    for acl in acl_order:
        lst = by_acl[acl]
        if _is_default_rule(last_valid_by_acl.get(acl)):
            notes.append(f"[{acl}] ends in an explicit catch-all/default rule — "
                         f"modeled as-is; no synthetic fail-closed marker added.")
        else:
            for anynet in (_ANY4, _ANY6):
                lst.append(ACE(
                    seq=len(lst) + 1, action="permit", proto="ip",
                    src=anynet, dst=anynet, imprecise=True,
                    raw=(f"[{acl}] fail-closed default marker — Umbrella CDFW's "
                         f"default action is configurable and not in this export; "
                         f"unmatched flows are INDETERMINATE, never a clean PASS"),
                    acl=acl, line=0, transit=True))
            notes.append(
                f"[{acl}] no explicit default/catch-all rule in export — appended "
                f"a fail-closed IMPRECISE marker so any flow not decided by an "
                f"explicit rule is segmentation-INDETERMINATE (never a false PASS, "
                f"never a silent leak). Provide the CDFW default action to make "
                f"this precise.")
        entries.extend(lst)

    if not entries and not notes:
        notes.append("no Umbrella CDFW rules found.")
    return entries, notes
