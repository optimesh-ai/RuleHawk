"""The checker's own evaluation of each assertion (v2 section 1.3), from
its own reading of the raw bytes, never from the record's model.

Per-role rules, each the checker's own:
- Junos: traffic from a source CIDR enters at the unit whose subnet holds
  it (exactly one, else indeterminate); that unit's `input` filter, if
  any, decides it. No filter: the flow is permitted. Source and
  destination on one unit: the flow never crosses a filter. A filter's end
  is the cited implicit discard (`junos-implicit-discard`).
- PAN-OS: the security rulebase decides every flow (zones `any`). Its end
  is the default rules, which are pending: indeterminate.
- iptables: transit traffic crosses only the filter table's FORWARD
  chain. Its end is the chain policy if one is set, else indeterminate.

The search is exact over the address space: rectangles (source network,
destination network), first match, each entry taking its part out of what
remains. No rule in the grammar matches a protocol or a port, so the
asserted protocol and ports do not split the space.

Answers: `must_not_reach` gives `witness`, `no-witness` or
`indeterminate`; `must_reach` gives `all-permitted`, `hole` or
`indeterminate`.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Dict, List, Optional, Tuple

from .derive import derive
from .split import split_bytes

WITNESS, NO_WITNESS = "witness", "no-witness"
ALL_PERMITTED, HOLE = "all-permitted", "hole"
INDETERMINATE = "indeterminate"

Net = ipaddress.IPv4Network
Rect = Tuple[Net, Net]
_ANY = ipaddress.IPv4Network("0.0.0.0/0")


def _minus(a: Net, s: Net) -> List[Net]:
    """a without s."""
    if not a.overlaps(s):
        return [a]
    if a.subnet_of(s):
        return []
    return list(a.address_exclude(s))


def _cut(rect: Rect, s: Net, d: Net) -> Tuple[Optional[Rect], List[Rect]]:
    """The part of rect inside s x d, and the rest."""
    a, b = rect
    if not (a.overlaps(s) and b.overlaps(d)):
        return None, [rect]
    ia = a if a.subnet_of(s) else s
    ib = b if b.subnet_of(d) else d
    rest = [(x, b) for x in _minus(a, s)] + [(ia, y) for y in _minus(b, d)]
    return (ia, ib), rest


def _walk(entries, default: Optional[str], space: List[Rect]):
    """First match over `space`. Returns (permitted, denied, unknown): whether
    any part is permitted, any denied, any left to an uncited default."""
    permitted = denied = False
    remaining = list(space)
    for srcs, dsts, action in entries:
        if action not in ("permit", "deny"):
            return permitted, denied, True
        for s in srcs:
            for d in dsts:
                nxt = []
                for r in remaining:
                    hit, rest = _cut(r, s, d)
                    if hit is not None:
                        if action == "permit":
                            permitted = True
                        else:
                            denied = True
                    nxt += rest
                remaining = nxt
    unknown = False
    if remaining:
        if default == "permit":
            permitted = True
        elif default == "deny":
            denied = True
        else:
            unknown = True
    return permitted, denied, unknown


def _members(model, path) -> List[str]:
    n = len(path)
    return [p[n] for p in model if len(p) == n + 1 and p[:n] == path]


def _nets(texts: List[str]) -> List[Net]:
    return [ipaddress.IPv4Network(t) for t in texts] or [_ANY]


def _junos_filter(model, name: str):
    path = ("firewall", "family inet", "filter " + name)
    if path not in model:
        return None
    out = []
    for term in model[path][1]:
        t = path + (term,)
        then = model[t][0].get("then")
        act = {"accept": "permit", "discard": "deny"}.get(then, "unknown")
        out.append((_nets(_members(model, t + ("from", "source-address"))),
                    _nets(_members(model, t + ("from", "destination-address"))), act))
    return out


def _junos(model, src: List[Net], dst: List[Net]) -> List[Tuple[list, Optional[str], List[Rect]]]:
    """Per source CIDR: (entries, default, space), or raises LookupError when
    the source has no single ingress."""
    units = {}
    for p, (vals, _) in model.items():
        if len(p) == 4 and p[0] == "interfaces" and p[3] == "family inet" and "address" in vals:
            units[p] = ipaddress.IPv4Interface(vals["address"]).network
    plans = []
    for s in src:
        ins = [p for p, n in units.items() if s.subnet_of(n)]
        if len(ins) != 1:
            raise LookupError("no single ingress")
        unit = ins[0]
        local = [d for d in dst if d.subnet_of(units[unit])]
        if local:
            plans.append(([], "permit", [(s, d) for d in local]))
        far = [d for d in dst if d not in local]
        if not far:
            continue
        binding = model.get(unit + ("filter",), ({}, []))[0].get("input")
        if binding is None:
            plans.append(([], "permit", [(s, d) for d in far]))
            continue
        entries = _junos_filter(model, binding)
        if entries is None:
            raise LookupError("bound filter not defined")
        plans.append((entries, "deny", [(s, d) for d in far]))
    return plans


def _panos(model, src, dst):
    base = ("rulebase security",)
    entries = []
    for rule in model.get(base, ({}, []))[1]:
        v = model[base + (rule,)][0]
        if any(v.get(k) != "any" for k in ("from", "to", "application", "service")):
            raise LookupError("rule matches more than addresses")
        nets = [[_ANY] if v.get(k) == "any" else [ipaddress.IPv4Network(v[k])]
                for k in ("source", "destination")]
        entries.append((nets[0], nets[1], {"allow": "permit", "deny": "deny"}.get(
            v.get("action"), "unknown")))
    return [(entries, None, [(s, d) for s in src for d in dst])]


def _iptables(model, src, dst):
    chain = ("filter", "FORWARD")
    vals, ordered = model.get(chain, ({}, []))
    entries = []
    for rule in ordered:
        w = rule.split(" ")
        opts = dict(zip(w[0::2], w[1::2]))
        entries.append(([ipaddress.IPv4Network(opts["-s"])] if "-s" in opts else [_ANY],
                        [ipaddress.IPv4Network(opts["-d"])] if "-d" in opts else [_ANY],
                        {"ACCEPT": "permit", "DROP": "deny"}.get(opts.get("-j"), "unknown")))
    default = {"ACCEPT": "permit", "DROP": "deny"}.get(vals.get("policy"))
    return [(entries, default, [(s, d) for s in src for d in dst])]


_PLANS = {"junos": _junos, "panos": _panos, "iptables": _iptables}


def _one(dialect: str, model, assertion: str) -> str:
    try:
        a = json.loads(assertion)
        kind = a["kind"]
        src = [ipaddress.IPv4Network(c) for c in a["src_cidrs"]]
        dst = [ipaddress.IPv4Network(c) for c in a["dst_cidrs"]]
        if not src or not dst or kind not in ("must_not_reach", "must_reach"):
            return INDETERMINATE
        plans = _PLANS[dialect](model, src, dst)
    except (LookupError, ValueError, TypeError, KeyError):
        return INDETERMINATE
    permitted = denied = unknown = False
    for entries, default, space in plans:
        p, d, u = _walk(entries, default, space)
        permitted, denied, unknown = permitted or p, denied or d, unknown or u
    if kind == "must_not_reach":
        return WITNESS if permitted else INDETERMINATE if unknown else NO_WITNESS
    return HOLE if denied else INDETERMINATE if unknown else ALL_PERMITTED


def evaluate(dialect: str, raw: bytes, assertions: List[str]) -> List[str]:
    """The checker's answer for each assertion, from the raw bytes."""
    lines = split_bytes(raw)
    model = derive(dialect, lines) if lines is not None else None
    if model is None:
        return [INDETERMINATE for _ in assertions]
    return [_one(dialect, model, a) for a in assertions]
