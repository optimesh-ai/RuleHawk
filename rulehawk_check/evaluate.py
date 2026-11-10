"""The checker's own evaluation of each assertion (v2 section 1.3), from
its own reading of the raw bytes, never from the record's model.

Per-role rules, each the checker's own:
- Junos: traffic from a source CIDR enters at the unit whose subnet holds
  it (exactly one, else indeterminate); that unit's `input` filter, if
  any, decides it. No filter: the flow is permitted. Source and
  destination on one unit: the flow never crosses a filter; a destination
  that holds more than the source's segment (a supernet of it) is
  indeterminate (review of #58, H2). Nothing says the source enters only
  there (H1): for `must_not_reach`, every other unit's `input` filter is
  walked for the source too, and a unit with no filter leaves the flow
  indeterminate. A filter's end is the cited implicit discard
  (`junos-implicit-discard`).
- PAN-OS: the security rulebase decides every flow (zones `any`). Its end
  is the default rules, which are pending: indeterminate. No cited row
  says what `any` matches (`panos-any-meaning`, pending), so a rule that
  uses `any` in any field is an unknown entry, and every PAN-OS answer is
  indeterminate while that row is pending (review of #60-#62 r2, F60-5).
- iptables: transit traffic crosses only the filter table's FORWARD
  chain. Its end is the chain policy if one is set, else indeterminate.
  `-A` appends after whatever the chain already holds, and the rule set
  before the script is not cited (`iptables-script-scope`, pending): an
  unknown entry heads the chain, so every iptables answer is indeterminate
  while that row is pending (review of #60-#62, F60-1, option b).

The search is exact over the address space: rectangles (source network,
destination network), first match, each entry taking its part out of what
remains. No rule in the grammar matches a protocol or a port, so the
asserted protocol and ports do not split the space.

Answers: `must_not_reach` gives `witness`, `no-witness` or
`indeterminate`; `must_reach` gives `hole` or `indeterminate`. No cited
row says the device forwards what its filters permit, so `all-permitted`
is never given (review of #58, H3).

The checker takes the policy itself and writes each assertion, with its
zones resolved, on its own (review of #52-#57, G11).
"""
from __future__ import annotations

import ipaddress
import json
from typing import Dict, List, Optional, Tuple

from .derive import derive
from .split import split_bytes
from .verify import _assertions

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


def _junos(model, src: List[Net], dst: List[Net],
           kind: str) -> List[Tuple[list, Optional[str], List[Rect]]]:
    """Per source CIDR: (entries, default, space), or raises LookupError when
    the source has no single ingress or a destination lies over its
    segment."""
    units = {}
    for p, (vals, _) in model.items():
        if len(p) == 4 and p[0] == "interfaces" and p[3] == "family inet" and "address" in vals:
            units[p] = ipaddress.IPv4Interface(vals["address"]).network
    every = [p for p in model if len(p) == 3 and p[0] == "interfaces"
             and p[2].startswith("unit ")]
    plans = []
    for s in src:
        ins = [p for p, n in units.items() if s.subnet_of(n)]
        if len(ins) != 1:
            raise LookupError("no single ingress")
        unit = ins[0]
        seg = units[unit]
        if any(d.overlaps(seg) and not d.subnet_of(seg) for d in dst):
            raise LookupError("a destination over the source's segment")
        local = [d for d in dst if d.subnet_of(seg)]
        if local:
            plans.append(([], "permit", [(s, d) for d in local]))
        far = [d for d in dst if d not in local]
        if not far:
            continue
        ingress = [unit]
        if kind == "must_not_reach":
            ingress += [u + ("family inet",) for u in every if u + ("family inet",) != unit]
        for at in ingress:
            binding = model.get(at + ("filter",), ({}, []))[0].get("input")
            if binding is None:
                if at == unit:
                    plans.append(([], "permit", [(s, d) for d in far]))
                else:
                    plans.append(([], None, [(s, d) for d in far]))
                continue
            entries = _junos_filter(model, binding)
            if entries is None:
                raise LookupError("bound filter not defined")
            plans.append((entries, "deny", [(s, d) for d in far]))
    return plans


def _panos(model, src, dst, kind):
    base = ("rulebase security",)
    entries = []
    for rule in model.get(base, ({}, []))[1]:
        v = model[base + (rule,)][0]
        if any(v.get(k) != "any" for k in ("from", "to", "application", "service")):
            raise LookupError("rule matches more than addresses")
        nets = [[_ANY] if v.get(k) == "any" else [ipaddress.IPv4Network(v[k])]
                for k in ("source", "destination")]
        act = {"allow": "permit", "deny": "deny"}.get(v.get("action"), "unknown")
        if any(v.get(k) == "any" for k in ("from", "to", "source", "destination",
                                           "application", "service")):
            act = "unknown"                      # panos-any-meaning is pending
        entries.append((nets[0], nets[1], act))
    return [(entries, None, [(s, d) for s in src for d in dst])]


def _iptables(model, src, dst, kind):
    chain = ("filter", "FORWARD")
    vals, ordered = model.get(chain, ({}, []))
    # The rules loaded before the script (iptables-script-scope, pending).
    entries = [([_ANY], [_ANY], "unknown")]
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
        plans = _PLANS[dialect](model, src, dst, kind)
    except (LookupError, ValueError, TypeError, KeyError):
        return INDETERMINATE
    permitted = denied = unknown = False
    for entries, default, space in plans:
        p, d, u = _walk(entries, default, space)
        permitted, denied, unknown = permitted or p, denied or d, unknown or u
    if kind == "must_not_reach":
        return WITNESS if permitted else INDETERMINATE if unknown else NO_WITNESS
    # H3: no cited forwarding row, so a flow every filter permits is still
    # indeterminate; ALL_PERMITTED is kept as a word for when one is cited.
    return HOLE if denied else INDETERMINATE


def evaluate(dialect: str, raw: bytes, policy) -> List[str]:
    """The checker's answer for each assertion of the policy, from the raw
    bytes."""
    assertions = _assertions(policy)
    lines = split_bytes(raw)
    model = derive(dialect, lines) if lines is not None else None
    if model is None:
        return [INDETERMINATE for _ in assertions]
    return [_one(dialect, model, a) for a in assertions]
