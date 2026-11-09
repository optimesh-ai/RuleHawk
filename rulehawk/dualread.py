"""The legacy-parser dual read (#42 design v2 section 2.2, v3 section 6.2,
v4 section 5), in shadow only: nothing here changes a verdict.

Side A is the grammar's final model (slice 5), passed in as data. Side B is
the existing dialect parser's output (`parse_junos`, `parse_panos`,
`parse_iptables`), mapped here into the same shape. This module imports no
grammar module (a test enforces it), so side B is not the fold read twice.

What is compared, per access list (a Junos filter, the PAN-OS security
rulebase, an iptables chain): the entries in order, grouped by the
statement that made them (a Junos term, a PAN-OS rule, an iptables `-A`
line, then the chain policy), each entry's action, protocol, source,
destination, ports, ICMP type and state flags. Any difference, a legacy
parse note, or a legacy parser that fails, is `reading-mismatch`.

What is not compared: a field side B does not expose has no second
reading and is listed under `single` (`reading-single`, v3 section 6.2):
Junos interface addresses and filter bindings, PAN-OS zones, application
and service. Slice 7's checker is what may re-derive them; until then the
file stays uncertified.

The dual read is an extra check. It is not counted as independence, and
no certificate rests on it alone (v4 section 5).
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

READING_MISMATCH = "reading-mismatch"
READING_SINGLE = "reading-single"

_ANY = "0.0.0.0/0"
_ACTIONS = {"accept": "permit", "discard": "deny", "allow": "permit",
            "deny": "deny", "ACCEPT": "permit", "DROP": "deny"}

Entry = Tuple[str, ...]
Lists = Dict[str, List[List[Entry]]]


def _entry(action: Optional[str], src: str, dst: str) -> Entry:
    # Side A reads no protocol, port, ICMP type or state: every entry is
    # `ip`, any port, no ICMP type, no state flag.
    return (str(action), "ip", _net(src), _net(dst), "*", "*", "-", "0", "0", "0")


def _net(text: str) -> str:
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return "?" + text


def _objs(model: dict) -> Dict[Tuple[str, ...], dict]:
    return {tuple(o["path"]): o for o in model["objects"]}


def _members(objs, path) -> List[str]:
    n = len(path)
    return [p[n] for p in objs if len(p) == n + 1 and p[:n] == path]


def _side_a_junos(model: dict) -> Tuple[Lists, List[str]]:
    objs = _objs(model)
    out: Lists = {}
    single = set()
    for path, o in objs.items():
        if path[:1] == ("interfaces",):
            if "address" in o["values"]:
                single.add("junos-interface-address")
            if "input" in o["values"]:
                single.add("junos-filter-binding")
        if len(path) == 3 and path[:2] == ("firewall", "family inet") \
                and path[2].startswith("filter "):
            groups = []
            for term in o["ordered"]:
                t = path + (term,)
                act = _ACTIONS.get(objs[t]["values"].get("then"))
                srcs = _members(objs, t + ("from", "source-address")) or [_ANY]
                dsts = _members(objs, t + ("from", "destination-address")) or [_ANY]
                groups.append(sorted(_entry(act, s, d) for s in srcs for d in dsts))
            out[path[2][len("filter "):]] = groups
    return out, sorted(single)


def _side_a_panos(model: dict) -> Tuple[Lists, List[str]]:
    objs = _objs(model)
    base = ("rulebase security",)
    groups = []
    for rule in objs.get(base, {"ordered": []})["ordered"]:
        v = objs[base + (rule,)]["values"]
        groups.append([_entry(_ACTIONS.get(v.get("action")),
                              _ANY if v.get("source") == "any" else v.get("source", ""),
                              _ANY if v.get("destination") == "any" else v.get("destination", ""))])
    single = ["panos-application", "panos-service", "panos-zones"] if groups else []
    return ({"security": groups} if groups else {}), single


def _side_a_iptables(model: dict) -> Tuple[Lists, List[str]]:
    objs = _objs(model)
    out: Lists = {}
    for path, o in objs.items():
        if len(path) != 2 or path[0] != "filter":
            continue
        groups = []
        for rule in o["ordered"]:
            toks = rule.split(" ")
            opt = dict(zip(toks[::2], toks[1::2]))
            groups.append([_entry(_ACTIONS.get(opt.get("-j")), opt.get("-s", _ANY),
                                  opt.get("-d", _ANY))])
        if "policy" in o["values"]:
            groups.append([_entry(_ACTIONS.get(o["values"]["policy"]), _ANY, _ANY)])
        if groups:
            out[path[1]] = groups
    return out, []


def _side_b(aces) -> Lists:
    out: Lists = {}
    last: Dict[str, int] = {}
    for a in aces:
        e = (a.action, a.proto, str(a.src), str(a.dst), str(a.src_port), str(a.dst_port),
             a.icmp_type or "-", str(int(a.stateful)), str(int(a.imprecise)),
             str(int(getattr(a, "state_limited", False))))
        groups = out.setdefault(a.acl, [])
        if groups and last.get(a.acl) == a.line:
            groups[-1].append(e)
        else:
            groups.append([e])
        last[a.acl] = a.line
    return {k: [sorted(g) for g in v] for k, v in out.items()}


def _legacy(dialect: str):
    """Side B's parser, looked up from its module when it runs."""
    if dialect == "junos":
        from .parse_junos import parse_junos as p
    elif dialect == "panos":
        from .parse_panos import parse_panos as p
    else:
        from .parse_iptables import parse_iptables as p
    return p


_SIDE_A = {"junos": _side_a_junos, "panos": _side_a_panos, "iptables": _side_a_iptables}


def dual_read(raw: bytes, model: dict) -> dict:
    """The dual-read entry for one file the grammar parses."""
    dialect = model.get("dialect")
    a, single = _SIDE_A[dialect](model)
    out = {"reason": None, "compared": sorted(a), "single": single, "mismatch": None}
    try:
        aces, notes = _legacy(dialect)(raw.decode("utf-8"))
        b = _side_b(aces)
    except Exception as e:  # side B fails: no second reading agrees
        out.update(reason=READING_MISMATCH,
                   mismatch=f"legacy parser failed: {type(e).__name__}")
        return out
    if notes:
        out.update(reason=READING_MISMATCH, mismatch=f"legacy parse note: {notes[0]}")
    elif a != b:
        out.update(reason=READING_MISMATCH, mismatch=_first_difference(a, b))
    elif single:
        out["reason"] = READING_SINGLE
    return out


def _first_difference(a: Lists, b: Lists) -> str:
    for acl in sorted(set(a) | set(b)):
        if acl not in b:
            return f"{acl}: only the grammar reads it"
        if acl not in a:
            return f"{acl}: only the legacy parser reads it"
        ga, gb = a[acl], b[acl]
        for i in range(max(len(ga), len(gb))):
            if i >= len(ga) or i >= len(gb) or ga[i] != gb[i]:
                return f"{acl}: entry group {i + 1} differs"
    return "differs"
