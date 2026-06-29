"""Parse Juniper Junos stateless firewall filters into RuleHawk `ACE`s.

Why Junos is the next vendor (RH-3): the engine downstream of parsing
(`analyze.py`, `segcheck.py`, `model.ACE`) is built around ORDERED, first-match,
`permit`/`deny` rules over an (proto, src-net, dst-net, src-port, dst-port)
packet space — see `analyze._analyze_one_acl` (shadowing/intent-inversion needs
both permit AND deny in match order), `segcheck._eval_acl` (first-match,
honoring earlier denies), and `model.ACE`. Junos firewall filters map onto this
*exactly*: a `filter` is an ordered list of `term`s, each `term` has a `from`
(the match) and a `then` (accept -> permit, discard/reject -> deny), evaluated
first-match. That is the same semantics as a Cisco ACL, just a different syntax —
so the whole existing analysis (the product's real IP) is reused unchanged: this
module only adds a new *frontend* that emits the same `(List[ACE], notes)` IR.

By contrast AWS Security Groups are stateful, allow-only and ORDER-INDEPENDENT
(no deny, no sequence) — the shadowing/intent-inversion engine produces nothing
for them, so they don't fit `model.ACE` without a different analyzer. Junos is
also the closest enterprise adjacency to the existing Cisco IOS/ASA userbase
(Juniper is the #2 enterprise/SP networking vendor; same buyer, same PCI/zone
segmentation-audit need), which is why it unlocks the most self-serve users next.

Scope (minimal but correct): the curly-brace `show configuration` form of
`firewall { family <inet|inet6> { filter NAME { term T { from {...} then ...; }}}}`.
Modeled `from` matches: source-address, destination-address, protocol/next-header,
source-port, destination-port (single value, [ list ], lo-hi range, named service).
Multi-value matches are expanded to the exact union of ACEs (sound). Everything
not modeled — `application`, `tcp-flags`, prefix-lists, `address`/`port`
(direction-agnostic), `except` exclusions, icmp-type, the `set`-display form,
unknown `then` actions — is SURFACED as a parse note, never silently dropped
(the engine's discipline: an unmodeled line must never become an invisible hole).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .model import ACE, ANY_PORTS, PortRange, _IPNet
from .parse import _port_num  # reuse the Cisco/IANA service-name -> port map

_ANY_NET: _IPNet = ipaddress.ip_network("0.0.0.0/0")

# Junos `then` terminating actions -> RuleHawk action. accept => permit;
# discard (silent drop) and reject (drop + ICMP unreachable) both => deny.
_TERMINATING = {"accept": "permit", "discard": "deny", "reject": "deny"}

# `then` modifiers that don't decide the packet's fate — safe to ignore.
_THEN_MODIFIERS = {
    "count", "log", "syslog", "policer", "forwarding-class", "loss-priority",
    "dscp", "sample", "port-mirror", "three-color-policer", "service-accounting",
    "routing-instance", "ipsec-sa",
}

# Common IP protocol numbers, so `protocol 6` reads the same as `protocol tcp`.
_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6",
              "47": "gre", "50": "esp", "51": "ah", "89": "ospf"}

# Cap the cartesian expansion of one term so a pathological filter can't blow up;
# beyond it we model the first value per dimension and mark the entry imprecise
# (+ a note), never silently dropping the rest.
_MAX_EXPAND = 256


def detect(text: str) -> bool:
    """Heuristic: does `text` look like a Junos firewall-filter config?

    Accepts the brace-form (`filter NAME { ... term ... then ...}`) and the
    set-display form (`set firewall family inet filter NAME term NAME ...`).
    A Cisco ACL has none of these markers, so it is never misrouted here.
    """
    if re.search(r"^set\s+firewall\s+family\s+\S+\s+filter\s+\S+\s+term\s+",
                 text, re.MULTILINE):
        return True
    return bool(
        re.search(r"\bfilter\s+\S+\s*\{", text)
        and re.search(r"\bterm\b", text)
        and re.search(r"\bthen\b", text)
    )


# --- tokenizer / block readers --------------------------------------------

def _tokenize(text: str) -> List[str]:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)   # /* block */ comments
    text = re.sub(r"#.*", " ", text)                     # # line comments
    for ch in "{};[]":
        text = text.replace(ch, f" {ch} ")
    return text.split()


def _read_block(toks: List[str], i: int) -> Tuple[List[str], int]:
    """`toks[i]` is `{`. Return (tokens strictly inside, index after the `}`)."""
    depth, j = 0, i
    while j < len(toks):
        if toks[j] == "{":
            depth += 1
        elif toks[j] == "}":
            depth -= 1
            if depth == 0:
                return toks[i + 1:j], j + 1
        j += 1
    return toks[i + 1:], len(toks)            # unbalanced — take the rest


def _split_semicolons(toks: List[str]) -> List[List[str]]:
    out: List[List[str]] = []
    cur: List[str] = []
    for t in toks:
        if t == ";":
            out.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out


def _read_conditions(toks: List[str]) -> List[Tuple[str, List[str]]]:
    """Parse a `from`/`then`-style body into (key, values) pairs.

    Handles the three Junos value forms: `key v;`, `key [ v1 v2 ];`,
    `key { v1; v2; }`, and a bare `key;` (values == [])."""
    out: List[Tuple[str, List[str]]] = []
    i, n = 0, len(toks)
    while i < n:
        key = toks[i]
        if key == ";":
            i += 1
            continue
        i += 1
        vals: List[str] = []
        if i < n and toks[i] == "{":
            inner, i = _read_block(toks, i)
            vals = [t for t in inner if t != ";"]
        elif i < n and toks[i] == "[":
            j = i + 1
            while j < n and toks[j] != "]":
                vals.append(toks[j])
                j += 1
            i = j + 1
        else:
            while i < n and toks[i] != ";":
                vals.append(toks[i])
                i += 1
            i += 1                              # skip the `;`
        out.append((key, vals))
    return out


# --- value parsers ---------------------------------------------------------

def _proto(v: str) -> str:
    return _PROTO_NUM.get(v, v.lower())


def _addrs(vals: List[str], label: str, notes: List[str]) -> Tuple[List[_IPNet], bool]:
    """Parse a Junos address set. Returns (nets, imprecise).

    `except` (set exclusion, e.g. `10/8 except 10.1/16`) can't be a single
    rectangle, so we keep the broader prefix and mark the entry imprecise (it may
    over-approximate but never under-approximate) — surfaced via a note."""
    nets: List[_IPNet] = []
    imprecise = False
    for v in vals:
        if v == "except":
            imprecise = True
            notes.append(f"unmodeled Junos 'except' address exclusion in {label} "
                         f"(kept the broader prefix, marked imprecise — verify manually)")
            continue
        try:
            nets.append(ipaddress.ip_network(v if "/" in v else f"{v}/32", strict=False))
        except ValueError:
            # Can't parse this address. Skipping it alone would let an all-bad
            # set fall back to ANY and over-approximate, which could falsely
            # prove a later deny dead. Mark imprecise so this ACE is never used
            # to prove another rule dead (trust > coverage).
            imprecise = True
            notes.append(f"unparsed Junos address '{v}' in {label} "
                         f"(marked imprecise — verify manually)")
    return nets, imprecise


def _ports(vals: List[str], label: str, key: str,
           notes: List[str]) -> Tuple[List[PortRange], bool]:
    """Parse a Junos port set. Returns (ranges, imprecise).

    A value we cannot parse is skipped with a note AND flips imprecise: an
    all-unparsed port set otherwise falls back to ANY (in _parse_term) and
    could falsely prove a later deny rule dead — the trust-breaking case."""
    ranges: List[PortRange] = []
    imprecise = False
    for v in vals:
        if "-" in v and not v.startswith("-"):
            lo, hi = v.split("-", 1)
            ln, hn = _port_num(lo), _port_num(hi)
            if ln < 0 or hn < 0:
                imprecise = True
                notes.append(f"unparsed Junos {key} '{v}' in {label} "
                             f"(marked imprecise — verify manually)")
                continue
            ranges.append(PortRange(min(ln, hn), max(ln, hn)))
        else:
            p = _port_num(v)
            if p < 0:
                imprecise = True
                notes.append(f"unparsed Junos {key} '{v}' in {label} "
                             f"(marked imprecise — verify manually)")
                continue
            ranges.append(PortRange(p, p))
    return ranges, imprecise


@dataclass
class _Match:
    srcs: List[_IPNet] = field(default_factory=list)
    dsts: List[_IPNet] = field(default_factory=list)
    protos: List[str] = field(default_factory=list)
    sports: List[PortRange] = field(default_factory=list)
    dports: List[PortRange] = field(default_factory=list)
    stateful: bool = False
    imprecise: bool = False


def _parse_from(from_toks: List[str], label: str, notes: List[str]) -> _Match:
    m = _Match()
    for key, vals in _read_conditions(from_toks):
        if key in ("source-address",):
            nets, imp = _addrs(vals, label, notes)
            m.srcs += nets
            m.imprecise |= imp
        elif key in ("destination-address",):
            nets, imp = _addrs(vals, label, notes)
            m.dsts += nets
            m.imprecise |= imp
        elif key in ("protocol", "next-header"):
            m.protos += [_proto(v) for v in vals]
        elif key == "source-port":
            pr, imp = _ports(vals, label, key, notes)
            m.sports += pr
            m.imprecise |= imp
        elif key == "destination-port":
            pr, imp = _ports(vals, label, key, notes)
            m.dports += pr
            m.imprecise |= imp
        elif key in ("tcp-established", "tcp-flags", "tcp-initial"):
            # return-traffic / flag match — like Cisco `established`: not a new flow.
            m.stateful = True
            notes.append(f"Junos '{key}' in {label} modeled as stateful "
                         f"(return-traffic only; never used to prove a rule dead)")
        elif key in ("address", "port", "icmp-type", "icmp-code"):
            # direction-agnostic / typed matches we can't place in the rectangle:
            # over-approximate (mark imprecise) so it's never used to prove deadness.
            m.imprecise = True
            notes.append(f"unmodeled Junos match '{key}' in {label} "
                         f"(treated conservatively/imprecise — verify manually)")
        else:
            m.imprecise = True
            notes.append(f"unmodeled Junos match '{key}' in {label} "
                         f"(rule kept but marked imprecise — verify manually)")
    return m


def _parse_then(then_toks: List[str], label: str,
                notes: List[str]) -> Tuple[Optional[str], bool]:
    """Return (action or None, fallthrough). First terminating action wins."""
    action: Optional[str] = None
    fallthrough = False
    for st in _split_semicolons(then_toks):
        if not st:
            continue
        head = st[0]
        if head in _TERMINATING:
            if action is None:
                action = _TERMINATING[head]
        elif head == "next":                 # `then next term;` — fall through
            fallthrough = True
        elif head in _THEN_MODIFIERS:
            continue
        else:
            notes.append(f"unmodeled Junos then-action '{head}' in {label}")
    return action, fallthrough


def _raw(tname: str, action: str, proto: str, s: _IPNet, d: _IPNet,
         sp: PortRange, dp: PortRange) -> str:
    parts = [f"term {tname}:", action, proto, str(s), "->", str(d)]
    if not sp.is_any():
        parts.append(f"sport {sp}")
    if not dp.is_any():
        parts.append(f"dport {dp}")
    return " ".join(parts)


def _parse_term(fname: str, tname: str, tbody: List[str], seq: int,
                entries: List[ACE], notes: List[str], line: int = 0) -> int:
    label = f"{fname}/{tname}"
    from_toks: List[str] = []
    then_toks: List[str] = []
    i, n = 0, len(tbody)
    while i < n:
        t = tbody[i]
        if t == "from" and i + 1 < n and tbody[i + 1] == "{":
            blk, i = _read_block(tbody, i + 1)
            from_toks += blk
        elif t == "then":
            if i + 1 < n and tbody[i + 1] == "{":
                blk, i = _read_block(tbody, i + 1)
                then_toks += blk
            else:                                    # inline: `then accept;`
                j = i + 1
                while j < n and tbody[j] != ";":
                    j += 1
                then_toks += tbody[i + 1:j]
                i = j + 1
        else:
            i += 1

    action, fallthrough = _parse_then(then_toks, label, notes)
    if action is None:
        if fallthrough:
            notes.append(f"Junos term {label} only falls through (`then next term`) "
                         f"— not modeled as a decision (match order may shift)")
        else:
            notes.append(f"Junos term {label} has no terminating action "
                         f"(accept/discard/reject) — skipped")
        return seq

    m = _parse_from(from_toks, label, notes)
    srcs = m.srcs or [_ANY_NET]
    dsts = m.dsts or [_ANY_NET]
    protos = m.protos or ["ip"]
    sports = m.sports or [ANY_PORTS]
    dports = m.dports or [ANY_PORTS]
    imprecise = m.imprecise

    if len(srcs) * len(dsts) * len(protos) * len(sports) * len(dports) > _MAX_EXPAND:
        notes.append(f"Junos term {label} expands to >{_MAX_EXPAND} rules; modeled "
                     f"the first value per match and marked imprecise — verify manually")
        srcs, dsts, protos = srcs[:1], dsts[:1], protos[:1]
        sports, dports = sports[:1], dports[:1]
        imprecise = True

    if (any(p not in ("tcp", "udp") for p in protos)
            and (m.sports or m.dports)):
        notes.append(f"Junos term {label}: port match on a non-tcp/udp protocol — "
                     f"ports ignored for those protocols (verify manually)")

    for proto in protos:
        ported = proto in ("tcp", "udp")
        for s in srcs:
            for d in dsts:
                for sp in (sports if ported else [ANY_PORTS]):
                    for dp in (dports if ported else [ANY_PORTS]):
                        seq += 1
                        entries.append(ACE(
                            seq=seq, action=action, proto=proto, src=s, dst=d,
                            src_port=sp, dst_port=dp, icmp_type=None,
                            stateful=m.stateful, imprecise=imprecise,
                            raw=_raw(tname, action, proto, s, d, sp, dp),
                            acl=fname, line=line))
    return seq


def _parse_filter(fname: str, body: List[str], entries: List[ACE],
                  notes: List[str], term_lines: "dict") -> None:
    seq = 0
    i, n = 0, len(body)
    while i < n:
        if body[i] == "term" and i + 2 < n and body[i + 2] == "{":
            tname = body[i + 1]
            tbody, i = _read_block(body, i + 2)
            seq = _parse_term(fname, tname, tbody, seq, entries, notes,
                              term_lines.get((fname, tname), 0))
        else:
            i += 1


def _term_line_map(text: str) -> "dict":
    """Best-effort map (filter, term) -> 1-based source line, by a light line scan
    of the brace-form config (the tokenizer flattens line structure, so the CI
    gate's diff annotations recover the term's line from here). Term names are
    unique within a filter, so keying by (filter, term) is unambiguous."""
    out: dict = {}
    cur_filter: Optional[str] = None
    for i, ln in enumerate(text.splitlines(), 1):
        mf = re.search(r"\bfilter\s+(\S+?)\s*\{", ln)
        if mf:
            cur_filter = mf.group(1)
        mt = re.search(r"\bterm\s+(\S+?)\s*\{", ln)
        if mt and cur_filter is not None:
            out.setdefault((cur_filter, mt.group(1)), i)
    return out


# --- set-display format parser -------------------------------------------
# Each line: `set firewall family <inet|inet6> filter <fname> term <tname>
#              from <key> <val...>` or `... then <action>`.
# We collect all from/then lines per (fname, tname) — preserving the
# declaration order of terms — then re-use the brace-form per-term machinery
# (_parse_from / _parse_then / _parse_term) unchanged. The set lines arrive
# one directive at a time: multi-value address/port lists are written as
# repeated lines (`from source-address 10/8` then `from source-address 10.1/16`)
# so we accumulate values per key before handing them to _parse_from, which
# already understands multi-value lists.

# Pattern:
#   set firewall family <fam> filter <fname> term <tname>
#         from <key> [<val>...]
#     or  then <action-or-modifier> [<val>...]
_SET_LINE_RE = re.compile(
    r"^set\s+firewall\s+family\s+\S+\s+filter\s+(\S+)\s+term\s+(\S+)\s+"
    r"(from|then)\s+(.*)",
    re.IGNORECASE,
)


def _parse_junos_set(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse Junos set-display format into (entries, notes).

    Iterates the set lines in source order; terms are emitted in first-seen
    order within each filter, preserving first-match semantics.
    """
    # (fname, tname) -> {"from": {key: [vals...]}, "then": [tokens...],
    #                    "line": <first-seen 1-based line>}
    # We use a list to track insertion order (filter/term declaration order).
    term_order: List[Tuple[str, str]] = []
    term_data: dict = {}

    entries: List[ACE] = []
    notes: List[str] = []

    for lineno, raw in enumerate(text.splitlines(), 1):
        m = _SET_LINE_RE.match(raw.strip())
        if not m:
            continue
        fname, tname, clause, rest = (m.group(1), m.group(2),
                                      m.group(3).lower(), m.group(4).strip())
        key = (fname, tname)
        if key not in term_data:
            term_order.append(key)
            term_data[key] = {"from": {}, "then": [], "line": lineno}

        rest_toks = rest.split()
        if clause == "from":
            if not rest_toks:
                continue
            fkey = rest_toks[0]
            fvals = rest_toks[1:]
            td_from = term_data[key]["from"]
            if fkey not in td_from:
                td_from[fkey] = []
            td_from[fkey].extend(fvals)
        else:                               # clause == "then"
            # Accumulate then-tokens; separate statements end with implicit ";"
            # which the brace-form parser marks with ";" tokens. We insert a
            # synthetic ";" between successive then-clauses so _parse_then's
            # _split_semicolons works correctly.
            if term_data[key]["then"]:
                term_data[key]["then"].append(";")
            term_data[key]["then"].extend(rest_toks)

    # Reconstruct synthetic token streams for each term and call the existing
    # per-term parser. We rebuild from_toks so that multi-value keys (e.g.
    # multiple source-address lines) become `key { v1 ; v2 ; }` blocks that
    # _read_conditions already handles.
    seq_per_filter: dict = {}   # fname -> running seq counter
    for fname, tname in term_order:
        td = term_data[(fname, tname)]
        seq = seq_per_filter.get(fname, 0)

        # Build from_toks: for each key, emit `key { val1 ; val2 ; }` when
        # there are multiple values (the brace-block form that _read_conditions
        # understands), or `key val ;` for a single value.
        from_toks: List[str] = []
        for fkey, fvals in td["from"].items():
            if len(fvals) > 1:
                block: List[str] = [fkey, "{"]
                for v in fvals:
                    block += [v, ";"]
                block.append("}")
                from_toks += block
            else:
                from_toks += [fkey] + fvals + [";"]

        then_toks = td["then"]
        # Build a synthetic tbody that _parse_term can consume:
        # `from { <from_toks> } then { <then_toks> }`
        tbody: List[str] = []
        if from_toks:
            tbody += ["from", "{"] + from_toks + ["}"]
        if then_toks:
            tbody += ["then", "{"] + then_toks + ["}"]

        seq = _parse_term(fname, tname, tbody, seq, entries, notes,
                          td["line"])
        seq_per_filter[fname] = seq

    return entries, notes


def parse_junos(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse Junos firewall filters in `text`; return (entries, notes).

    Auto-detects the format: the brace-form (`show configuration`) is parsed
    by the block-walking tokenizer; the set-display form (`set firewall …`)
    is parsed by the line-oriented `_parse_junos_set` helper. Both emit the
    same `(List[ACE], notes)` IR; the rest of the engine is unchanged.

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation`
    consume the result unchanged.
    """
    # set-display form: every firewall rule is a `set firewall ...` line.
    if re.search(r"^set\s+firewall\s+family\s+\S+\s+filter\s+\S+\s+term\s+",
                 text, re.MULTILINE):
        return _parse_junos_set(text)

    toks = _tokenize(text)
    term_lines = _term_line_map(text)
    entries: List[ACE] = []
    notes: List[str] = []
    i, n = 0, len(toks)
    while i < n:
        # A filter DEFINITION is `filter NAME {`. An *applied* filter
        # (`filter input NAME;` on an interface) is not followed by `{`, so the
        # guard below skips it.
        if toks[i] == "filter" and i + 2 < n and toks[i + 2] == "{":
            fname = toks[i + 1]
            fbody, i = _read_block(toks, i + 2)
            _parse_filter(fname, fbody, entries, notes, term_lines)
        else:
            i += 1

    return entries, notes
