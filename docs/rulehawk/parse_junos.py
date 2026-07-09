"""Parse Juniper Junos stateless firewall filters into RuleHawk `ACE`s.

Why Junos is the next vendor (RH-3): the engine downstream of parsing
(`analyze.py`, `segcheck.py`, `model.ACE`) is built around ORDERED, first-match,
`permit`/`deny` rules over an (proto, src-net, dst-net, src-port, dst-port)
packet space — see `analyze._analyze_one_acl` (shadowing/intent-inversion needs
both permit AND deny in match order), `segcheck._search` (first-match,
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

from .model import ACE, ANY_PORTS, _PORTED, PortRange, _IPNet
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
# beyond it we widen every dimension to ANY (a superset) and mark the entry
# imprecise (+ a note) — never truncate to a subset of the values.
_MAX_EXPAND = 256


def detect(text: str) -> bool:
    """Heuristic: does `text` look like a Junos firewall-filter config?

    Requires the brace-form signature (`filter NAME {` ... `term` ... `then`) so
    a Cisco ACL — which has none of these keywords — is never misrouted here.
    """
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

    `except` EXCLUDES the prefix it follows: that prefix must never appear as
    matched space, so it is dropped and the remaining prefixes — the exclusion
    left un-subtracted — are a sound superset, marked imprecise. An unparseable
    value widens the whole dimension to ANY: skipping just that member would
    model a SUBSET of the term's true space (the parser-contract breaker)."""
    nets: List[_IPNet] = []
    imprecise = False
    widen = False
    prev_ok = False
    for v in vals:
        if v == "except":
            if prev_ok and nets:
                nets.pop()                    # the preceding prefix is excluded
            imprecise = True
            prev_ok = False
            notes.append(f"Junos 'except' address exclusion in {label} — excluded "
                         f"prefix removed from the match; remainder kept "
                         f"un-subtracted (marked imprecise — verify manually)")
            continue
        try:
            # ip_network() on a bare address yields the host route (/32 for v4,
            # /128 for v6) — never widen a bare v6 address to a /32.
            nets.append(ipaddress.ip_network(v, strict=False))
            prev_ok = True
        except ValueError:
            widen = True
            imprecise = True
            prev_ok = False
            notes.append(f"unparsed Junos address '{v}' in {label} "
                         f"(dimension widened to ANY, marked imprecise — verify manually)")
    if widen:
        nets = [_ANY_NET]
    return nets, imprecise


def _ports(vals: List[str], label: str, key: str,
           notes: List[str]) -> Tuple[List[PortRange], bool]:
    """Parse a Junos port set. Returns (ranges, imprecise).

    The whole token is tried as a named/numeric port FIRST — `ftp-data` is
    port 20, not a range — and only then split as lo-hi (each side may itself
    be a service name). An unparseable value widens the whole dimension to ANY:
    skipping just that member would model a SUBSET of the term's true space,
    and a narrowed deny can be falsely proven dead."""
    ranges: List[PortRange] = []
    widen = False
    for v in vals:
        p = _port_num(v)
        if p >= 0:
            ranges.append(PortRange(p, p))
            continue
        if "-" in v and not v.startswith("-"):
            lo, hi = v.split("-", 1)
            ln, hn = _port_num(lo), _port_num(hi)
            if ln >= 0 and hn >= 0:
                ranges.append(PortRange(min(ln, hn), max(ln, hn)))
                continue
        widen = True
        notes.append(f"unparsed Junos {key} '{v}' in {label} "
                     f"(dimension widened to ANY, marked imprecise — verify manually)")
    if widen:
        ranges = [ANY_PORTS]
    return ranges, widen


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
        elif key in ("tcp-established", "established"):
            # return-traffic only — like Cisco `established`: not a new flow.
            m.stateful = True
            notes.append(f"Junos '{key}' in {label} modeled as stateful "
                         f"(return-traffic only; never used to prove a rule dead)")
        elif key in ("tcp-flags", "tcp-initial"):
            # A generic flag match CAN match new-flow SYNs — modeling it as
            # stateful would hide the term from the segmentation witness search
            # (false PASS). It narrows an unmodeled dimension: over-approximate.
            m.imprecise = True
            notes.append(f"Junos '{key}' in {label} not modeled — flag restriction "
                         f"ignored (over-approximated, marked imprecise)")
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

    if (m.sports or m.dports) and any(p not in _PORTED for p in protos):
        # covers()/segcheck ignore ports on a non-port-carrying protocol
        # (including an omitted protocol -> "ip"), so those ACEs would claim an
        # exact all-ports space: widen the ports (superset) and flag imprecise.
        imprecise = True
        notes.append(f"Junos term {label}: port match on a non-port-carrying "
                     f"protocol — ports widened to ANY for those protocols "
                     f"(marked imprecise — verify manually)")

    if len(srcs) * len(dsts) * len(protos) * len(sports) * len(dports) > _MAX_EXPAND:
        # Truncating to the first value per dimension would model a SUBSET
        # (dropped members become invisible holes): widen everything instead.
        notes.append(f"Junos term {label} expands to >{_MAX_EXPAND} rules; widened "
                     f"to a single any/any rule (superset) and marked imprecise "
                     f"— verify manually")
        srcs, dsts, protos = [_ANY_NET], [_ANY_NET], ["ip"]
        sports, dports = [ANY_PORTS], [ANY_PORTS]
        imprecise = True

    for proto in protos:
        ported = proto in _PORTED
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
        if (body[i] == "inactive:" and i + 3 < n and body[i + 1] == "term"
                and body[i + 3] == "{"):
            # `inactive: term NAME { ... }` is deactivated — NOT enforced. Parsing
            # it would let a deactivated deny block the witness (false PASS).
            tname = body[i + 2]
            _, i = _read_block(body, i + 3)
            notes.append(f"Junos term {fname}/{tname} is inactive (deactivated) — "
                         f"not enforced; skipped")
        elif body[i] == "term" and i + 2 < n and body[i + 2] == "{":
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


def parse_junos(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse Junos firewall filters in `text`; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation`
    consume the result unchanged.
    """
    toks = _tokenize(text)
    term_lines = _term_line_map(text)
    entries: List[ACE] = []
    notes: List[str] = []
    i, n = 0, len(toks)
    while i < n:
        # A filter DEFINITION is `filter NAME {`. An *applied* filter
        # (`filter input NAME;` on an interface) is not followed by `{`, so the
        # guard below skips it. An `inactive:`-marked filter is deactivated —
        # none of its terms are enforced.
        if (toks[i] == "inactive:" and i + 3 < n and toks[i + 1] == "filter"
                and toks[i + 3] == "{"):
            fname = toks[i + 2]
            _, i = _read_block(toks, i + 3)
            notes.append(f"Junos filter {fname} is inactive (deactivated) — "
                         f"not enforced; skipped")
        elif toks[i] == "filter" and i + 2 < n and toks[i + 2] == "{":
            fname = toks[i + 1]
            fbody, i = _read_block(toks, i + 2)
            _parse_filter(fname, fbody, entries, notes, term_lines)
        else:
            i += 1

    if not entries and re.search(r"\bset\b.*\bfilter\b", text):
        notes.append("Junos 'set'-display format detected but not yet supported — "
                     "paste the curly-brace `show configuration` form to audit it.")
    return entries, notes
