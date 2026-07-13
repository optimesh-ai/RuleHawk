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
(direction-agnostic), icmp-type, the `set`-display form, unknown `then` actions —
is SURFACED as a parse note, never silently dropped (the engine's discipline: an
unmodeled line must never become an invisible hole). An `except` address
exclusion is removed from the match space (the remaining prefixes — the
exclusion left un-subtracted — are a sound superset, marked imprecise), and an
`inactive:`-marked term or filter is NOT enforced on the device, so it is
skipped entirely (with a note) rather than modeled as live.

PARSER CONTRACT (model.py): every emitted exact (imprecise=False) ACE's space
must be EXACT, and the union of (exact ACEs ∪ imprecise marker space) must be a
SUPERSET of the term's true match space — a value we cannot model exactly must
widen its dimension (superset) or be covered by an opaque imprecise ACE, never
narrow it (subset = invisible hole = false PASS). Partial precision below: a
term mixing resolved address values with unresolvable named references emits
EXACT ACEs for the resolved members (they can prove a CRITICAL) plus ONE opaque
any/any imprecise ACE covering the unresolved remainder (it keeps the remainder
INDETERMINATE — never PASS, never a false CRITICAL). When another imprecision
source blocks the partial path, the unresolved dimension is widened to ANY
instead — the same soundness, less precision.

`apply-groups` (configuration-group inheritance) injects terms we cannot see:
inside a filter body it gets a note AND a leading opaque ACE (permit ip any->any,
imprecise=True) so segmentation evaluation returns INDETERMINATE instead of
falling to the implicit default deny — a missing inherited permit term must
never become a false segmentation PASS. Outside a filter body (config/firewall/
family level) it is surfaced as a note that the audit may be incomplete.

Address family: the `family <inet|inet6> {` context wrapping each filter is
tracked, so every "matches everything" fallback (a term with no src/dst, the
unresolved-address opaque remainder, the apply-groups opaque ACE) uses the
family's own any-net — `::/0` for inet6, `0.0.0.0/0` for inet. A v4 fallback
in an inet6 filter can never match a v6 witness (mixed IP versions never
intersect), which made real inet6 permits invisible to segcheck and silently
false-PASSed v6 segmentation assertions — the exact trust-breaking case. When
one side of a term is given, the missing side falls back to that side's IP
version, keeping every emitted ACE internally version-consistent. A filter
pasted without its enclosing family block is inferred inet6 if it contains any
IPv6 literal (surfaced as a note); pure-v4 behavior is unchanged.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .model import ACE, ANY_PORTS, _PORTED, PortRange, _IPNet
from .parse import _port_num  # reuse the Cisco/IANA service-name -> port map

_ANY_NET: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6_NET: _IPNet = ipaddress.ip_network("::/0")


def _fam_any_net(family: Optional[str]) -> _IPNet:
    """The 'matches everything' network for a filter's address family."""
    return _ANY6_NET if family == "inet6" else _ANY_NET


def _is_v6_literal(tok: str) -> bool:
    """True iff `tok` parses as an IPv6 address/network. Used to infer family
    inet6 for a filter pasted without its enclosing `family` block."""
    if ":" not in tok:
        return False
    try:
        return ipaddress.ip_network(tok, strict=False).version == 6
    except ValueError:
        return False

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


def _addrs(vals: List[str], label: str,
           notes: List[str]) -> Tuple[List[_IPNet], bool, bool, bool]:
    """Parse a Junos address set.
    Returns (nets, imprecise, has_unresolved, has_except).

    *imprecise* is True when any value introduces an approximation — either an
    ``except`` exclusion or an unresolvable named reference.

    *has_unresolved* is True ONLY when at least one value was an unresolvable
    named reference (address-book entry, raised ``ValueError``).  The caller
    uses this flag to apply partial precision: emit exact ACEs for the resolved
    CIDR subset plus one opaque ACE for the unresolved remainder — or, when
    another imprecision source blocks that path, widen the whole dimension to
    ANY (superset), never keep the resolved subset alone (subset = false PASS).

    *has_except* is True when an ``except`` exclusion was seen.  The exclusion
    EXCLUDES the prefix it follows: that prefix must never appear as matched
    space, so it is dropped and the remaining prefixes — the exclusion left
    un-subtracted — are a sound SUPERSET, marked imprecise.  Because those nets
    over-approximate the true match, the caller must not emit them as "precise"
    ACEs: ``has_except`` blocks the partial-precision path."""
    nets: List[_IPNet] = []
    imprecise = False
    has_unresolved = False
    has_except = False
    prev_ok = False
    for v in vals:
        if v == "except":
            if prev_ok and nets:
                nets.pop()                    # the preceding prefix is excluded
            imprecise = True
            has_except = True
            prev_ok = False
            notes.append(f"Junos 'except' address exclusion in {label} — excluded "
                         f"prefix removed from the match; remainder kept "
                         f"un-subtracted (marked imprecise — verify manually)")
            continue
        try:
            # ip_network() on a bare address yields the host route (/32 for v4,
            # /128 for v6) — never widen a bare v6 address to a /32 (a huge
            # over-approximation that could mint a false CRITICAL).
            nets.append(ipaddress.ip_network(v, strict=False))
            prev_ok = True
        except ValueError:
            # Can't parse this address — it is a named address-book reference
            # that isn't defined in the config snippet we received.  Skipping it
            # alone would model a SUBSET of the term's true space (the parser-
            # contract breaker).  Mark imprecise so this term can never prove
            # another rule dead, and set has_unresolved so the caller applies
            # the partial-precision pattern (or widens the dimension to ANY).
            imprecise = True
            has_unresolved = True
            prev_ok = False
            notes.append(f"unparsed Junos address '{v}' in {label} "
                         f"(marked imprecise — verify manually)")
    return nets, imprecise, has_unresolved, has_except


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
    # Partial-precision tracking — used by _parse_term to apply the same
    # "resolved subset exact + opaque remainder" pattern as parse.py's
    # _resolve_nets_partial / _resolve_svcs_partial.
    has_unresolved_src: bool = False   # ≥1 src address was an unresolved named ref
    has_unresolved_dst: bool = False   # ≥1 dst address was an unresolved named ref
    other_imprecise: bool = False      # imprecision from any source EXCEPT unresolved
                                       # named addresses (e.g. except-clauses, port
                                       # parse failures, tcp-flags, unmodeled match
                                       # keys).  When True the resolved-address subset
                                       # is NOT exactly bounded, so partial-precision
                                       # emission is blocked.


def _parse_from(from_toks: List[str], label: str, notes: List[str]) -> _Match:
    m = _Match()
    for key, vals in _read_conditions(from_toks):
        if key in ("source-address",):
            nets, imp, has_unres, has_exc = _addrs(vals, label, notes)
            m.srcs += nets
            m.imprecise |= imp
            m.has_unresolved_src |= has_unres
            # An except-clause over-approximates the remaining nets (exclusion
            # left un-subtracted), so partial-precision emission is blocked —
            # a "precise" ACE would over-claim.
            m.other_imprecise |= has_exc
        elif key in ("destination-address",):
            nets, imp, has_unres, has_exc = _addrs(vals, label, notes)
            m.dsts += nets
            m.imprecise |= imp
            m.has_unresolved_dst |= has_unres
            m.other_imprecise |= has_exc
        elif key in ("protocol", "next-header"):
            m.protos += [_proto(v) for v in vals]
        elif key == "source-port":
            pr, imp = _ports(vals, label, key, notes)
            m.sports += pr
            m.imprecise |= imp
            # A port-parse failure means the ACE's port space is approximate;
            # emit it as imprecise even for resolved addresses.
            m.other_imprecise |= imp
        elif key == "destination-port":
            pr, imp = _ports(vals, label, key, notes)
            m.dports += pr
            m.imprecise |= imp
            m.other_imprecise |= imp
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
            m.other_imprecise = True
            notes.append(f"Junos '{key}' in {label} not modeled — flag restriction "
                         f"ignored (over-approximated, marked imprecise)")
        elif key in ("address", "port", "icmp-type", "icmp-code"):
            # direction-agnostic / typed matches we can't place in the rectangle:
            # over-approximate (mark imprecise) so it's never used to prove deadness.
            # Also block partial precision: these conditions narrow the rule's true
            # match space in a way we don't model, so a "precise" src/dst ACE would
            # claim the rule matches flows the condition actually excludes.
            m.imprecise = True
            m.other_imprecise = True
            notes.append(f"unmodeled Junos match '{key}' in {label} "
                         f"(treated conservatively/imprecise — verify manually)")
        else:
            m.imprecise = True
            m.other_imprecise = True
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
                entries: List[ACE], notes: List[str], line: int = 0,
                family: Optional[str] = None) -> int:
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
    # Family-aware fallback: a missing src/dst matches EVERYTHING in the
    # filter's address family. Emitting a v4 0.0.0.0/0 for an inet6 term made
    # the ACE unable to match any v6 witness (mixed IP versions never
    # intersect), turning real inet6 permits invisible to segcheck — a silent
    # false PASS on assertions the device actually violates.
    fam_any = _fam_any_net(family)
    srcs = m.srcs or [fam_any]
    dsts = m.dsts or [fam_any]
    protos = m.protos or ["ip"]
    sports = m.sports or [ANY_PORTS]
    dports = m.dports or [ANY_PORTS]
    imprecise = m.imprecise
    other_imprecise = m.other_imprecise

    if (m.sports or m.dports) and any(p not in _PORTED for p in protos):
        # covers()/segcheck ignore ports on a non-port-carrying protocol
        # (including an omitted protocol -> "ip"), so those ACEs would claim an
        # exact all-ports space: widen the ports (superset) and flag imprecise.
        # This also blocks partial precision (the port space is approximate).
        imprecise = True
        other_imprecise = True
        notes.append(f"Junos term {label}: port match on a non-port-carrying "
                     f"protocol — ports widened to ANY for those protocols "
                     f"(marked imprecise — verify manually)")

    cap_exceeded = False
    if len(srcs) * len(dsts) * len(protos) * len(sports) * len(dports) > _MAX_EXPAND:
        # Truncating to the first value per dimension would model a SUBSET
        # (dropped members become invisible holes): widen everything instead.
        notes.append(f"Junos term {label} expands to >{_MAX_EXPAND} rules; widened "
                     f"to a single any/any rule (superset) and marked imprecise "
                     f"— verify manually")
        srcs, dsts, protos = [fam_any], [fam_any], ["ip"]
        sports, dports = [ANY_PORTS], [ANY_PORTS]
        imprecise = True
        cap_exceeded = True

    # --- Partial-precision path -----------------------------------------------
    # When at least one source-address or destination-address value was an
    # unresolvable named reference (address-book entry absent from this config
    # snippet), AND no other imprecision source is present, emit EXACT ACEs for
    # the resolved CIDR subset PLUS one opaque (any/any, imprecise=True) ACE for
    # the unresolved remainder.
    #
    # Soundness contract (mirrors parse.py _resolve_nets_partial):
    #   (1) Resolved-member ACEs are emitted with imprecise=False — their match
    #       space is EXACT and can prove a CRITICAL verdict.
    #   (2) Adding unresolved members can only EXPAND reachability, never remove a
    #       proven leak, so reporting CRITICAL from the resolved subset is correct.
    #   (3) The trailing opaque ACE keeps the unresolved portion INDETERMINATE —
    #       it can never produce a false PASS or a false CRITICAL on its own.
    #   (4) All-unresolved (m.srcs / m.dsts empty): the safety gate below blocks
    #       partial emission — the any-net fallback would over-approximate the
    #       source/destination space and risk a false CRITICAL.
    _do_partial = (
        (m.has_unresolved_src or m.has_unresolved_dst)  # at least one unresolved name
        and not other_imprecise                           # no other approximation source
        and not cap_exceeded                              # _MAX_EXPAND cap not hit
        and (not m.has_unresolved_src or bool(m.srcs))   # partial src: resolved srcs exist
        and (not m.has_unresolved_dst or bool(m.dsts))   # partial dst: resolved dsts exist
    )

    if not _do_partial and not cap_exceeded:
        # Blocked/normal path: a dimension holding unresolved names is widened
        # to the family ANY. Keeping only the resolved subset would model a
        # SUBSET of the term's true space (the unresolved members add unknown
        # space) and segcheck could skip the permit entirely — a false PASS.
        # ANY ⊇ true match restores the over-approximation invariant; the term
        # is imprecise here, so ANY can never prove a violation or deadness.
        if m.has_unresolved_src:
            srcs = [fam_any]
        if m.has_unresolved_dst:
            dsts = [fam_any]

    # (src, dst) pairs to emit. When exactly one side fell back to "any", the
    # fallback takes the IP VERSION OF THE GIVEN SIDE, so the ACE is always
    # internally version-consistent (a v4-src/v6-dst ACE matches nothing and
    # would be an invisible hole). Covers family-less snippets: a lone v6
    # source-address still gets a ::/0 destination, never 0.0.0.0/0.
    if m.srcs and not m.dsts:
        pairs = [(s, _ANY6_NET if s.version == 6 else _ANY_NET) for s in srcs]
    elif m.dsts and not m.srcs:
        pairs = [(_ANY6_NET if d.version == 6 else _ANY_NET, d) for d in dsts]
    else:
        pairs = [(s, d) for s in srcs for d in dsts]

    if _do_partial:
        n_precise = 0
        for proto in protos:
            ported = proto in _PORTED
            for s, d in pairs:
                for sp in (sports if ported else [ANY_PORTS]):
                    for dp in (dports if ported else [ANY_PORTS]):
                        seq += 1
                        n_precise += 1
                        entries.append(ACE(
                            seq=seq, action=action, proto=proto, src=s, dst=d,
                            src_port=sp, dst_port=dp, icmp_type=None,
                            stateful=m.stateful, imprecise=False,
                            raw=_raw(tname, action, proto, s, d, sp, dp),
                            acl=fname, line=line))
        # Trailing opaque ACE covers the unresolved-name remainder (in the
        # filter's own family: a v4 any/any remainder in an inet6 filter could
        # never match a v6 witness, so the fail-closed guard would fail OPEN).
        seq += 1
        entries.append(ACE(
            seq=seq, action=action, proto="ip",
            src=fam_any, dst=fam_any, imprecise=True,
            raw=f"term {tname}: {action} ip any -> any (unresolved address remainder)",
            acl=fname, line=line))
        notes.append(
            f"Junos term {label}: partially resolved address references — "
            f"{n_precise} exact ACE(s) + 1 opaque for unresolved named addresses"
        )
        return seq

    # Normal (non-partial) path — existing behaviour.
    for proto in protos:
        ported = proto in _PORTED
        for s, d in pairs:
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


# Filter-body statements that provably do not change which packets a term
# matches or what happens to them (they only affect counter instantiation) —
# safe to skip WITHOUT a note. Everything else unrecognized gets a note.
_HARMLESS_FILTER_STMTS = {"interface-specific", "physical-interface-filter"}


def _consume_stmt(toks: List[str], i: int) -> Tuple[List[str], int]:
    """`toks[i]` starts a non-term statement. Consume through its terminating
    `;` or matched `{...}` block (bracket lists included). Returns
    (head tokens — everything before the `;`/`{` — , index after the stmt)."""
    start, n = i, len(toks)
    while i < n and toks[i] not in (";", "{"):
        if toks[i] == "[":
            while i < n and toks[i] != "]":
                i += 1
        i += 1
    head = toks[start:i]
    if i < n and toks[i] == "{":
        _, i = _read_block(toks, i)
    else:
        i += 1                              # skip the `;` (or ran off the end)
    return head, i


def _parse_filter(fname: str, body: List[str], entries: List[ACE],
                  notes: List[str], term_lines: "dict",
                  family: Optional[str] = None) -> None:
    if family is None and any(_is_v6_literal(t) for t in body):
        # The filter was pasted without its enclosing `family` block but holds
        # IPv6 literals: infer inet6 so "matches everything" fallbacks emit
        # ::/0. Failing toward the v6 any is the fail-closed direction — a v4
        # any could never match a v6 witness (invisible permit => false PASS).
        family = "inet6"
        notes.append(f"Junos filter {fname}: no explicit family block in this "
                     f"snippet but IPv6 addresses present — modeled as family "
                     f"inet6 (unmatched src/dst default to ::/0)")
    seq = 0
    terms: List[Tuple[str, List[str]]] = []
    inherits = False
    i, n = 0, len(body)
    while i < n:
        t = body[i]
        if t == ";":
            i += 1
            continue
        if t == "term" and i + 2 < n and body[i + 2] == "{":
            tname = body[i + 1]
            tbody, i = _read_block(body, i + 2)
            terms.append((tname, tbody))
            continue
        if t == "inactive:":
            # A deactivated statement is NOT evaluated on the device — skipping
            # it is the exact model (modeling a deactivated deny as live could
            # falsely block a witness). Surfaced, never silent.
            head, i = _consume_stmt(body, i + 1)
            notes.append(f"deactivated (inactive:) Junos statement "
                         f"'{' '.join(head) or '?'}' in filter {fname} skipped "
                         f"(not evaluated on the device)")
            continue
        head, i = _consume_stmt(body, i)
        key = head[0] if head else "?"
        if key in ("apply-groups", "apply-groups-except"):
            # Configuration-group inheritance injects terms (BEFORE local terms)
            # that this snippet does not show. A missing inherited permit would
            # otherwise fall to the implicit default deny and false-PASS a
            # segmentation assertion — fail closed instead (opaque ACE below).
            inherits = True
            names = " ".join(v for v in head[1:] if v not in "[]") or "?"
            notes.append(
                f"Junos '{key} {names}' inside filter {fname}: inherited terms "
                f"are not visible in this config — the filter is modeled as "
                f"indeterminate (leading opaque rule), never as default-deny; "
                f"paste `show configuration | display inheritance` to audit "
                f"the effective filter exactly")
        elif key in _HARMLESS_FILTER_STMTS:
            continue
        else:
            notes.append(f"unmodeled Junos filter statement '{key}' in filter "
                         f"{fname} (surfaced, not modeled — verify manually)")
    if inherits:
        # Fail-closed: one leading opaque ACE (same pattern as the unresolved-
        # address opaque ACE in _parse_term). It is a permit so it is itself a
        # segmentation candidate (a filter with no literal permit can still not
        # PASS), and imprecise so _rule_matches returns "indeterminate" — it can
        # never prove a rule dead, never fire permit-any-any, and never produce
        # a concrete permit/deny verdict on its own.
        seq += 1
        entries.append(ACE(
            seq=seq, action="permit", proto="ip",
            src=_fam_any_net(family), dst=_fam_any_net(family), imprecise=True,
            raw=(f"filter {fname}: apply-groups — inherited terms not visible "
                 f"(indeterminate)"),
            acl=fname, line=0))
    for tname, tbody in terms:
        seq = _parse_term(fname, tname, tbody, seq, entries, notes,
                          term_lines.get((fname, tname), 0), family=family)


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


def _walk(toks: List[str], entries: List[ACE], notes: List[str],
          term_lines: "dict", family: Optional[str]) -> None:
    """Scan `toks` for filter definitions, tracking `family <name> {` context.

    Family blocks lexically wrap filter blocks (`firewall { family inet6 {
    filter F { ... } } }`), so the family of a filter is the innermost
    enclosing family block — None when the filter appears outside any (a bare
    pasted snippet). Everything else is walked token-by-token, exactly like
    the previous flat scan.
    """
    i, n = 0, len(toks)
    while i < n:
        if toks[i] == "family" and i + 2 < n and toks[i + 2] == "{":
            fam = toks[i + 1]
            fam_body, i = _read_block(toks, i + 2)
            _walk(fam_body, entries, notes, term_lines, fam)
        elif (toks[i] == "inactive:" and i + 3 < n and toks[i + 1] == "filter"
                and toks[i + 3] == "{"):
            # An `inactive:`-marked filter is deactivated — NONE of its terms
            # are enforced. Parsing it would let a deactivated deny block the
            # witness (false PASS). Skipped entirely, surfaced as a note.
            fname = toks[i + 2]
            _, i = _read_block(toks, i + 3)
            notes.append(f"Junos filter {fname} is inactive (deactivated) — "
                         f"not enforced; skipped")
        # A filter DEFINITION is `filter NAME {`. An *applied* filter
        # (`filter input NAME;` or `filter { input NAME; }` on an interface)
        # is not followed by NAME + `{`, so the guard below skips it.
        elif toks[i] == "filter" and i + 2 < n and toks[i + 2] == "{":
            fname = toks[i + 1]
            fbody, i = _read_block(toks, i + 2)
            _parse_filter(fname, fbody, entries, notes, term_lines, family)
        elif toks[i] in ("apply-groups", "apply-groups-except"):
            # Group inheritance OUTSIDE a filter body (config / firewall /
            # family level): inherited configuration this snippet does not show
            # may add or change filters/terms. We cannot attribute it to one
            # filter, so it is surfaced as a note — never silently dropped.
            key = toks[i]
            head, i = _consume_stmt(toks, i)
            names = " ".join(v for v in head[1:] if v not in "[]") or "?"
            notes.append(
                f"Junos '{key} {names}' outside a filter body: inherited "
                f"(group) configuration is not visible in this snippet and may "
                f"add or change firewall filters/terms — this audit covers only "
                f"the configuration shown; paste `show configuration | display "
                f"inheritance` to audit the effective config exactly")
        else:
            i += 1


def parse_junos(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse Junos firewall filters in `text`; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation`
    consume the result unchanged.
    """
    toks = _tokenize(text)
    term_lines = _term_line_map(text)
    entries: List[ACE] = []
    notes: List[str] = []
    _walk(toks, entries, notes, term_lines, None)

    if not entries and re.search(r"\bset\b.*\bfilter\b", text):
        notes.append("Junos 'set'-display format detected but not yet supported — "
                     "paste the curly-brace `show configuration` form to audit it.")
    return entries, notes
