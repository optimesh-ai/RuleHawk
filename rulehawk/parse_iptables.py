"""Parse Linux iptables / ip6tables filter rules into RuleHawk `ACE`s (RH-5).

Why iptables is the next frontend: the engine downstream of parsing
(`analyze.py`, `segcheck.py`, `model.ACE`) reasons about ORDERED, first-match
`permit`/`deny` rules over an (proto, src-net, dst-net, src-port, dst-port)
packet space. An iptables `filter`-table chain is exactly that shape: an ordered
list of rules evaluated top-to-bottom, first terminating match wins
(`-j ACCEPT` -> permit; `-j DROP`/`-j REJECT` -> deny), with a chain default
policy as the implicit last rule. So the whole existing analysis (the product's
real IP) is reused unchanged — this module only adds a new *frontend* that emits
the same `(List[ACE], notes)` IR. It broadens the free wedge from network
appliances to the host/container firewalls that dominate cloud/Kubernetes
estates (every node, every container host, runs a filter chain).

Each base chain (INPUT/FORWARD/OUTPUT) is its own first-match context, so we keep
the chain name as the ACE `acl` and number rules per chain — exactly how the
multi-ACL Cisco path already groups for shadow analysis. The default chain policy
(`:INPUT DROP` / `iptables -P INPUT DROP`) is appended as a synthetic trailing
`permit`/`deny ip any any`: a default-ACCEPT chain that *omits* this would make
`segcheck` falsely conclude isolation (the unsound direction).

THE SOUNDNESS LINE (the RH-3 lesson). RuleHawk models the L3/L4 packet space
only. Any construct that NARROWS a rule in a dimension we don't model — an
interface (`-i`/`-o`), an `ipset` membership (`-m set`), a negated match
(`! -s`), or an unknown match extension — OVER-APPROXIMATES the rule's space, so
it is marked `imprecise` and SURFACED as a parse note: it is never used to prove
another rule dead (`covers()` refuses it) and segmentation yields an honest
"indeterminate / review manually" instead of a possibly-wrong verdict.
`conntrack`/`state` ESTABLISHED,RELATED matches are return-traffic only and map
to `stateful` (like Cisco `established`). `multiport` is expanded to the exact
union of per-port ACEs (sound, not imprecise). NAT/custom-chain jumps and other
tables are surfaced, never silently dropped (an unmodeled line must never become
an invisible hole).

Scope (minimal but correct): both the `iptables-save` form (`*filter` ... `-A
CHAIN ...` ... `COMMIT`) and the command form (`iptables -A CHAIN ...`), for the
`filter` table only. Other tables (`nat`/`mangle`/`raw`) are surfaced and skipped.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet
from .parse import _port_num  # reuse the Cisco/IANA service-name -> port map

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")

# iptables `-j`/`-g` terminating targets -> RuleHawk action. ACCEPT => permit;
# DROP (silent) and REJECT (drop + ICMP/RST) both => deny.
_TERMINATING = {"ACCEPT": "permit", "DROP": "deny", "REJECT": "deny"}

# Non-terminating built-in targets: matching packets continue to the next rule,
# so these never decide a packet's fate and emit no ACE.
_NONTERMINATING = {"LOG", "AUDIT", "MARK", "CONNMARK", "TOS", "TCPMSS",
                   "NFLOG", "TRACE", "CLASSIFY", "SECMARK", "CONNSECMARK", "NOTRACK"}

# Built-in chains that carry a default policy (custom chains default to RETURN).
_BASE_CHAINS = frozenset({"INPUT", "FORWARD", "OUTPUT"})

# Host in/out hooks: a TRANSIT (inter-zone) packet is forwarded through the box
# and traverses ONLY the FORWARD chain, never INPUT (locally-destined) or OUTPUT
# (locally-originated). So INPUT/OUTPUT ACEs must NOT participate in the inter-
# zone segmentation witness search — their default-deny would otherwise shadow a
# FORWARD permit and FALSE-PASS a real leak. They stay available for hygiene
# analysis (shadow/least-privilege), just flagged `transit=False`. FORWARD and
# any user chains keep `transit=True` (safe side: at worst an over-report, never
# a hidden leak).
_NON_TRANSIT_CHAINS = frozenset({"INPUT", "OUTPUT"})


def _is_transit(chain: str) -> bool:
    return chain not in _NON_TRANSIT_CHAINS


def detect(text: str) -> bool:
    """Heuristic: does `text` look like iptables/ip6tables rules?

    Matches the command form (`iptables`/`ip6tables`), the iptables-save table
    header (`*filter`), or an append rule with a jump (`-A CHAIN ... -j`). Cisco
    ACLs, Junos filters and PAN-OS set-policies have none of these tokens, so they
    are never misrouted here.
    """
    return bool(
        re.search(r"(?m)^\s*ip6?tables\b", text)
        or re.search(r"(?m)^\s*\*(?:filter|nat|mangle|raw)\b", text)
        or (re.search(r"(?m)^\s*-A\s+\S+", text) and re.search(r"-j\s+\S+", text))
    )


def _is_v6(text: str) -> bool:
    """File-level default family: ip6tables (and no iptables) => IPv6."""
    return bool(re.search(r"(?m)^\s*ip6tables\b", text)) and not re.search(
        r"(?m)^\s*iptables\b", text)


def _net(tok: str) -> _IPNet:
    return ipaddress.ip_network(tok if "/" in tok else f"{tok}/32", strict=False)


def _ports(spec: str, label: str, key: str,
           notes: List[str]) -> Tuple[List[PortRange], bool]:
    """Parse an iptables port spec into ranges. Supports a single port, a
    `lo:hi` range (open ends `:hi` / `lo:` allowed), and a comma list (multiport).
    Each is expanded EXACTLY to one or more ranges. An unparsable component flips
    imprecise + a note so an all-bad spec can never widen to ANY and silently
    prove a later rule dead (the RH-3 lesson)."""
    ranges: List[PortRange] = []
    imprecise = False
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            lo, hi = part.split(":", 1)
            ln = _port_num(lo) if lo else PORT_MIN
            hn = _port_num(hi) if hi else PORT_MAX
            if ln < 0 or hn < 0:
                imprecise = True
                notes.append(f"unparsed iptables {key} '{part}' in {label} "
                             f"(marked imprecise — verify manually)")
                continue
            ranges.append(PortRange(min(ln, hn), max(ln, hn)))
        else:
            p = _port_num(part)
            if p < 0:
                imprecise = True
                notes.append(f"unparsed iptables {key} '{part}' in {label} "
                             f"(marked imprecise — verify manually)")
                continue
            ranges.append(PortRange(p, p))
    return ranges, imprecise


class _Rule:
    """Accumulated match state for one `-A` rule, before ACE expansion."""

    __slots__ = ("src", "dst", "proto", "sports", "dports", "stateful",
                 "imprecise", "icmp_type", "action", "skip_note", "modules")

    def __init__(self) -> None:
        self.src: Optional[_IPNet] = None
        self.dst: Optional[_IPNet] = None
        self.proto = "ip"
        self.sports: List[PortRange] = []
        self.dports: List[PortRange] = []
        self.stateful = False
        self.imprecise = False
        self.icmp_type: Optional[str] = None
        self.action: Optional[str] = None
        self.skip_note: Optional[str] = None   # set => rule emits no ACE (surfaced)
        self.modules: List[str] = []


_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6",
              "47": "gre", "50": "esp", "51": "ah", "89": "ospf", "132": "sctp"}


def _norm_proto(v: str) -> str:
    v = v.lower()
    v = _PROTO_NUM.get(v, v)
    if v in ("ipv6-icmp",):
        return "icmpv6"
    if v == "all":
        return "ip"
    return v


def _parse_rule(toks: List[str], label: str, notes: List[str]) -> _Rule:
    """Parse the option tokens of one `-A CHAIN <here>` rule into a `_Rule`."""
    r = _Rule()
    i, n = 0, len(toks)
    negate = False
    while i < n:
        t = toks[i]
        if t == "!":                                  # negate the NEXT match
            negate = True
            i += 1
            continue
        nxt = toks[i + 1] if i + 1 < n else None
        if t in ("-s", "--source", "--src"):
            if negate:
                r.imprecise = True
                notes.append(f"negated source (`! -s {nxt}`) in {label} — a negated "
                             f"set isn't one rectangle (marked imprecise — verify)")
            else:
                try:
                    r.src = _net(nxt)
                except ValueError:
                    r.imprecise = True
                    notes.append(f"unparsed iptables source '{nxt}' in {label} "
                                 f"(marked imprecise — verify manually)")
            i += 2
        elif t in ("-d", "--destination", "--dst"):
            if negate:
                r.imprecise = True
                notes.append(f"negated destination (`! -d {nxt}`) in {label} — a "
                             f"negated set isn't one rectangle (marked imprecise — verify)")
            else:
                try:
                    r.dst = _net(nxt)
                except ValueError:
                    r.imprecise = True
                    notes.append(f"unparsed iptables destination '{nxt}' in {label} "
                                 f"(marked imprecise — verify manually)")
            i += 2
        elif t in ("-p", "--protocol"):
            r.proto = _norm_proto(nxt)
            if negate:
                r.imprecise = True
                notes.append(f"negated protocol (`! -p {nxt}`) in {label} "
                             f"(marked imprecise — verify manually)")
            i += 2
        elif t in ("--dport", "--destination-port"):
            pr, imp = _ports(nxt, label, "--dport", notes)
            r.dports += pr
            r.imprecise |= imp or negate
            if negate:
                notes.append(f"negated --dport in {label} (marked imprecise — verify)")
            i += 2
        elif t in ("--sport", "--source-port"):
            pr, imp = _ports(nxt, label, "--sport", notes)
            r.sports += pr
            r.imprecise |= imp or negate
            if negate:
                notes.append(f"negated --sport in {label} (marked imprecise — verify)")
            i += 2
        elif t in ("--dports", "--destination-ports"):   # multiport (exact union)
            pr, imp = _ports(nxt, label, "--dports", notes)
            r.dports += pr
            r.imprecise |= imp or negate
            notes.append(f"iptables multiport --dports '{nxt}' in {label} expanded to "
                         f"{len(pr)} exact per-port rule(s)")
            i += 2
        elif t in ("--sports", "--source-ports"):
            pr, imp = _ports(nxt, label, "--sports", notes)
            r.sports += pr
            r.imprecise |= imp or negate
            notes.append(f"iptables multiport --sports '{nxt}' in {label} expanded to "
                         f"{len(pr)} exact per-port rule(s)")
            i += 2
        elif t in ("--state", "--ctstate"):
            states = {s.strip().upper() for s in (nxt or "").split(",") if s.strip()}
            if states and states <= {"ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"}:
                # No NEW: return-traffic only -> stateful (never proves a flow open).
                r.stateful = True
                notes.append(f"iptables conntrack/state {sorted(states)} in {label} "
                             f"modeled as stateful (return-traffic only; never used "
                             f"to prove a rule dead)")
            else:
                # Includes NEW: the connection-opening packet IS allowed, so the
                # L3/L4 reachability is real — model it normally (a note for audit).
                notes.append(f"iptables conntrack/state {sorted(states)} in {label} "
                             f"(NEW present — modeled as a new-flow rule)")
            i += 2
        elif t == "--match-set":                      # ipset: membership unknown
            r.imprecise = True
            notes.append(f"iptables ipset match `-m set --match-set {nxt} ...` in "
                         f"{label} — set membership not modeled (over-approximated to "
                         f"ANY, marked imprecise — verify manually)")
            i += 3 if (i + 2 < n and not toks[i + 2].startswith("-")) else 2
        elif t in ("-i", "--in-interface", "-o", "--out-interface"):
            r.imprecise = True
            notes.append(f"iptables interface match `{t} {nxt}` in {label} not modeled "
                         f"(L3/L4 over-approximation — marked imprecise, used "
                         f"conservatively)")
            i += 2
        elif t == "--icmp-type" or t == "--icmpv6-type":
            r.icmp_type = nxt
            i += 2
        elif t in ("-m", "--match"):
            r.modules.append(nxt or "")
            i += 2
        elif t in ("-j", "--jump", "-g", "--goto"):
            target = (nxt or "").upper()
            if target in _TERMINATING:
                r.action = _TERMINATING[target]
            elif target in _NONTERMINATING:
                r.skip_note = (f"iptables non-terminating target `-j {nxt}` in {label} "
                               f"— matching packets continue to the next rule (no "
                               f"decision modeled)")
            elif target == "RETURN":
                r.skip_note = (f"iptables `-j RETURN` in {label} returns to the calling "
                               f"chain/policy (no terminating decision modeled)")
            elif target in ("MASQUERADE", "SNAT", "DNAT", "REDIRECT", "NETMAP"):
                r.skip_note = (f"iptables NAT target `-j {nxt}` in {label} — address "
                               f"rewriting is not modeled (filter-space only; verify "
                               f"the NAT table manually)")
            else:
                # A jump to a user-defined chain: its effect (accept/drop/return)
                # is indeterminate in this flat model -> surface, emit no decision.
                r.skip_note = (f"iptables jump to custom chain `-j {nxt}` in {label} — "
                               f"sub-chain effect not modeled (no decision emitted; "
                               f"flatten or verify the chain manually)")
            i += 2
        elif t == "-f" or t == "--fragment":
            r.imprecise = True
            notes.append(f"iptables fragment match (`-f`) in {label} — applies only to "
                         f"non-first fragments (marked imprecise — verify manually)")
            i += 1
        elif t.startswith("-") and t not in ("-A", "--append"):
            # Unknown narrowing option (e.g. --tcp-flags, --syn, -m limit options):
            # over-approximate and surface, never silently drop the constraint.
            r.imprecise = True
            consumed = 2 if (nxt is not None and not nxt.startswith("-")) else 1
            notes.append(f"unmodeled iptables option `{t}"
                         + (f" {nxt}`" if consumed == 2 else "`")
                         + f" in {label} (marked imprecise — verify manually)")
            i += consumed
        else:
            i += 1
        negate = False
    return r


def _raw(chain: str, action: str, proto: str, s: _IPNet, d: _IPNet,
         sp: PortRange, dp: PortRange) -> str:
    parts = [f"{chain}:", action, proto, str(s), "->", str(d)]
    if not sp.is_any():
        parts.append(f"sport {sp}")
    if not dp.is_any():
        parts.append(f"dport {dp}")
    return " ".join(parts)


def _expand(chain: str, r: _Rule, seq: int, entries: List[ACE],
            default6: bool) -> int:
    """Expand one parsed rule into ACEs (one per src/dst-port combo)."""
    v6 = default6
    if r.src is not None:
        v6 = r.src.version == 6
    elif r.dst is not None:
        v6 = r.dst.version == 6
    any_net = _ANY6 if v6 else _ANY4
    src = r.src if r.src is not None else any_net
    dst = r.dst if r.dst is not None else any_net
    ported = r.proto in ("tcp", "udp", "sctp")
    sports = (r.sports or [ANY_PORTS]) if ported else [ANY_PORTS]
    dports = (r.dports or [ANY_PORTS]) if ported else [ANY_PORTS]
    transit = _is_transit(chain)
    for sp in sports:
        for dp in dports:
            seq += 1
            entries.append(ACE(
                seq=seq, action=r.action, proto=r.proto, src=src, dst=dst,
                src_port=sp, dst_port=dp, icmp_type=r.icmp_type,
                stateful=r.stateful, imprecise=r.imprecise,
                raw=_raw(chain, r.action, r.proto, src, dst, sp, dp), acl=chain,
                transit=transit))
    return seq


def _strip_command(line: str) -> Optional[str]:
    """For the command form, drop a leading `iptables`/`ip6tables` (and `sudo`).
    Return the remaining args string, or None if the line isn't an ip(6)tables
    command."""
    s = line.strip()
    s = re.sub(r"^sudo\s+", "", s)
    m = re.match(r"^ip6?tables(?:-(?:save|restore|nft))?\s+(.*)$", s)
    return m.group(1) if m else None


def parse_iptables(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse iptables/ip6tables filter rules in `text`; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation`
    consume the result unchanged. Rules are grouped per chain (first-match
    context) in first-appearance order; each chain's declared default policy is
    appended as a synthetic trailing rule.
    """
    default6 = _is_v6(text)
    notes: List[str] = []
    chains: List[str] = []                       # chain order of first appearance
    by_chain: Dict[str, List[ACE]] = {}
    seqs: Dict[str, int] = {}
    policies: Dict[str, str] = {}                # chain -> permit|deny (from policy)
    table = "filter"                             # iptables-save default before *table
    table_is_filter = True
    other_tables_noted: set = set()

    def ensure_chain(ch: str) -> None:
        if ch not in by_chain:
            by_chain[ch] = []
            seqs[ch] = 0
            chains.append(ch)

    def add_rule(ch: str, args: List[str]) -> None:
        ensure_chain(ch)
        label = f"{ch}:{seqs[ch] + 1}"
        r = _parse_rule(args, label, notes)
        if r.skip_note is not None:
            notes.append(r.skip_note)
            return
        if r.action is None:
            notes.append(f"iptables rule in {ch} has no terminating target "
                         f"(-j ACCEPT/DROP/REJECT) — skipped")
            return
        seqs[ch] = _expand(ch, r, seqs[ch], by_chain[ch], default6)

    def set_policy(ch: str, pol: str) -> None:
        act = _TERMINATING.get(pol.upper())
        if act is not None:
            policies[ch] = act
            ensure_chain(ch)

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):                 # iptables-save table header
            table = line[1:].strip().split()[0] if len(line) > 1 else "filter"
            table_is_filter = (table == "filter")
            if not table_is_filter and table not in other_tables_noted:
                other_tables_noted.add(table)
                notes.append(f"iptables '{table}' table present — not modeled "
                             f"(filter-space only; review NAT/mangle/raw manually)")
            continue
        if line.upper() == "COMMIT":
            continue

        if line.startswith(":"):                 # save-form chain + default policy
            if not table_is_filter:
                continue
            parts = line[1:].split()
            if len(parts) >= 2 and parts[0] in _BASE_CHAINS:
                set_policy(parts[0], parts[1])
            elif len(parts) >= 1:
                ensure_chain(parts[0])           # custom chain declaration
            continue

        # Command form: strip the leading `iptables`/`ip6tables`.
        cmd = _strip_command(line)
        rest = cmd if cmd is not None else line  # save-form `-A ...` has no prefix

        try:
            toks = shlex.split(rest, comments=False, posix=True)
        except ValueError:
            toks = rest.split()
        if not toks:
            continue

        # Honor an explicit `-t TABLE` (command form); default table is filter.
        if "-t" in toks or "--table" in toks:
            k = toks.index("-t") if "-t" in toks else toks.index("--table")
            tbl = toks[k + 1] if k + 1 < len(toks) else "filter"
            del toks[k:k + 2]
            if tbl != "filter":
                if tbl not in other_tables_noted:
                    other_tables_noted.add(tbl)
                    notes.append(f"iptables '{tbl}' table rule present — not modeled "
                                 f"(filter-space only; review manually)")
                continue
        elif cmd is not None and not table_is_filter:
            # A bare command line inside a non-filter save block (rare) — skip.
            continue

        # Dispatch the action verb.
        if "-A" in toks or "--append" in toks:
            k = toks.index("-A") if "-A" in toks else toks.index("--append")
            if k + 1 < len(toks):
                ch = toks[k + 1]
                add_rule(ch, toks[k + 2:])
        elif "-I" in toks or "--insert" in toks:
            # Insert: surfaced (we can't reorder soundly without the index math);
            # treat as append-at-position-unknown -> note, then append for coverage.
            k = toks.index("-I") if "-I" in toks else toks.index("--insert")
            if k + 1 < len(toks):
                ch = toks[k + 1]
                args = toks[k + 2:]
                # Drop a leading numeric insert position if present.
                if args and args[0].isdigit():
                    args = args[1:]
                notes.append(f"iptables `-I {ch}` insert in {ch} appended at end for "
                             f"analysis — original insert position not modeled (verify)")
                add_rule(ch, args)
        elif "-P" in toks or "--policy" in toks:
            k = toks.index("-P") if "-P" in toks else toks.index("--policy")
            if k + 2 < len(toks):
                set_policy(toks[k + 1], toks[k + 2])
        elif "-N" in toks or "--new-chain" in toks:
            k = toks.index("-N") if "-N" in toks else toks.index("--new-chain")
            if k + 1 < len(toks):
                ensure_chain(toks[k + 1])
        # -F/-X/-Z and others: no rule contribution; ignored.

    # Append each chain's default policy as the implicit trailing rule. A missing
    # policy on a base chain that carries rules is surfaced (we must not silently
    # assume DROP and risk a false isolation PASS).
    entries: List[ACE] = []
    for ch in chains:
        chain_aces = by_chain[ch]
        if ch in policies:
            seqs[ch] += 1
            any_net = _ANY6 if default6 else _ANY4
            act = policies[ch]
            chain_aces.append(ACE(
                seq=seqs[ch], action=act, proto="ip", src=any_net, dst=any_net,
                raw=f"{ch}: default policy {act} (chain policy)", acl=ch,
                transit=_is_transit(ch)))
        elif chain_aces and ch in _BASE_CHAINS:
            notes.append(f"iptables base chain {ch} has rules but no explicit default "
                         f"policy in this config — default not modeled (paste the "
                         f"`:{ch} POLICY` line / `-P {ch} ...` to audit the fall-through)")
        entries.extend(chain_aces)

    # iptables base chains (INPUT/FORWARD/OUTPUT) are INDEPENDENT first-match
    # hooks. A transit (inter-zone) packet is forwarded through the box and
    # traverses ONLY the FORWARD chain, so the INPUT/OUTPUT host hooks are flagged
    # `transit=False` (see `_is_transit`) and excluded from the inter-zone
    # segmentation witness search — one hook's default-deny can no longer shadow a
    # FORWARD permit (the soundness fix). Surface the chain inventory so the FORWARD
    # scoping is visible to an auditor.
    chains_with_rules = [c for c in chains if any(
        "policy" not in a.raw for a in by_chain[c])]
    if len(chains_with_rules) > 1:
        notes.append("multiple iptables chains present "
                     f"({', '.join(chains_with_rules)}); they are independent "
                     "first-match hooks. Inter-zone segmentation is decided by the "
                     "FORWARD chain only (transit path); the INPUT/OUTPUT host hooks "
                     "are excluded from the cross-zone witness search so their "
                     "default policy cannot shadow a FORWARD rule (they remain in "
                     "hygiene/shadow analysis).")

    if not entries and not notes:
        notes.append("no iptables filter-table rules found "
                     "(only the `filter` table is modeled).")
    return entries, notes
