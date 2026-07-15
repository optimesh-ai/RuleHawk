"""Parse Microsoft (Windows Server) DNS **client-subnet query-resolution
policies** into RuleHawk ``ACE``s — the L3/L4-relevant access slice only.

SCOPE (what this models, and what it deliberately does NOT).
Windows DNS Server exposes several policy surfaces. Only ONE of them is a
packet-layer access control: the *Query Resolution Policy* gated by CLIENT
SUBNET — "which client networks may resolve (or are blocked) via this DNS
server on udp/tcp 53". That is exactly the shape RuleHawk reasons about
(ordered, first-match permit/deny over an (proto, src-net, dst-net, port)
space), so it is modeled here. Everything else the DNS policy engine can do —
RPZ / Response Rate Limiting, ZONE-scope and RECURSION-scope selection, QTYPE /
FQDN / record-content matching — lives at the DNS application layer (WHICH
ANSWER is returned), not at the packet-reachability layer, and is OUT OF SCOPE
for a packet auditor. A policy that carries such a dimension is not exactly
modelable as one src-rectangle, so it is widened + flagged ``imprecise`` (never
narrowed) rather than silently dropped.

TARGET FORMAT — the PowerShell cmdlets that DEFINE this access layer (this is
how Windows DNS client-subnets and query-resolution policies are configured and
exported):

    Add-DnsServerClientSubnet -Name "CorpSubnet"  -IPv4Subnet "10.20.0.0/16"
    Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/16","10.71.0.0/16"
    Add-DnsServerQueryResolutionPolicy -Name "BlockGuest" -Action DENY  -ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1
    Add-DnsServerQueryResolutionPolicy -Name "AllowCorp"  -Action ALLOW -ClientSubnet "EQ,CorpSubnet"  -ProcessingOrder 2

THE ACE MAPPING (reach-the-resolver, modeled soundly as a SUPERSET).
The "packet" is a DNS query FROM a client subnet TO this DNS server on port 53.
  * src = the matched client subnet's CIDR(s).
  * dst = ANY. The server's own address is NOT present in this config; dst=ANY
    is a strict SUPERSET of "the server", hence sound.
  * proto/port = BOTH udp/53 and tcp/53 (two ACEs per src member) — DNS answers
    over either transport.
Action ALLOW -> ``permit``; DENY and IGNORE -> ``deny`` (IGNORE drops the query,
same reachability effect as DENY).

FIRST-MATCH ORDER. Policies are evaluated by ``-ProcessingOrder`` ASCENDING
(the Windows first-match order); the ACE list is emitted in that order and every
policy shares the single ``acl`` context ``"dns-query-policy"`` (one ordered
first-match list). A policy with no explicit ``-ProcessingOrder`` is appended
AFTER all explicitly-ordered ones — which is exactly what the real cmdlet does
when the parameter is omitted (it auto-assigns the next-highest order).

THE ``-ClientSubnet`` EXPRESSION selects the src. It is a comma/boolean list:
  * ``EQ,Name``    -> src = that client subnet's CIDR(s)  (one ACE per CIDR).
  * ``EQ,A,B``     -> OR of A and B  (ACEs for every CIDR of A and of B).
  * ``NE,Name``    -> NEGATED: "every client EXCEPT Name". A set-complement is
    NOT one rectangle, so the src is widened to ANY (both families) + flagged
    ``imprecise`` + noted. The negated value is NEVER kept and the modeled src
    is never a subset — over-approximation only (the RuleHawk parser contract).
  * unknown operator, ``GT``/``LT`` (time-of-day) forms, an AND-combined extra
    criterion, or an undefined referenced client-subnet name -> src widened to
    ANY + ``imprecise`` + noted. Same fail-closed reason.

THE FAIL-CLOSED DEFAULT. When NO query-resolution policy matches, Windows DNS
resolves normally (default = ALLOW). Omitting that would let ``must_not_reach``
FALSE-PASS: an unmatched forbidden flow would fall to RuleHawk's implicit
default-deny and certify isolation that the server does not actually enforce. So
a trailing ``permit ip any any`` marker (per family) is appended with
``imprecise=True``: an unmatched forbidden flow hits it and yields segmentation
INDETERMINATE (fail closed / review manually), never a clean PASS. An explicit
DENY that fully covers the flow decides it earlier and still PASSes correctly —
the marker only catches the genuinely unmatched space.

DETECTION. ``detect`` fires only on the DNS cmdlet names
(``Add``/``Set``/``Get``/``Remove``-``DnsServerQueryResolutionPolicy`` or
``-DnsServerClientSubnet``), line-anchored and case-insensitive. Those tokens
appear in no other vendor and, in particular, cannot collide with a Windows
*Firewall* export (``netsh advfirewall`` / ``Rule Name:`` / ``Direction:`` /
``Action:``) — different markers entirely.

Robustness: malformed cmdlet lines, missing parameters and unknown expression
forms degrade to a surfaced note (and, where reachability could be affected, an
``imprecise`` fail-closed ACE) — never a crash, never a silent hole.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PortRange, _IPNet

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")
_DNS_PORT = PortRange(53, 53)
_ACL = "dns-query-policy"

# The cmdlet verbs/nouns that define this access layer. `Get`/`Remove` are
# accepted for detection completeness; only `Add`/`Set` DEFINE state we parse.
_DETECT_RE = re.compile(
    r"(?im)^\s*(?:Add|Set|Get|Remove)-DnsServer"
    r"(?:QueryResolutionPolicy|ClientSubnet)\b"
)
_DEFINE_RE = re.compile(
    r"(?i)^\s*(?P<verb>Add|Set)-DnsServer(?P<noun>QueryResolutionPolicy|ClientSubnet)\b"
    r"(?P<args>.*)$"
)

# Policy parameters we fully model or that never narrow the packet match space.
# ANY other parameter on a policy is an unmodeled (possibly narrowing) criterion
# -> the policy is flagged imprecise (fail closed), never silently ignored.
_POLICY_OK = frozenset({
    "name", "action", "clientsubnet", "processingorder",
    "passthru", "computername", "cimsession", "whatif", "confirm",
})

_BIG_ORDER = 10 ** 9  # sort key for policies with no explicit -ProcessingOrder

# One tokenizer for a cmdlet's argument string: quoted strings are kept whole,
# commas are array separators, `-Word` is a parameter name, everything else is a
# bare value. Whitespace between tokens is skipped by finditer.
_TOK_RE = re.compile(
    r'"(?P<dq>[^"]*)"'
    r"|'(?P<sq>[^']*)'"
    r"|(?P<comma>,)"
    r"|(?P<bare>[^\s,]+)"
)


def detect(text: str) -> bool:
    """True iff `text` contains a Windows DNS client-subnet / query-resolution
    cmdlet (line-anchored, case-insensitive). These cmdlet names appear in no
    other vendor and never collide with the Windows Firewall (`netsh
    advfirewall` / `Rule Name:` / `Direction:`) format."""
    return bool(_DETECT_RE.search(text))


def _join_continuations(text: str) -> List[Tuple[int, str]]:
    """Split into (1-based first-line-number, logical-line) pairs, joining
    PowerShell backtick line continuations. Tolerant: a dangling trailing
    backtick at EOF just ends the line."""
    out: List[Tuple[int, str]] = []
    pending: Optional[str] = None
    start = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        s = raw.rstrip("\r\n")
        if pending is None:
            start = lineno
            pending = ""
        cont = s.rstrip().endswith("`")
        body = s.rstrip()[:-1] if cont else s
        pending += (" " if pending else "") + body.strip()
        if not cont:
            out.append((start, pending))
            pending = None
    if pending is not None:
        out.append((start, pending))
    return out


def _tokenize(argstr: str):
    for m in _TOK_RE.finditer(argstr):
        if m.group("dq") is not None:
            yield ("val", m.group("dq"))
        elif m.group("sq") is not None:
            yield ("val", m.group("sq"))
        elif m.group("comma") is not None:
            yield ("comma", None)
        else:
            b = m.group("bare")
            if len(b) > 1 and b[0] == "-" and b[1].isalpha():
                yield ("param", b[1:].lower())
            else:
                yield ("val", b)


def _params(argstr: str) -> Dict[str, List[str]]:
    """Parse a cmdlet argument string into {param_name_lower: [value, ...]}.
    Parameter order is irrelevant; a bare switch (no value) maps to []."""
    d: Dict[str, List[str]] = {}
    cur: Optional[str] = None
    for kind, v in _tokenize(argstr):
        if kind == "param":
            cur = v
            d.setdefault(cur, [])
        elif kind == "val" and cur is not None:
            d[cur].append(v)
        # comma: array separator — values are already collected individually.
    return d


def _flat(d: Dict[str, List[str]], key: str) -> List[str]:
    """All values of `key`, each further split on commas (so a quoted
    "EQ,A,B" single value and an unquoted EQ,A,B array both flatten alike)."""
    out: List[str] = []
    for v in d.get(key, []):
        for part in v.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _scalar(d: Dict[str, List[str]], key: str) -> Optional[str]:
    vals = _flat(d, key)
    return vals[0] if vals else None


def _net(tok: str) -> _IPNet:
    return ipaddress.ip_network(tok, strict=False)


def _resolve_subnet_cidrs(d: Dict[str, List[str]], name: str,
                          notes: List[str]) -> List[_IPNet]:
    """Parse -IPv4Subnet / -IPv6Subnet CIDRs of one client-subnet definition."""
    nets: List[_IPNet] = []
    for key in ("ipv4subnet", "ipv6subnet"):
        for c in _flat(d, key):
            try:
                nets.append(_net(c))
            except ValueError:
                notes.append(
                    f"msdns client-subnet '{name}': invalid CIDR '{c}' skipped "
                    f"(verify manually)")
    return nets


def _src_entries(op: str, names: List[str],
                 subnets: Dict[str, List[_IPNet]],
                 policy: str, notes: List[str]) -> List[Tuple[_IPNet, bool]]:
    """Map a -ClientSubnet expression to a list of (src_net, imprecise) entries.

    EQ over defined names -> one exact (cidr, False) per member CIDR (OR of the
    members). NE (negation), an undefined member, an empty/unknown expression,
    or a non-EQ/NE operator (GT/LT time forms, etc.) -> widen to ANY of BOTH
    families with imprecise=True (a set-complement / unresolved reference is not
    one rectangle; over-approximate, never narrow)."""
    widened = [(_ANY4, True), (_ANY6, True)]
    if op == "NE":
        notes.append(
            f"msdns policy '{policy}': negated client-subnet (NE,{','.join(names)}) "
            f"— 'every client except' is a set-complement, not one subnet; src "
            f"widened to ANY + imprecise (fail-closed; verify manually)")
        return widened
    if op != "EQ":
        notes.append(
            f"msdns policy '{policy}': unsupported client-subnet operator "
            f"'{op or '(none)'}' — src widened to ANY + imprecise (fail-closed; "
            f"verify manually)")
        return widened
    if not names:
        notes.append(
            f"msdns policy '{policy}': EQ client-subnet expression names no "
            f"subnet — src widened to ANY + imprecise (fail-closed)")
        return widened
    entries: List[Tuple[_IPNet, bool]] = []
    for nm in names:
        cidrs = subnets.get(nm.lower())
        if not cidrs:
            notes.append(
                f"msdns policy '{policy}': references undefined client-subnet "
                f"'{nm}' — src cannot be resolved; widened to ANY + imprecise "
                f"(fail-closed; verify manually)")
            return widened
        for c in cidrs:
            entries.append((c, False))
    return entries


def _emit(entries: List[ACE], seq: int, action: str, src: _IPNet,
          imprecise: bool, line: int, tag: str) -> int:
    """Emit the udp/53 and tcp/53 ACE pair for one src member."""
    fam_any = _ANY4 if src.version == 4 else _ANY6
    for proto in ("udp", "tcp"):
        seq += 1
        entries.append(ACE(
            seq=seq, action=action, proto=proto, src=src, dst=fam_any,
            src_port=ANY_PORTS, dst_port=_DNS_PORT, imprecise=imprecise,
            raw=f"{_ACL}: {action} {proto} {src} -> any dport 53 ({tag})",
            acl=_ACL, line=line, transit=True))
    return seq


def parse_msdns(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse Windows DNS client-subnet query-resolution policies into ACEs.

    Same (entries, notes) contract as every other RuleHawk frontend, so
    ``analyze`` / ``check_segmentation`` consume the result unchanged. All ACEs
    share the single first-match context ``"dns-query-policy"`` and are ordered
    by ``-ProcessingOrder``; a trailing fail-closed default marker models the
    Windows default-ALLOW.
    """
    notes: List[str] = []
    subnets: Dict[str, List[_IPNet]] = {}   # name_lower -> CIDRs
    # policies keyed by name_lower for Set/Add upsert; each carries its params.
    policies: Dict[str, dict] = {}
    order_counter = 0                       # first-seen insertion rank

    for line, logical in _join_continuations(text):
        if not logical or logical.lstrip().startswith("#"):
            continue
        m = _DEFINE_RE.match(logical)
        if not m:
            continue  # Get-/Remove- and unrelated lines define no state here.
        noun = m.group("noun").lower()
        try:
            d = _params(m.group("args"))
        except Exception:  # pragma: no cover - defensive; never crash a parse
            notes.append(f"msdns: could not parse cmdlet arguments at line "
                         f"{line} (skipped; verify manually)")
            continue

        name = _scalar(d, "name")
        if noun == "clientsubnet":
            if name is None:
                notes.append(f"msdns Add/Set-DnsServerClientSubnet at line "
                             f"{line} has no -Name (skipped; verify manually)")
                continue
            cidrs = _resolve_subnet_cidrs(d, name, notes)
            key = name.lower()
            if key in subnets:
                notes.append(f"msdns client-subnet '{name}' redefined — last "
                             f"definition wins (verify manually)")
            subnets[key] = cidrs
        else:  # queryresolutionpolicy
            if name is None:
                notes.append(f"msdns Add/Set-DnsServerQueryResolutionPolicy at "
                             f"line {line} has no -Name (skipped; verify manually)")
                continue
            key = name.lower()
            if key not in policies:
                policies[key] = {"name": name, "rank": order_counter,
                                 "params": {}, "line": line}
                order_counter += 1
            # Merge params (Set updates an existing policy in place).
            policies[key]["params"].update(d)
            policies[key]["line"] = line

    # Order by -ProcessingOrder ascending; policies without one sort AFTER the
    # explicitly-ordered ones (matching the cmdlet's auto-assign behavior), with
    # first-seen rank as a stable tiebreak.
    ordered = []
    for pol in policies.values():
        po = _scalar(pol["params"], "processingorder")
        order_val = _BIG_ORDER
        if po is not None:
            try:
                order_val = int(po)
            except ValueError:
                notes.append(f"msdns policy '{pol['name']}': non-integer "
                             f"-ProcessingOrder '{po}' — placed after ordered "
                             f"policies (verify manually)")
        ordered.append((order_val, pol["rank"], pol))
    ordered.sort(key=lambda t: (t[0], t[1]))

    entries: List[ACE] = []
    seq = 0
    for _order, _rank, pol in ordered:
        d = pol["params"]
        pname = pol["name"]
        line = pol["line"]

        # Any parameter beyond the modeled/benign set is an unmodeled criterion
        # (TransportProtocol, TimeOfDay, QType, ServerInterface, ZoneName, ...)
        # that could NARROW the real match space. Modeling such a policy at full
        # width would let a DENY over-subtract (a false-PASS in isolation), so
        # fail closed: flag imprecise + surface it.
        extra = sorted(k for k in d if k not in _POLICY_OK)
        base_imprecise = False
        if extra:
            base_imprecise = True
            notes.append(
                f"msdns policy '{pname}': additional unmodeled criterion "
                f"parameter(s) {extra} — narrow the real match beyond client "
                f"subnet; flagged imprecise (fail-closed; verify manually)")

        act_raw = _scalar(d, "action")
        if act_raw is None:
            action = "permit"
            base_imprecise = True
            notes.append(f"msdns policy '{pname}': no -Action — cannot tell "
                         f"allow from deny; flagged imprecise (fail-closed)")
        elif act_raw.upper() == "ALLOW":
            action = "permit"
        elif act_raw.upper() in ("DENY", "IGNORE"):
            action = "deny"
        else:
            action = "permit"
            base_imprecise = True
            notes.append(f"msdns policy '{pname}': unknown -Action '{act_raw}' "
                         f"— flagged imprecise (fail-closed; verify manually)")

        expr = _flat(d, "clientsubnet")
        if not expr:
            notes.append(f"msdns policy '{pname}': no -ClientSubnet criterion — "
                         f"src widened to ANY + imprecise (fail-closed)")
            src_entries = [(_ANY4, True), (_ANY6, True)]
        else:
            op = expr[0].upper()
            names = expr[1:]
            src_entries = _src_entries(op, names, subnets, pname, notes)

        tag = f"policy {pname}"
        for src, ent_imprecise in src_entries:
            seq = _emit(entries, seq, action, src,
                        base_imprecise or ent_imprecise, line, tag)

    # Trailing fail-closed default: Windows DNS resolves normally when no policy
    # matches (default ALLOW). Emit an imprecise `permit ip any any` per family
    # so an unmatched forbidden flow yields segmentation-INDETERMINATE, never a
    # false isolation PASS. An explicit DENY that fully covers a flow decides it
    # earlier and this marker is never reached for that flow.
    for fam in (_ANY4, _ANY6):
        seq += 1
        entries.append(ACE(
            seq=seq, action="permit", proto="ip", src=fam, dst=fam,
            imprecise=True,
            raw=f"{_ACL}: DEFAULT allow (Windows DNS resolves when no policy "
                f"matches) — modeled fail-closed (imprecise)",
            acl=_ACL, line=0, transit=True))

    if not policies:
        notes.append("msdns: no query-resolution policies found — Windows DNS "
                     "default is ALLOW; modeled as a fail-closed imprecise "
                     "marker so isolation is never falsely certified.")
    return entries, notes
