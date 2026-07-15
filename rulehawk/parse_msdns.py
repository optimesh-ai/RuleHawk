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

TARGET FORMAT — the PowerShell cmdlets that DEFINE this access layer:

    Add-DnsServerClientSubnet -Name "CorpSubnet"  -IPv4Subnet "10.20.0.0/16"
    Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/16","10.71.0.0/16"
    Add-DnsServerQueryResolutionPolicy -Name "BlockGuest" -Action DENY  -ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1
    Add-DnsServerQueryResolutionPolicy -Name "AllowCorp"  -Action ALLOW -ClientSubnet "EQ,CorpSubnet"  -ProcessingOrder 2

This is the PROVISIONING form (an IaC / DSC / setup-script artifact). Note the
audit-time reality: reading an EXISTING server with
`Get-DnsServerQueryResolutionPolicy` renders the match criteria as the opaque
`{DnsServerPolicyCriteria}` token — the `-ClientSubnet` expression and CIDRs are
NOT in that output (they live in the nested `$_.Criteria` object and the
separate `Get-DnsServerClientSubnet` object). So the plain `Get-*` output is
NOT a usable input and is out of scope; feed the `Add-*` cmdlets (from your
provisioning repo) or a `Get-*` dump expanded to the `Add-*` form. Feeding an
out-of-scope format is SAFE: it matches no detector, parses to zero rules, and
the gate fails closed (exit 2) — never a false clean audit.

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

# Boolean/operator tokens of the -ClientSubnet criterion language. A leading one
# is the expression's operator (EQ / NE / GT / LT ...); one appearing in the
# MEMBER position (e.g. the "NE" in "EQ,Corp,NE,Guest") means the expression is a
# multi-criterion boolean, not a single subnet name — so it is widened to ANY +
# imprecise, but the NOTE must call it an operator, not an "undefined subnet".
_CLIENTSUBNET_OPS = frozenset({"EQ", "NE", "AND", "OR", "GT", "LT", "GE", "LE"})

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
                 imprecise_subnets: frozenset,
                 policy: str, notes: List[str]) -> List[Tuple[_IPNet, bool]]:
    """Map a -ClientSubnet expression to a list of (src_net, imprecise) entries.

    EQ over defined names -> one exact (cidr, False) per member CIDR (OR of the
    members). NE (negation), an undefined member, a boolean operator in the
    member position, an empty/unknown expression, or a non-EQ/NE operator (GT/LT
    time forms, etc.) -> widen to ANY of BOTH families with imprecise=True (a
    set-complement / unresolved reference is not one rectangle; over-approximate,
    never narrow). A member whose client-subnet name is in `imprecise_subnets`
    (ambiguous membership: redefined, non-REPLACE Set, or Set with no prior Add)
    keeps its CIDR but is flagged imprecise so its ACEs cannot over-cover."""
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
        if nm.upper() in _CLIENTSUBNET_OPS:
            # An operator token where a member name was expected -> the whole
            # expression is a compound/boolean criterion (e.g. "EQ,Corp,NE,Guest"),
            # not one subnet rectangle. Widen + imprecise, with an accurate note.
            notes.append(
                f"msdns policy '{policy}': compound/boolean client-subnet "
                f"expression (operator '{nm}' in member position: "
                f"{op},{','.join(names)}) is not a single subnet — src widened "
                f"to ANY + imprecise (fail-closed; verify manually)")
            return widened
        cidrs = subnets.get(nm.lower())
        if not cidrs:
            notes.append(
                f"msdns policy '{policy}': references undefined client-subnet "
                f"'{nm}' — src cannot be resolved; widened to ANY + imprecise "
                f"(fail-closed; verify manually)")
            return widened
        ambiguous = nm.lower() in imprecise_subnets
        if ambiguous:
            notes.append(
                f"msdns policy '{policy}': references client-subnet '{nm}' whose "
                f"true membership is ambiguous (redefined / non-REPLACE Set / Set "
                f"with no prior Add) — ACEs flagged imprecise so a deny cannot "
                f"over-cover (fail-closed; verify manually)")
        for c in cidrs:
            entries.append((c, ambiguous))
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
    subnet_added: set = set()               # names that have been Add-ed
    imprecise_subnets: set = set()          # names whose membership is ambiguous
    # policies keyed by name_lower for Set/Add upsert; each carries its params.
    policies: Dict[str, dict] = {}
    order_counter = 0                       # first-seen insertion rank

    for line, logical in _join_continuations(text):
        if not logical or logical.lstrip().startswith("#"):
            continue
        m = _DEFINE_RE.match(logical)
        if not m:
            continue  # Get-/Remove- and unrelated lines define no state here.
        verb = m.group("verb").lower()      # "add" or "set"
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
            key = name.lower()
            if verb == "add":
                cidrs = _resolve_subnet_cidrs(d, name, notes)
                if key in subnet_added:
                    # A SECOND Add of the same name: real Windows REJECTS the
                    # duplicate (the first definition stays) — the true membership
                    # is ambiguous from the config, so any policy referencing it
                    # must be imprecise (a deny of the wrong CIDR would over-cover
                    # and false-PASS). Keep the FIRST definition; do not overwrite.
                    imprecise_subnets.add(key)
                    notes.append(
                        f"msdns client-subnet '{name}' Add-ed more than once — "
                        f"Windows rejects the duplicate (first definition stays); "
                        f"membership ambiguous; referencing policies flagged "
                        f"imprecise (fail-closed; verify manually)")
                else:
                    subnets[key] = cidrs
                    subnet_added.add(key)
            else:  # Set-DnsServerClientSubnet
                if key not in subnet_added:
                    # Set on a name never Add-ed: real Windows ERRORS (no such
                    # object). No subnet is defined; a referencing policy cannot
                    # resolve it -> imprecise (widened to ANY at emit time).
                    imprecise_subnets.add(key)
                    notes.append(
                        f"msdns Set-DnsServerClientSubnet '{name}' with no prior "
                        f"Add — Windows errors (no such client-subnet); membership "
                        f"undefined; referencing policies flagged imprecise "
                        f"(fail-closed; verify manually)")
                else:
                    sub_action = (_scalar(d, "action") or "REPLACE").upper()
                    if sub_action in ("ADD", "REMOVE"):
                        # -Action ADD appends / REMOVE deletes members; the result
                        # is not exactly modelable from the config (REMOVE cannot
                        # be applied to a superset). Keep the existing definition;
                        # imprecise makes any referencing verdict indeterminate.
                        imprecise_subnets.add(key)
                        notes.append(
                            f"msdns Set-DnsServerClientSubnet '{name}' -Action "
                            f"{sub_action} modifies membership (not a REPLACE) — "
                            f"not exactly modelable; referencing policies flagged "
                            f"imprecise (fail-closed; verify manually)")
                    else:  # REPLACE (the default) — modelable exactly
                        subnets[key] = _resolve_subnet_cidrs(d, name, notes)
        else:  # queryresolutionpolicy
            if name is None:
                notes.append(f"msdns Add/Set-DnsServerQueryResolutionPolicy at "
                             f"line {line} has no -Name (skipped; verify manually)")
                continue
            key = name.lower()
            if key not in policies:
                policies[key] = {"name": name, "rank": order_counter,
                                 "params": {}, "line": line, "added": False}
                order_counter += 1
            if verb == "add":
                policies[key]["added"] = True
            # Merge params (Set updates an existing policy in place).
            policies[key]["params"].update(d)
            policies[key]["line"] = line

    # Order by -ProcessingOrder ascending; policies without one sort AFTER the
    # explicitly-ordered ones (matching the cmdlet's auto-assign behavior), with
    # first-seen rank as a stable tiebreak.
    ordered = []
    explicit_order_groups: Dict[int, List[dict]] = {}
    for pol in policies.values():
        po = _scalar(pol["params"], "processingorder")
        order_val = _BIG_ORDER
        pol["order_collision"] = False
        if po is not None:
            try:
                order_val = int(po)
                explicit_order_groups.setdefault(order_val, []).append(pol)
            except ValueError:
                notes.append(f"msdns policy '{pol['name']}': non-integer "
                             f"-ProcessingOrder '{po}' — placed after ordered "
                             f"policies (verify manually)")
        ordered.append((order_val, pol["rank"], pol))

    # Two or more policies with the SAME explicit -ProcessingOrder: real Windows
    # keeps ProcessingOrder UNIQUE at runtime (inserting a policy SHIFTS the
    # existing ones), so the config text does NOT determine their relative
    # first-match order. Tiebreaking by text order would let the verdict flip on
    # authoring order (deny-first PASSes, allow-first violates) — mark EVERY
    # colliding policy imprecise so the outcome is honestly indeterminate.
    for ov, group in explicit_order_groups.items():
        if len(group) >= 2:
            for p in group:
                p["order_collision"] = True
            names_ = ", ".join(p["name"] for p in group)
            notes.append(
                f"msdns policies [{names_}] share -ProcessingOrder {ov} — Windows "
                f"assigns each policy a UNIQUE runtime order (a new insert shifts "
                f"existing ones), so their relative first-match order is not "
                f"determined by the config text; all flagged imprecise "
                f"(fail-closed; verify manually)")

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

        # A policy defined ONLY by Set (never Add-ed): real Windows errors on a
        # Set of a non-existent policy, so NO rule is created and clients fall
        # through to the default-ALLOW. Synthesizing a confident rule here would
        # certify isolation that does not exist — model it imprecise (fail-closed).
        if not pol.get("added"):
            base_imprecise = True
            notes.append(
                f"msdns policy '{pname}': defined only by Set with no prior Add — "
                f"Windows errors on Set of a non-existent policy (no rule is "
                f"created; clients fall through to the default-ALLOW); flagged "
                f"imprecise so isolation is never falsely certified (fail-closed).")

        # Colliding -ProcessingOrder (see above): relative first-match order is
        # not knowable from the config, so the verdict must not depend on it.
        if pol.get("order_collision"):
            base_imprecise = True

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
            src_entries = _src_entries(op, names, subnets,
                                       frozenset(imprecise_subnets), pname, notes)

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
