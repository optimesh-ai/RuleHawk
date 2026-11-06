"""Parse Palo Alto Networks PAN-OS security policy (set-format) into `ACE`s.

Why PAN-OS is the next vendor (RH-4): the engine downstream of parsing
(`analyze.py`, `segcheck.py`, `model.ACE`) reasons about ORDERED, first-match
`permit`/`deny` rules over an (proto, src-net, dst-net, src-port, dst-port)
packet space. A PAN-OS *security rulebase* is exactly that shape: one globally
ordered list of rules, evaluated top-to-bottom, first match wins, each with a
terminating action (`allow` -> permit; `deny`/`drop`/`reset-*` -> deny). So the
whole existing analysis (the product's real IP) is reused unchanged — this module
only adds a new *frontend* that emits the same `(List[ACE], notes)` IR.

AWS Security Groups (added later, see parse_awssg.py) are stateful, allow-only
and ORDER-INDEPENDENT. That kills intent-inversion for them — with no deny, no
rule can invert another's intent — but NOT the rest: an allow-only,
order-independent ruleset is exactly equivalent to permits terminated by the
implicit default-deny, so segmentation is exact and least-privilege analysis
(`0.0.0.0/0` on 22/3389/3306) is the most valuable thing to run on one. PAN-OS
was still the right next step at the time: it is the highest enterprise
buyer-pull vendor, Palo Alto is the #1 enterprise
firewall vendor by revenue, and its buyers carry the same PCI/zone
segmentation-audit need that drives Config Studio — the natural lead-magnet pull.

THE SOUNDNESS LINE (the RH-3 lesson, applied to PAN-OS). PAN-OS rules are
ZONE-aware and APPLICATION-aware (layer 7). RuleHawk models the L3/L4 packet
space only, so a rule that constrains its match by a specific `from`/`to` zone,
a specific `application`, `application-default` service, an unresolved
object/group, or a `negate-*` flag is OVER-APPROXIMATED (we model a superset of
the real traffic). Such a rule is marked `imprecise` and SURFACED as a parse
note: it is never used to prove another rule dead (covers() refuses it) and in
segmentation it yields an honest "indeterminate / review manually" instead of a
possibly-wrong verdict. Rules expressed purely in L3/L4 terms (any zones, any
application, concrete addresses + a concrete service) get RuleHawk's full
shadow/segmentation analysis. Nothing is ever silently dropped.

PARTIAL PRECISION (the Junos/objgroup pattern, applied to PAN-OS addresses).
A source/destination list mixing resolved members (address objects, static
groups, literal CIDRs) with unresolvable ones (fqdn, ip-wildcard, dynamic
groups, undefined names) must NOT collapse to "the resolved subset, marked
imprecise": the modeled space would be a SUBSET of the real match, breaking the
over-approximation invariant above (a segmentation PASS could be false). When
the ONLY imprecision source is unresolved src/dst names, the rule is expanded
into EXACT ACEs for the resolved members (they can prove a CRITICAL) plus ONE
trailing opaque any/any imprecise ACE covering the unresolved remainder (it
keeps the remainder INDETERMINATE — never PASS, never a false CRITICAL). Any
other imprecision source (zones, application, negate-*, service) taints every
combo, so the whole rule stays imprecise as before — with the unresolved
dimension widened to ANY (superset), never kept as the resolved subset.

Scope (minimal but correct): the `set`-display form (`set ... rulebase security
rules NAME ...`, fields possibly split across lines), with `set address` /
`set address-group static` / `set service` object resolution. Modeled rule
fields: from, to, source, destination, application, service, action, disabled.
Everything else (zones' effect, L7 application, dynamic groups, service-groups,
fqdn/ip-wildcard addresses, application-default, unknown actions, the XML config
form) is SURFACED as a parse note.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, _PORTED, PortRange, _IPNet
from .parse import _port_num  # reuse the Cisco/IANA service-name -> port map

_ANY_NET: _IPNet = ipaddress.ip_network("0.0.0.0/0")

# PAN-OS terminating actions -> RuleHawk action. allow => permit; deny/drop and
# the reset-* family (drop + TCP reset) all => deny.
_ACTION = {"allow": "permit", "deny": "deny", "drop": "deny",
           "reset-client": "deny", "reset-server": "deny", "reset-both": "deny"}

# Built-in PAN-OS predefined services with well-known L4 ports. The predefined
# service-http is tcp 80 AND 8080 (both ports, per PAN-OS) — modeling only 80
# would hide an 8080 leak.
_BUILTIN_SERVICES: Dict[str, Tuple[str, List[PortRange], List[PortRange]]] = {
    "service-http": ("tcp", [PortRange(80, 80), PortRange(8080, 8080)], [ANY_PORTS]),
    "service-https": ("tcp", [PortRange(443, 443)], [ANY_PORTS]),
}

# Security-rule fields, as an ALLOWLIST. A field outside all three sets is
# one RuleHawk knows nothing about: it may narrow the rule's match (a 5G
# subscriber or slice, say), so it gets a parse note, which blocks every
# PASS on the file. Never consume an unknown field silently.
#
# Modelled: they decide the ACEs a rule becomes.
_MODELLED_FIELDS = frozenset({
    "from", "to", "source", "destination", "application", "service", "action",
    "disabled", "negate-source", "negate-destination",
})
# Consumed but not modelled; failclosed.panos-unmodeled-rule-field blocks the
# PASS whenever one carries a value other than any.
_BLOCKED_FIELDS = frozenset({
    "source-user", "schedule", "category", "source-hip", "destination-hip",
    "hip-profiles", "source-device", "destination-device", "rule-type", "target",
})
# Known harmless: none changes which packets the rule matches or its action.
_HARMLESS_FIELDS = frozenset({
    "description",        # free text
    "tag", "group-tag",   # labels for grouping and display
    "uuid",               # the rule's identifier
    "log-start", "log-end", "log-setting",   # logging only
    "icmp-unreachable",   # what a deny/drop sends back; the match is unchanged
    "qos",                # marks traffic the rule already allowed
    # disables inspection of server-to-client traffic: it can only drop less
    "option", "disable-server-response-inspection",
    # Security profiles inspect traffic the rule allows and can drop more of
    # it, never less, so they cannot make an isolation PASS false. They CAN
    # make a connectivity OK false: failclosed blocks that with
    # panos-security-profile.
    "profile-setting",
})
_RULE_FIELDS = _MODELLED_FIELDS | _BLOCKED_FIELDS | _HARMLESS_FIELDS

# Container fields whose value is a short path, not one token.
_PROFILE_TYPES = frozenset({"virus", "spyware", "vulnerability", "url-filtering",
                            "file-blocking", "wildfire-analysis", "data-filtering"})
_QOS_MARKING = {"ip-dscp": 1, "ip-precedence": 1, "follow-c2s-flow": 0}
_TARGET_SUBS = frozenset({"devices", "negate", "tags"})

# Cap the cartesian expansion of one rule so a pathological config can't blow up;
# beyond it we widen every dimension to ANY (a superset) and mark the entry
# imprecise (+ a note) — never truncate to a subset (mirrors the Junos frontend).
_MAX_EXPAND = 256


def detect(text: str) -> bool:
    """Heuristic: does `text` look like a PAN-OS set-format security policy?

    Requires a `set` statement plus the `... security rules` anchor, which a
    Cisco ACL and a Junos firewall filter both lack — so neither is misrouted.
    """
    return bool(
        re.search(r"(?m)^\s*set\b", text)
        and re.search(r"\b(?:rulebase|pre-rulebase|post-rulebase)\s+security\s+rules\b",
                      text)
    )


# --- tokenizer -------------------------------------------------------------

def _tok(line: str) -> List[str]:
    """Tokenize one set-format line; honor double-quoted names with spaces.

    PAN-OS bracket lists are space-separated (`[ A B ]`), so `[`/`]` survive as
    their own tokens. shlex handles the quoting; fall back to a plain split."""
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        return line.split()


def _one(toks: List[str], i: int) -> "Tuple[List[str], int]":
    """One value: a single token or a `[ ... ]` list (PAN-OS takes no other
    form: several values need the brackets)."""
    n = len(toks)
    if i >= n:
        return [], i
    if toks[i] == "[":
        vals: List[str] = []
        i += 1
        while i < n and toks[i] != "]":
            vals.append(toks[i])
            i += 1
        return vals, i + 1                       # skip the closing ]
    return [toks[i]], i + 1


def _container(key: str, toks: List[str], i: int) -> "Tuple[List[str], int, bool]":
    """(values, next index, well-formed) for qos / option / profile-setting /
    target, whose value is a short path such as `marking ip-dscp ef`."""
    n = len(toks)
    vals: List[str] = []
    if key == "qos":
        if i < n and toks[i] == "marking" and i + 1 < n and toks[i + 1] in _QOS_MARKING:
            want = _QOS_MARKING[toks[i + 1]]
            vals, i = toks[i:i + 2], i + 2
            if want:
                v, i = _one(toks, i)
                vals += v
                return vals, i, bool(v)
            return vals, i, True
        return vals, i, False
    if key == "option":
        if i < n and toks[i] == "disable-server-response-inspection":
            v, j = _one(toks, i + 1)
            return [toks[i]] + v, j, bool(v)
        return vals, i, False
    if key == "profile-setting":
        if i < n and toks[i] == "group":
            v, j = _one(toks, i + 1)
            return ["group"] + v, j, bool(v)
        if i < n and toks[i] == "profiles":
            i += 1
            vals = ["profiles"]
            ok = False
            while i < n and toks[i] in _PROFILE_TYPES:
                v, i2 = _one(toks, i + 1)
                if not v:
                    return vals, i2, False
                vals += [toks[i]] + v
                i, ok = i2, True
            return vals, i, ok
        return vals, i, False
    # target
    ok = False
    while i < n and toks[i] in _TARGET_SUBS:
        v, i2 = _one(toks, i + 1)
        if not v:
            return vals, i2, False
        vals += [toks[i]] + v
        i, ok = i2, True
    return vals, i, ok


_CONTAINERS = frozenset({"qos", "option", "profile-setting", "target"})


def _read_fields(toks: List[str], unknown: Optional[List[str]] = None
                 ) -> "Dict[str, List[str]]":
    """Parse a `key val | key [ v1 v2 ] | key a b c` body into key->values.

    Each field takes ONE value or a `[ ]` list, except the container fields,
    which take their short path. A field name not on the allowlist, or a
    container whose path RuleHawk does not recognise, is appended to
    `unknown` (the caller notes it); its value is consumed so it is never
    misread as the next field."""
    out: Dict[str, List[str]] = {}
    i, n = 0, len(toks)
    while i < n:
        key = toks[i]
        i += 1
        if key in _CONTAINERS:
            vals, i, ok = _container(key, toks, i)
            if not ok and unknown is not None:
                unknown.append(f"{key} {' '.join(vals)}".strip())
        else:
            vals, i = _one(toks, i)
            if key not in _RULE_FIELDS and unknown is not None:
                unknown.append(key)
        out.setdefault(key, []).extend(vals)
    return out


# --- object definitions ----------------------------------------------------

def _parse_portspec(spec: str, label: str, key: str,
                    notes: List[str]) -> Tuple[List[PortRange], bool]:
    """Parse a PAN-OS port spec (`80`, `80,443`, `8080-8090`, mixed). Returns
    (ranges, imprecise). An unparsable component flips imprecise + a note so an
    all-bad spec can never widen to ANY and silently prove a later rule dead."""
    ranges: List[PortRange] = []
    imprecise = False
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part and not part.startswith("-"):
            lo, hi = part.split("-", 1)
            ln, hn = _port_num(lo), _port_num(hi)
            if ln < 0 or hn < 0:
                imprecise = True
                notes.append(f"unparsed PAN-OS {key} '{part}' in {label} "
                             f"(marked imprecise — verify manually)")
                continue
            ranges.append(PortRange(min(ln, hn), max(ln, hn)))
        else:
            p = _port_num(part)
            if p < 0:
                imprecise = True
                notes.append(f"unparsed PAN-OS {key} '{part}' in {label} "
                             f"(marked imprecise — verify manually)")
                continue
            ranges.append(PortRange(p, p))
    return ranges, imprecise


# Where an object may be defined: the firewall itself, `shared`, a vsys or a
# Panorama device-group. Objects are resolved by name; a name defined in more
# than one of these scopes is ambiguous (a vsys1 rule sees vsys1's object, a
# vsys2 rule vsys2's), and RuleHawk does not resolve per scope, so the name is
# treated as unresolvable (imprecise) and noted: failclosed blocks the PASS
# with object-scope-ambiguous.
def _object_scope(prefix: List[str]) -> Optional[str]:
    """The scope a `set <prefix> address ...` line defines its object in, or
    None when the prefix is not one RuleHawk recognises."""
    if not prefix:
        return ""
    if prefix == ["shared"]:
        return "shared"
    if len(prefix) == 2 and prefix[0] in ("vsys", "device-group"):
        return f"{prefix[0]} {prefix[1]}"
    return None


# Object attributes that do not change the object's value.
_OBJECT_HARMLESS = frozenset({"description", "tag", "disable-override"})


# Address and address-group names share one namespace, as do service and
# service-group names: a rule's `source CORP` can mean either kind, so a name
# is ambiguous when it is defined as more than one (kind, scope) pair (review
# of #42, round 4, R3).
_NAMESPACE = {"address": "addr", "address-group": "addr",
              "service": "svc", "service-group": "svc"}


def _collect_objects(numbered: "List[Tuple[int, List[str]]]", notes: List[str],
                     consumed: Optional[set] = None,
                     scope_map: Optional[dict] = None) -> Tuple[
        Dict[str, Optional[Tuple[List[_IPNet], bool]]],
        Dict[str, Optional[List[str]]],
        Dict[str, Optional[Tuple[str, List[PortRange], List[PortRange]]]]]:
    """First pass: build address, address-group and service maps.

    Map value `None` means the object is KNOWN but cannot be reduced to an exact
    L3/L4 space (fqdn, ip-wildcard, dynamic group, service-group); referencing it
    marks the rule imprecise rather than guessing.
    """
    addresses: Dict[str, Optional[Tuple[List[_IPNet], bool]]] = {}
    addr_groups: Dict[str, Optional[List[str]]] = {}
    services: Dict[str, Optional[Tuple[str, List[PortRange], List[PortRange]]]] = dict(
        _BUILTIN_SERVICES)
    # Repeated `set service NAME protocol P port ...` lines APPEND on the device
    # (a `set` on a list node adds a member); last-wins would model a SUBSET of
    # the ports the service matches (dropping one false-PASSes a must_not_reach on
    # it). Accumulate each service's definition tokens across lines and parse the
    # UNION once, mirroring the address-group member accumulation above.
    service_defs: "Dict[str, List[str]]" = {}
    if consumed is None:
        consumed = set()
    # (namespace, name) -> {(kind, scope)}; handed back through `scope_map`
    # so the caller can check each rule sees the objects it names.
    scopes: "Dict[Tuple[str, str], set]" = {} if scope_map is None else scope_map

    def _take(lineno: int, kind: str, name: str, prefix: List[str]) -> None:
        consumed.add(lineno)
        scopes.setdefault((_NAMESPACE[kind], name), set()).add(
            (kind, _object_scope(prefix)))

    for lineno, toks in numbered:
        if not toks or toks[0] != "set":
            continue
        # `set [shared | vsys X | device-group Y] address NAME ...`: the object
        # keyword must follow a recognised scope prefix, else the line is not
        # an object definition RuleHawk reads (and is noted as unmodelled).
        kw = next((k for k, t in enumerate(toks[1:4], 1)
                   if t in ("address", "address-group", "service", "service-group")
                   and _object_scope(toks[1:k]) is not None), None)
        if kw is None:
            continue
        if toks[kw] == "address":
            k = kw
            if k + 2 < len(toks):
                name, kind = toks[k + 1], toks[k + 2]
                rest = toks[k + 3:]
                if kind in _OBJECT_HARMLESS:
                    _take(lineno, "address", name, toks[1:k])
                    continue
                if kind in ("fqdn", "ip-wildcard") or (
                        kind in ("ip-netmask", "ip-range") and rest):
                    _take(lineno, "address", name, toks[1:k])
                if kind == "ip-range" and rest and "-" not in rest[0]:
                    addresses[name] = None
                    notes.append(f"unparsed PAN-OS address '{name}' "
                                 f"ip-range '{rest[0]}' (referencing rule imprecise)")
                elif kind == "ip-netmask" and rest:
                    try:
                        # ip_network() on a bare address yields the host route
                        # (/32 for v4, /128 for v6) — never widen v6 to a /32.
                        addresses[name] = ([ipaddress.ip_network(
                            rest[0], strict=False)], False)
                    except ValueError:
                        addresses[name] = None
                        notes.append(f"unparsed PAN-OS address '{name}' "
                                     f"ip-netmask '{rest[0]}' (referencing rule imprecise)")
                elif kind == "ip-range" and rest and "-" in rest[0]:
                    lo, hi = rest[0].split("-", 1)
                    try:
                        nets = list(ipaddress.summarize_address_range(
                            ipaddress.ip_address(lo.strip()),
                            ipaddress.ip_address(hi.strip())))
                        addresses[name] = (nets, False)   # exact CIDR cover
                    except (ValueError, TypeError):
                        addresses[name] = None
                        notes.append(f"unparsed PAN-OS address '{name}' "
                                     f"ip-range '{rest[0]}' (referencing rule imprecise)")
                elif kind in ("fqdn", "ip-wildcard"):
                    addresses[name] = None
                    notes.append(f"unmodeled PAN-OS address '{name}' ({kind}) — "
                                 f"no fixed L3 space; referencing rule marked imprecise")
                continue
            continue
        if toks[kw] == "address-group":
            k = kw
            if k + 2 < len(toks):
                name = toks[k + 1]
                if toks[k + 2] in _OBJECT_HARMLESS:
                    _take(lineno, "address-group", name, toks[1:k])
                    continue
                if toks[k + 2] not in ("static", "dynamic"):
                    continue                           # unmodelled: noted
                _take(lineno, "address-group", name, toks[1:k])
                if toks[k + 2] == "static":
                    # Repeated `set address-group G static ...` lines APPEND
                    # (exports commonly emit one member per line); overwriting
                    # would model a subset of the group. A group already marked
                    # unresolvable (None) stays unresolvable (superset).
                    members = [t for t in toks[k + 3:] if t not in ("[", "]")]
                    prev = addr_groups.get(name)
                    if isinstance(prev, list):
                        prev.extend(members)
                    elif name not in addr_groups:
                        addr_groups[name] = members
                else:                                  # dynamic
                    addr_groups[name] = None
                    notes.append(f"unmodeled PAN-OS dynamic address-group "
                                 f"'{name}' — referencing rule marked imprecise")
            continue
        if toks[kw] == "service":
            k = kw
            if k + 2 < len(toks) and toks[k + 2] in _OBJECT_HARMLESS:
                _take(lineno, "service", toks[k + 1], toks[1:k])
                continue
            if k + 2 < len(toks) and toks[k + 2] == "protocol":
                name = toks[k + 1]
                _take(lineno, "service", name, toks[1:k])
                # Concatenate this line's `protocol ... port ...` segment onto any
                # prior lines for the same service; _parse_service_def then unions
                # every `port` spec (and keeps a single protocol per service).
                service_defs.setdefault(name, []).extend(toks[k + 2:])
            continue
        if toks[kw] == "service-group":
            k = kw
            if k + 1 < len(toks):
                _take(lineno, "service-group", toks[k + 1], toks[1:k])
                notes.append(f"unmodeled PAN-OS service-group '{toks[k + 1]}' — "
                             f"referencing rule marked imprecise")
            continue

    # A name defined as more than one (kind, scope): resolve it to nothing
    # exact, whichever kind a rule would have picked.
    for (ns, name), where in sorted(scopes.items()):
        if len(where) < 2:
            continue
        defs = ", ".join(sorted(f"{k} in {w or 'firewall'}" for k, w in where))
        notes.append(f"PAN-OS object '{name}' is defined more than once "
                     f"({defs}) — objects are not resolved per kind and vsys / "
                     f"device-group, so '{name}' is treated as unresolved "
                     f"(object-scope-ambiguous)")
        if ns == "addr":
            addresses[name] = None
            addr_groups[name] = None
        else:
            service_defs.pop(name, None)
            services[name] = None

    # Parse each service's accumulated definition once (union of all its port
    # members across lines). A user redefinition overrides a same-named builtin.
    for name, deftoks in service_defs.items():
        services[name] = _parse_service_def(deftoks, name, notes)
    return addresses, addr_groups, services


def _parse_service_def(toks: List[str], name: str, notes: List[str]
                       ) -> Tuple[str, List[PortRange], List[PortRange]]:
    """Parse `protocol <tcp|udp|...> [port SPEC] [source-port SPEC]`."""
    proto = "ip"
    dports: List[PortRange] = []
    sports: List[PortRange] = []
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t == "protocol" and i + 1 < n:
            proto = toks[i + 1].lower()
            i += 2
        elif t == "port" and i + 1 < n:
            rs, _ = _parse_portspec(toks[i + 1], f"service {name}", "port", notes)
            dports += rs
            i += 2
        elif t == "source-port" and i + 1 < n:
            rs, _ = _parse_portspec(toks[i + 1], f"service {name}", "source-port", notes)
            sports += rs
            i += 2
        else:
            i += 1
    return proto, (dports or [ANY_PORTS]), (sports or [ANY_PORTS])


# --- address resolution ----------------------------------------------------

def _resolve_name(name: str,
                  addresses: Dict[str, Optional[Tuple[List[_IPNet], bool]]],
                  addr_groups: Dict[str, Optional[List[str]]],
                  seen: frozenset, label: str, dim: str,
                  notes: List[str]) -> Tuple[List[_IPNet], bool, bool]:
    """Resolve one source/destination token to (nets, imprecise, has_unresolved).

    Objects and static groups (unioned, recursively) resolve exactly; anything
    unresolved over-approximates and flips imprecise — surfaced, never dropped.

    *has_unresolved* is True ONLY when the value (or a group member) could not
    be reduced to concrete nets — fqdn/ip-wildcard/dynamic-group/undefined name/
    circular group. The caller uses it to apply the partial-precision pattern
    (exact ACEs for resolved members + one opaque ACE for the unresolved
    remainder), mirroring parse_junos._addrs."""
    if name in seen:
        notes.append(f"circular PAN-OS address-group '{name}' in {label} {dim} "
                     f"(marked imprecise)")
        return [], True, True
    if name in addresses:
        e = addresses[name]
        if e is None:
            return [], True, True                  # known-but-inexact (note already emitted)
        return list(e[0]), e[1], False
    if name in addr_groups:
        members = addr_groups[name]
        if members is None:
            return [], True, True                  # dynamic group (note already emitted)
        nets: List[_IPNet] = []
        imp = False
        unres = False
        for m in members:
            ns, e, u = _resolve_name(m, addresses, addr_groups, seen | {name},
                                     label, dim, notes)
            nets += ns
            imp |= e
            unres |= u
        return nets, imp, unres
    try:
        # ip_network() on a bare address yields the host route (/32 for v4,
        # /128 for v6) — never widen a bare v6 literal to a /32.
        return [ipaddress.ip_network(name, strict=False)], False, False
    except ValueError:
        notes.append(f"unresolved PAN-OS address object/value '{name}' in "
                     f"{label} {dim} (marked imprecise — verify manually)")
        return [], True, True


def _resolve_addrs(vals: List[str],
                   addresses: Dict[str, Optional[Tuple[List[_IPNet], bool]]],
                   addr_groups: Dict[str, Optional[List[str]]],
                   label: str, dim: str,
                   notes: List[str]) -> Tuple[List[_IPNet], bool, bool]:
    """Resolve a source/destination value list to (nets, imprecise, has_unresolved).

    Returns the RAW resolved nets (possibly empty when everything was
    unresolved); the caller widens an empty list to ANY. Keeping the raw list
    lets `_build_rule` distinguish "some members resolved" (partial precision
    applies) from "nothing resolved" (any-net fallback, fully imprecise)."""
    nets: List[_IPNet] = []
    imprecise = False
    has_unresolved = False
    for v in vals:
        if v == "any":
            nets.append(_ANY_NET)
            continue
        ns, imp, unres = _resolve_name(v, addresses, addr_groups, frozenset(),
                                       label, dim, notes)
        nets += ns
        imprecise |= imp
        has_unresolved |= unres
    return nets, imprecise, has_unresolved


# --- service resolution ----------------------------------------------------

def _resolve_service(vals: List[str],
                     services: Dict[str, Optional[Tuple[str, List[PortRange], List[PortRange]]]],
                     label: str,
                     notes: List[str]) -> Tuple[List[Tuple[str, PortRange, PortRange]], bool]:
    """Resolve the `service` field to a list of (proto, src_port, dst_port)
    combos to expand the rule over, plus an imprecise flag."""
    combos: List[Tuple[str, PortRange, PortRange]] = []
    imprecise = False
    if not vals:
        vals = ["any"]
    for v in vals:
        if v == "any":
            combos.append(("ip", ANY_PORTS, ANY_PORTS))
        elif v == "application-default":
            # Ports come from the matched L7 app's defaults — unknown to us.
            imprecise = True
            combos.append(("ip", ANY_PORTS, ANY_PORTS))
            notes.append(f"PAN-OS 'service application-default' in {label} — "
                         f"L7-derived ports not modeled (marked imprecise)")
        elif v in services and services[v] is not None:
            proto, dports, sports = services[v]
            if proto not in _PORTED and any(not p.is_any() for p in dports + sports):
                # covers()/segcheck ignore ports on a non-port-carrying protocol,
                # so the ACE would claim an exact all-ports space: widen + flag.
                imprecise = True
                combos.append((proto, ANY_PORTS, ANY_PORTS))
                notes.append(f"PAN-OS service '{v}' puts ports on non-port-carrying "
                             f"protocol '{proto}' in {label} — ports widened to ANY "
                             f"(marked imprecise — verify manually)")
            else:
                for sp in sports:
                    for dp in dports:
                        combos.append((proto, sp, dp))
        else:
            imprecise = True
            combos.append(("ip", ANY_PORTS, ANY_PORTS))
            notes.append(f"unresolved PAN-OS service '{v}' in {label} "
                         f"(marked imprecise — verify manually)")
    return combos, imprecise


# --- rule assembly ---------------------------------------------------------

def _raw(name: str, action: str, proto: str, s: _IPNet, d: _IPNet,
         sp: PortRange, dp: PortRange) -> str:
    parts = [f"rule {name}:", action, proto, str(s), "->", str(d)]
    if not sp.is_any():
        parts.append(f"sport {sp}")
    if not dp.is_any():
        parts.append(f"dport {dp}")
    return " ".join(parts)


def _build_rule(name: str, fields: "Dict[str, List[str]]", seq: int,
                addresses, addr_groups, services,
                entries: List[ACE], notes: List[str], line: int = 0,
                acl: str = "security") -> int:
    label = f"{acl}/{name}"

    # Scalar fields set on several lines follow `set` semantics: last wins.
    if fields.get("disabled", []) and fields["disabled"][-1].lower() == "yes":
        notes.append(f"PAN-OS rule {label} is disabled — skipped (not enforced)")
        return seq

    act_vals = fields.get("action", [])
    if not act_vals:
        notes.append(f"PAN-OS rule {label} has no action — skipped")
        return seq
    action = _ACTION.get(act_vals[-1].lower())
    if action is None:
        notes.append(f"unmodeled PAN-OS action '{act_vals[-1]}' in {label} — skipped")
        return seq

    imprecise = False

    # Zones: a specific from/to constrains the match in a dimension we don't
    # model -> over-approximation -> imprecise (the RH-3 line). `any` is exact.
    for zk in ("from", "to"):
        zvals = fields.get(zk, [])
        if zvals and any(z != "any" for z in zvals):
            imprecise = True
            notes.append(f"PAN-OS '{zk}' zone {[z for z in zvals if z != 'any']} "
                         f"in {label} not modeled (L3/L4 over-approximation — "
                         f"marked imprecise, used conservatively)")

    # Layer-7 application match is a narrowing we can't represent.
    app_vals = fields.get("application", [])
    if app_vals and any(a != "any" for a in app_vals):
        imprecise = True
        notes.append(f"PAN-OS application {[a for a in app_vals if a != 'any']} "
                     f"in {label} not modeled (L7 match — marked imprecise)")

    negate_src = negate_dst = False
    for nk in ("negate-source", "negate-destination"):
        if fields.get(nk, []) and fields[nk][-1].lower() == "yes":
            imprecise = True
            if nk == "negate-source":
                negate_src = True
            else:
                negate_dst = True
            notes.append(f"PAN-OS '{nk}' in {label} — rule matches the COMPLEMENT "
                         f"of the listed set; widened to any (marked imprecise)")

    srcs, imp_s, unres_s = _resolve_addrs(fields.get("source", ["any"]) or ["any"],
                                          addresses, addr_groups, label, "source", notes)
    dsts, imp_d, unres_d = _resolve_addrs(fields.get("destination", ["any"]) or ["any"],
                                          addresses, addr_groups, label, "destination", notes)

    # negate-source/destination: the rule matches the COMPLEMENT of the listed
    # set, so the listed nets are NOT a superset of the real match — keeping
    # them would UNDER-approximate and segcheck could skip the permit for a
    # probe outside the listed set (a false PASS). Widen the negated dimension
    # to ANY (ANY ⊇ complement restores the over-approximation invariant);
    # imprecise=True (set above) already blocks any false CRITICAL/deadness
    # proof. Mirrors parse_iptables, which leaves src/dst at ANY on `! -s/-d`.
    if negate_src:
        srcs, imp_s, unres_s = [_ANY_NET], False, False
    if negate_dst:
        dsts, imp_d, unres_d = [_ANY_NET], False, False
    combos, imp_v = _resolve_service(fields.get("service", []), services, label, notes)

    # Imprecision from ANY source other than unresolved src/dst names (zones,
    # application, negate-*, service, an over-approximated address entry) taints
    # every expanded combo, so partial precision is blocked — mirrors
    # parse_junos._Match.other_imprecise.
    other_imprecise = (imprecise or imp_v
                       or (imp_s and not unres_s) or (imp_d and not unres_d))
    imprecise = imprecise or imp_s or imp_d or imp_v

    has_resolved_src, has_resolved_dst = bool(srcs), bool(dsts)
    for nets, dim in ((srcs, "source"), (dsts, "destination")):
        if not nets and not (imp_s if dim == "source" else imp_d):
            # Nothing unresolved, yet no address: an EMPTY static address-group.
            # It was widened to an EXACT any, so a deny on it shadowed every
            # later rule (false PASS, false "permit never takes effect"). What
            # an empty group matches on the device is not modeled: widen to any
            # (a superset) and mark the rule imprecise so it never decides.
            imprecise = True
            notes.append(f"PAN-OS rule {label}: {dim} resolves to no address "
                         f"(empty address-group) — not modeled, widened to any "
                         f"and marked imprecise")
    if not srcs:                                   # all unresolved -> widen to ANY
        srcs = [_ANY_NET]
    if not dsts:
        dsts = [_ANY_NET]

    cap_exceeded = False
    if len(srcs) * len(dsts) * len(combos) > _MAX_EXPAND:
        # Truncating to the first value per dimension would model a SUBSET
        # (dropped members become invisible holes): widen everything instead.
        notes.append(f"PAN-OS rule {label} expands to >{_MAX_EXPAND} ACEs; widened "
                     f"to a single any/any ACE (superset) and marked imprecise "
                     f"— verify manually")
        srcs, dsts = [_ANY_NET], [_ANY_NET]
        combos = [("ip", ANY_PORTS, ANY_PORTS)]
        imprecise = True
        cap_exceeded = True

    # --- Partial-precision path (the parse_junos._parse_term pattern) ----------
    # When ≥1 source/destination value was unresolvable AND no other imprecision
    # source is present, emit EXACT ACEs for the resolved member combos PLUS one
    # opaque (any/any, imprecise=True) ACE for the unresolved remainder.
    #
    # Soundness contract (mirrors parse_junos / parse.py _resolve_nets_partial):
    #   (1) Resolved-member ACEs carry imprecise=False — their match space is
    #       EXACT and can prove a CRITICAL verdict.
    #   (2) Unresolved members can only EXPAND the rule's real match, never
    #       shrink it, so a CRITICAL proven from the resolved subset is correct.
    #   (3) The trailing opaque ACE keeps the unresolved portion INDETERMINATE —
    #       it can never produce a false PASS (it is never skipped as a
    #       candidate) nor a false CRITICAL (imprecise ⇒ no witness).
    #   (4) All-unresolved in a dimension: partial emission is blocked — the
    #       any-net fallback over-approximates and could invent a false CRITICAL.
    _do_partial = (
        (unres_s or unres_d)                       # at least one unresolved name
        and not other_imprecise                    # no other approximation source
        and not cap_exceeded                       # _MAX_EXPAND cap not hit
        and (not unres_s or has_resolved_src)      # partial src: resolved srcs exist
        and (not unres_d or has_resolved_dst)      # partial dst: resolved dsts exist
    )
    if _do_partial:
        n_precise = 0
        for proto, sp, dp in combos:
            ported = proto in _PORTED
            for s in srcs:
                for d in dsts:
                    seq += 1
                    n_precise += 1
                    entries.append(ACE(
                        seq=seq, action=action, proto=proto, src=s, dst=d,
                        src_port=sp if ported else ANY_PORTS,
                        dst_port=dp if ported else ANY_PORTS, icmp_type=None,
                        stateful=False, imprecise=False,
                        raw=_raw(name, action, proto, s, d,
                                 sp if ported else ANY_PORTS,
                                 dp if ported else ANY_PORTS),
                        acl=acl, line=line))
        # Trailing opaque ACE covers the unresolved-name remainder.
        seq += 1
        entries.append(ACE(
            seq=seq, action=action, proto="ip",
            src=_ANY_NET, dst=_ANY_NET, imprecise=True,
            raw=f"rule {name}: {action} ip any -> any (unresolved address remainder)",
            acl=acl, line=line))
        notes.append(
            f"PAN-OS rule {label}: partially resolved address references — "
            f"{n_precise} exact ACE(s) + 1 opaque for unresolved names"
        )
        return seq

    # Normal (non-partial) path. A dimension that contains unresolved names but
    # could not take the partial path (another imprecision source, the expansion
    # cap, or nothing resolved) is widened to ANY: keeping only the resolved
    # subset would UNDER-approximate the rule's real match (the unresolved
    # members add unknown space) and segcheck could skip the permit entirely —
    # a false PASS. ANY ⊇ real match restores the over-approximation invariant;
    # the rule is imprecise here, so ANY can never prove a violation or deadness.
    if unres_s:
        srcs = [_ANY_NET]
    if unres_d:
        dsts = [_ANY_NET]
    for proto, sp, dp in combos:
        ported = proto in _PORTED
        for s in srcs:
            for d in dsts:
                seq += 1
                entries.append(ACE(
                    seq=seq, action=action, proto=proto, src=s, dst=d,
                    src_port=sp if ported else ANY_PORTS,
                    dst_port=dp if ported else ANY_PORTS, icmp_type=None,
                    stateful=False, imprecise=imprecise,
                    raw=_raw(name, action, proto, s, d,
                             sp if ported else ANY_PORTS, dp if ported else ANY_PORTS),
                    acl=acl, line=line))
    return seq


# Top-level `set` subtrees that cannot change which security rule matches a
# packet or what it does, so their lines are consumed without a note. Each is
# justified; anything not listed is noted. The scope prefix (`shared`,
# `vsys X`, `device-group Y`) is stripped first.
_HARMLESS_SUBTREES = frozenset({
    # management plane: admin access, logging, reporting, certificates. None
    # of it is on the data path.
    "deviceconfig", "mgt-config", "admin-role", "local-user-database",
    "authentication-profile", "authentication-sequence", "certificate",
    "certificate-profile", "ssl-tls-service-profile", "server-profile",
    "log-settings", "reports", "report-group", "pdf-summary-report",
    "email-scheduler", "response-page", "display-name",
    # labels
    "tag",
    # Definitions a rule refers to by name. A rule naming a specific zone or
    # application is already imprecise (parse_panos), a rule with a schedule
    # or an external list is blocked or imprecise, and security profiles only
    # drop more of what a rule allows (connectivity OK is blocked separately
    # by panos-security-profile).
    "zone", "application", "application-group", "application-filter",
    "profiles", "profile-group", "schedule", "external-list",
    # Interfaces, routing and tunnels: every forwarded packet still crosses
    # the security rulebase, and the PASS states that routing and topology
    # are not evaluated.
    "network",
})


def _subtree(toks: List[str]) -> str:
    """The first keyword of a `set` line after its scope prefix."""
    i = 1
    if i < len(toks) and toks[i] == "shared":
        i += 1
    elif i + 1 < len(toks) and toks[i] in ("vsys", "device-group"):
        i += 2
    return toks[i] if i < len(toks) else ""


_MAX_LINE_NOTES = 20


def _note_unconsumed(numbered: "List[Tuple[int, List[str]]]", consumed: set,
                     notes: List[str]) -> None:
    """A note for every line no handler consumed. NAT rules get their own
    wording (failclosed also blocks them as nat-present)."""
    missed: List[Tuple[int, List[str]]] = []
    for lineno, toks in numbered:
        if lineno in consumed or not toks:
            continue
        if toks[0] == "set" and _subtree(toks) in _HARMLESS_SUBTREES:
            continue
        missed.append((lineno, toks))
    for lineno, toks in missed[:_MAX_LINE_NOTES]:
        text = " ".join(toks)
        if len(text) > 100:
            text = text[:97] + "..."
        if toks[0] == "set" and _subtree(toks).endswith("rulebase") and \
                len(toks) > 2 and "nat" in toks:
            notes.append(f"PAN-OS NAT rule (line {lineno}) not modeled — security "
                         f"rules match the pre-NAT address, so a translated "
                         f"flow is not checked: `{text}`")
        else:
            notes.append(f"unmodeled PAN-OS line {lineno}: `{text}` — RuleHawk "
                         f"reads only `set` object and security-rule lines, so "
                         f"it cannot tell what this line changes")
    if len(missed) > _MAX_LINE_NOTES:
        notes.append(f"... and {len(missed) - _MAX_LINE_NOTES} more unmodeled "
                     f"PAN-OS line(s)")


def _rule_anchor(toks: List[str]) -> int:
    """Index of `rules` in a `... rulebase security rules NAME ...` line, else -1."""
    for k in range(1, len(toks) - 1):
        if (toks[k] == "rules" and toks[k - 1] == "security"
                and toks[k - 2] in ("rulebase", "pre-rulebase", "post-rulebase")):
            return k
    return -1


# PAN-OS evaluates security rules pre-rulebase -> device-local rulebase ->
# post-rulebase (Panorama pushes pre/post around the firewall's own rules).
# `_PHASE_RANK` orders emitted ACEs by this real evaluation order; textual order
# is preserved WITHIN a phase.
_PHASE_OF = {"pre-rulebase": "pre", "rulebase": "main", "post-rulebase": "post"}
_PHASE_RANK = {"pre": 0, "main": 1, "post": 2}


def _rule_path(toks: List[str]) -> "Tuple[int, str, str]":
    """(anchor, phase, scope) for a security-rule line, else (-1, "", "").

    anchor = index of `rules`; phase in {pre, main, post} from the rulebase
    keyword; scope = the `vsys <name>` / `device-group <name>` the rulebase
    belongs to ("" for a firewall-global rulebase). Each scope is an INDEPENDENT
    first-match context (its own ACL), so same-named rules in different vsys /
    device-groups must never merge; phase only orders rules WITHIN one scope."""
    k = _rule_anchor(toks)
    if k < 0:
        return -1, "", ""
    phase = _PHASE_OF.get(toks[k - 2], "main")
    scope = ""
    # The path between `set` and the rulebase keyword (toks[k-2]) may carry a
    # `vsys <name>` or `device-group <name>` scope segment.
    j = 1
    while j + 1 < k - 2:
        if toks[j] in ("vsys", "device-group"):
            scope = toks[j + 1]
            break
        j += 1
    return k, phase, scope


def _visible_scopes(rule_scope: str) -> set:
    if not rule_scope:
        return {"", "shared"}
    return {f"vsys {rule_scope}", f"device-group {rule_scope}", "shared"}


def _check_visible(rule_scope: str, rule: str, fields: "Dict[str, List[str]]",
                   scope_map: dict, addr_groups: dict, notes: List[str]) -> None:
    """Note (object-scope-ambiguous) each object the rule names, directly or
    through a static group, that is defined only outside the rule's view.
    Names RuleHawk does not define (literals, `any`, builtins) are left to
    the resolver."""
    vis = _visible_scopes(rule_scope)
    todo = [("addr", v) for f in ("source", "destination") for v in fields.get(f, [])]
    todo += [("svc", v) for v in fields.get("service", [])]
    seen: set = set()
    while todo:
        ns, name = todo.pop()
        if (ns, name) in seen:
            continue
        seen.add((ns, name))
        where = scope_map.get((ns, name))
        if not where:
            continue
        if not any(w in vis for _, w in where):
            defs = ", ".join(sorted(f"{k} in {w or 'firewall'}" for k, w in where))
            notes.append(f"PAN-OS rule {rule} ({rule_scope or 'firewall'}) names "
                         f"'{name}', defined only outside its scope ({defs}) — "
                         f"not resolved (object-scope-ambiguous)")
            continue
        if ns == "addr" and isinstance(addr_groups.get(name), list):
            todo += [("addr", m) for m in addr_groups[name]]


def parse_panos(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse a PAN-OS set-format security policy; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation`
    consume the result unchanged. Rules are grouped by their `vsys`/`device-group`
    scope (each an INDEPENDENT first-match context, emitted as its own `acl`) and,
    within a scope, ordered pre-rulebase -> local rulebase -> post-rulebase (the
    real PAN-OS evaluation order), preserving textual order within a phase.
    """
    numbered = [(i, _tok(ln)) for i, ln in enumerate(text.splitlines(), 1)
                if ln.strip() and not ln.lstrip().startswith("#")]
    notes: List[str] = []
    entries: List[ACE] = []
    # Every line is consumed by a modelled handler or gets a note (review of
    # #42, round 3): a line skipped silently (a `delete`, an `edit` followed
    # by relative `set`s, a NAT rule) could change what the rulebase does.
    consumed: set = set()

    scope_map: dict = {}
    addresses, addr_groups, services = _collect_objects(numbered, notes, consumed,
                                                        scope_map)

    # Second pass: accumulate each rule's fields (split across lines) keyed by
    # (scope, phase, name) so same-named rules in different vsys / device-groups
    # or different rulebase phases never merge. We remember the source line of
    # each rule for the CI gate's diff annotations — preferring the line that
    # carries `action` (the rule's decisive line), else first appearance.
    Key = Tuple[str, str, str]                        # (scope, phase, name)
    order: List[Key] = []
    rules: "Dict[Key, Dict[str, List[str]]]" = {}
    rule_lines: Dict[Key, int] = {}
    for lineno, toks in numbered:
        if not toks or toks[0] != "set":
            continue
        k, phase, scope = _rule_path(toks)
        if k < 0 or k + 1 >= len(toks):
            continue
        consumed.add(lineno)
        name = toks[k + 1]
        key: Key = (scope, phase, name)
        if key not in rules:
            rules[key] = {}
            order.append(key)
        unknown: List[str] = []
        fields_here = _read_fields(toks[k + 2:], unknown)
        for u in unknown:
            notes.append(f"unmodeled PAN-OS rule field '{u}' in rule {name} "
                         f"(line {lineno}) — not modeled; RuleHawk cannot tell "
                         f"which packets the rule matches")
        for fk, vals in fields_here.items():
            rules[key].setdefault(fk, []).extend(vals)
        if "action" in fields_here or key not in rule_lines:
            rule_lines[key] = lineno

    # Each name a rule uses must be defined where the rule can see it: its own
    # vsys / device-group, then shared (a firewall rulebase sees the firewall
    # objects and shared). A name defined only elsewhere would resolve on the
    # device to something else, or not at all (round 4, R3).
    for key in order:
        _check_visible(key[0], key[2], rules[key], scope_map, addr_groups, notes)

    # Emit ordered per scope. Each scope is an independent first-match context
    # (its own `acl`, so segcheck searches it in isolation); WITHIN a scope rules
    # run pre-rulebase -> local rulebase -> post-rulebase, textual order kept
    # within a phase (stable sort). seq is 1-based per scope.
    scope_order: List[str] = []
    by_scope: "Dict[str, List[Key]]" = {}
    for key in order:
        scope = key[0]
        if scope not in by_scope:
            by_scope[scope] = []
            scope_order.append(scope)
        by_scope[scope].append(key)

    for scope in scope_order:
        acl = "security" if not scope else f"security/{scope}"
        seq = 0
        for key in sorted(by_scope[scope], key=lambda kk: _PHASE_RANK[kk[1]]):
            seq = _build_rule(key[2], rules[key], seq, addresses, addr_groups,
                              services, entries, notes, rule_lines.get(key, 0), acl)

    _note_unconsumed(numbered, consumed, notes)

    if not entries and re.search(r"<\s*(?:rulebase|security|entry)\b", text):
        notes.append("PAN-OS XML config detected but not yet supported — export "
                     "the set-format (`set cli config-output-format set`) to audit it.")
    return entries, notes
