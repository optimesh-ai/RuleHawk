"""Fail-closed verdicts: the UNKNOWN outcome and the reasons behind it.

The segmentation search (segcheck._search) answers one narrow question: does
any parsed rule context permit a packet in the asserted flow space? "No" is a
SEARCH RESULT. It is a verdict (PASS / connectivity OK) only when every
assumption it rests on holds for the config: the rules really are transit
packet filters on the path, nothing on the evaluated context was left
unmodeled, and no vendor default RuleHawk does not model decides the packets
the search let fall through.

This module states those assumptions, checks them against the config, and
names each one that fails with a machine-readable reason code. Any reason
turns a would-be PASS into UNKNOWN. A violation (a concrete permitted witness)
or a broken required flow stays a FAIL: over-blocking is the safe direction,
and a FAIL never certifies anything.

Vedu (2026-11-06): "RuleHawk never returns PASS/VERIFIED when: the search is
empty; any parse note exists on an object on the evaluated path; the ACL's
binding or role is unknown or is not a packet filter (vty, SNMP, route-map);
a vendor default it doesn't model applies (PAN-OS default-security-rules,
iptables chain policy); or an IOS numbered-ACL wildcard is ambiguous. Those
return UNKNOWN with the reason."

Conservative by construction:
  * a parse note ANYWHERE in the file counts as on the evaluated path (no
    attempt is made to prove a note off-path);
  * every ACL context the search consults must have a known transit role;
    one unknown or non-transit context is enough;
  * a vendor default is reported whenever the construct is present, except
    for the implicit end-of-list defaults, which are reported exactly when the
    search let part of the flow space fall through to them.

Reason codes are stable identifiers (kebab-case). The message is for humans
and may change.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------- #
# reason codes
# --------------------------------------------------------------------------- #
REASONS: Dict[str, str] = {
    # (a) empty search
    "no-rules-parsed":
        "no rules were parsed from the config, so nothing was searched",
    "no-transit-filter":
        "no rule context on the evaluated path is a known transit packet "
        "filter, so the search proved nothing about forwarded packets",
    "search-not-run":
        "the search did not run over any rule context for this assertion",
    # (b) parse notes
    "parse-note":
        "the parser left a note (a line it did not fully model, or a "
        "resolution it had to make) and RuleHawk cannot prove the note is off "
        "the evaluated path",
    # (c) binding and role
    "acl-role-unknown":
        "an ACL in the search has no recognised transit binding "
        "(no interface ip access-group / ipv6 traffic-filter / ASA "
        "access-group / Junos interface filter), so its role is unknown",
    "acl-not-packet-filter":
        "an ACL in the search is used only in a role that is not a transit "
        "packet filter (line vty access-class, SNMP, route-map, NAT, crypto, "
        "PBR, QoS, or a Junos lo0 control-plane filter)",
    "asa-security-levels":
        "the ASA nameif / security-level semantics (implicit permit from a "
        "higher to a lower security level on an interface with no ACL) are "
        "not modeled",
    "junos-srx-policies":
        "Junos SRX zone-based security policies are present and not modeled",
    "junos-logical-systems":
        "Junos logical systems are present; their filters are not kept as "
        "separate contexts",
    "junos-groups":
        "Junos configuration groups are present; inherited statements are "
        "not replayed",
    "iptables-host-chain-only":
        "only the iptables INPUT / OUTPUT host chains carry rules; they never "
        "see a forwarded (transit) packet",
    "aws-sg-binding-unknown":
        "an AWS security group's attachment (which network interfaces it "
        "filters, and with which other groups) is not in the input",
    # (d) vendor defaults RuleHawk does not model
    "panos-default-security-rules":
        "PAN-OS default-security-rules overrides are present and not modeled",
    "panos-implicit-default":
        "part of the flow space reaches the end of the PAN-OS rulebase, where "
        "the predefined intrazone-default (allow) / interzone-default (deny) "
        "rules decide it; zones are not modeled",
    "panos-security-profile":
        "a PAN-OS allow rule carries security profiles, which can drop traffic "
        "the rule permits; a connectivity OK cannot rest on the rule alone",
    "panos-unmodeled-rule-field":
        "a PAN-OS rule uses a match field RuleHawk consumes but does not "
        "model (source-user, schedule, category, HIP, device, rule-type, "
        "target)",
    "iptables-chain-policy-unset":
        "part of the flow space reaches the end of an iptables chain with no "
        "explicit policy; a base chain's kernel default is ACCEPT and a user "
        "chain returns to its caller",
    "iptables-proto-zero":
        "an iptables rule uses `-p 0`, which RuleHawk does not model",
    "ip6tables-family":
        "ip6tables rules are present; the address family of `any` and of the "
        "chain policies is not modeled reliably",
    "iptables-delete":
        "an iptables `-D` delete is present and not applied to the rule set",
    "ipv6-implicit-nd":
        "part of an IPv6 flow space reaches the end of a Cisco/Arista IPv6 "
        "ACL, where implicit neighbor-discovery permits apply before the "
        "implicit deny; they are not modeled",
    "icmpv6-canonicalisation":
        "an ICMP rule in an IPv6 context (`icmp` in an `ipv6 access-list`, "
        "ASA `icmp6`) is not canonicalised to ICMPv6",
    "tcp-established":
        "an `established` / `tcp-established` match is present; on the device "
        "it is a stateless ACK/RST bit test, not connection state",
    "l4-fragments":
        "a rule matches on layer-4 fields (ports, ICMP type, TCP flags); "
        "non-initial fragments carry no layer-4 header and their handling is "
        "not modeled",
    "ios-dynamic-entry":
        "an IOS lock-and-key `dynamic` entry is present and not modeled",
    "nftables-unsupported":
        "the input looks like an nftables ruleset, which RuleHawk does not "
        "read",
    "nftables-present":
        "nftables text is present next to the parsed rules; RuleHawk does not "
        "read nftables, whose chains can accept, drop or forward a packet "
        "before or after the parsed ones",
    "acl-binding-negated":
        "a filter binding is removed, reset or deactivated (`no` or "
        "`default` before `ip access-group`, `ipv6 traffic-filter` or "
        "`access-class`, a top-level `no interface` or `default interface`, "
        "Junos `inactive:` / "
        "`deactivate` / `delete` on an interface filter or a filter); the "
        "removal is not applied, so which interfaces are filtered is unknown",
    "nat-present":
        "NAT is configured (Cisco `ip nat` / `ipv6 nat` / `nat64`, ASA "
        "`nat`/`static`, PAN-OS NAT rulebase, Junos NAT, iptables nat table); "
        "addresses are checked before translation only, so a translated flow "
        "may reach the zone",
    "object-scope-ambiguous":
        "a PAN-OS object name is defined as more than one kind (address and "
        "address-group, service and service-group) or in more than one vsys / "
        "device-group / shared scope, or a rule names an object defined only "
        "outside its own vsys / device-group and shared; such a name is not "
        "resolved",
    "interface-feature-unmodeled":
        "a Cisco / Arista interface carries a line that is not on RuleHawk's "
        "allowlist of lines that cannot change a transit packet's fate (any "
        "other feature, any `default` form, any abbreviated keyword); what the "
        "line does to the packet is not modeled",
    "zone-firewall":
        "a zone-based firewall is configured (`zone security`, "
        "`zone-member security`, `zone-pair security`); zone policy drops or "
        "passes traffic independently of the interface ACLs and is not modeled",
    "stateful-inspection":
        "stateful inspection is configured (`ip inspect` / CBAC); it opens "
        "return-traffic holes in the interface ACLs and is not modeled",
    "qos-policy":
        "a `service-policy` applies a policy-map; its actions (drop, police, "
        "redirect) can discard or divert traffic and are not modeled",
    "policy-routing":
        "policy-based routing is configured (`ip policy route-map`, "
        "`ipv6 policy route-map`, `ip local policy`, `service-policy type pbr`); "
        "it can send traffic to another interface or Null0 and is not modeled",
    "mpls-forwarding":
        "MPLS or a pseudowire is configured (any `mpls ...` line such as "
        "`mpls ip` or `mpls label protocol`, `tag-switching`, `xconnect`, "
        "`l2vpn`, `pseudowire`); labelled or "
        "cross-connected traffic is not filtered by the IP ACLs modeled here",
    "reach-not-every-context":
        "one audited rule context permits the whole flow but another denies "
        "part of it; which contexts are on the path is not modelled, so "
        "connectivity is not proven",
    "acl-family-mismatch":
        "part of the flow space reaches the end of a rule context that has "
        "no rule of the packet's address family; such a context may not "
        "filter that family at all",
    # (e) IOS numbered-ACL masks
    "numbered-acl-mask-ambiguous":
        "a numbered `access-list N permit|deny` line without `extended` "
        "appears in a config with a PIX/ASA dialect marker, so its mask "
        "could be a netmask or an IOS wildcard",
    "ios-wildcard-all-ones":
        "an IOS ACL entry pairs a nonzero address with 255.255.255.255; as an "
        "IOS wildcard that matches any address, as a netmask it is one host, "
        "and RuleHawk will not pick a reading to prove a PASS",
    "acl-binding-undefined":
        "an interface or access-group is bound to an ACL with no parsed rule; "
        "on IOS a missing or empty ACL permits all traffic, so that path is "
        "unfiltered",
    "unfiltered-path":
        "traffic of this address family can cross the device without meeting "
        "any audited rule: an interface with no filter in either direction "
        "(a packet can enter and leave on it, e.g. between a primary and a "
        "secondary subnet), or one interface with no inbound filter and "
        "another with no outbound filter",
    "iptables-fragments":
        "an iptables rule matches ports or other L4 fields; a non-initial "
        "fragment carries no L4 header, never matches it and falls through to "
        "later rules or the chain policy",
    "pathground-witness-only":
        "Hammerhead proved one witness packet unreachable; that does not prove "
        "the rest of the violated flow space unreachable",
    "vendor-unknown":
        "the config's vendor label is not one RuleHawk has fail-closed checks "
        "for, so none of them ran",
    # the search itself
    "imprecise-rule":
        "a rule on the path uses a form RuleHawk over-approximates "
        "(neq / complex mask / unresolved group / unknown qualifier)",
    "search-budget":
        "the rule context is too complex to search exhaustively",
    "policy-error":
        "the assertion could not be evaluated because the policy is invalid",
}


@dataclass(frozen=True)
class Reason:
    code: str
    detail: str = ""

    def to_dict(self) -> dict:
        msg = REASONS.get(self.code, self.code)
        if self.detail:
            msg = f"{msg} ({self.detail})"
        return {"code": self.code, "message": msg}


def reason_dicts(reasons: Iterable[Reason]) -> List[dict]:
    """Deduplicated, order-preserving list of reason dicts."""
    out: List[dict] = []
    seen: Set[Tuple[str, str]] = set()
    for r in reasons:
        key = (r.code, r.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(r.to_dict())
    return out


# --------------------------------------------------------------------------- #
# vendor normalisation
# --------------------------------------------------------------------------- #
_VENDOR_ALIASES = {
    "ios-asa": "ios-asa", "nxos": "nxos", "eos": "eos", "junos": "junos",
    "panos": "panos", "iptables": "iptables", "aws-sg": "aws-sg",
    # the hosted page's display labels
    "Cisco IOS / ASA": "ios-asa", "Cisco NX-OS": "nxos", "Arista EOS": "eos",
    "Juniper Junos": "junos", "Palo Alto PAN-OS": "panos",
    "Linux iptables": "iptables", "AWS Security Groups": "aws-sg",
}
_CISCO = frozenset({"ios-asa", "nxos", "eos"})


def normalise_vendor(vendor: str) -> str:
    """The canonical vendor key; an unknown label is kept as given, and
    build_context then blocks every PASS with `vendor-unknown` (no
    vendor-specific checks ran, so nothing a PASS rests on was checked)."""
    return _VENDOR_ALIASES.get(vendor, vendor or "ios-asa")


# --------------------------------------------------------------------------- #
# the context
# --------------------------------------------------------------------------- #
@dataclass
class FailClosedContext:
    """Everything about one config that a PASS rests on.

    `blockers` apply to every positive verdict. `transit_acls` is the set of
    ACL contexts with a recognised transit binding (None when the vendor's
    rule contexts are transit by construction, e.g. a PAN-OS rulebase or the
    iptables FORWARD chain). The `*_fallthrough` lists decide a PASS only when
    the search let part of the flow space reach the end of a context."""
    vendor: str
    blockers: List[Reason] = field(default_factory=list)
    v6_blockers: List[Reason] = field(default_factory=list)
    v4_blockers: List[Reason] = field(default_factory=list)
    fallthrough: List[Reason] = field(default_factory=list)
    v6_icmp_fallthrough: List[Reason] = field(default_factory=list)
    reach_blockers: List[Reason] = field(default_factory=list)
    n_rules: int = 0

    def pass_blockers(self, *, families: Set[int], proto: str,
                      fell_through: Set[Tuple[str, int]],
                      context_families: Dict[str, Set[int]],
                      reach: bool = False) -> List[Reason]:
        """Every reason a would-be PASS for this assertion is unsupported.

        `families` are the IP versions of the assertion's zones, `proto` its
        protocol, `fell_through` the (ACL, IP version) pairs whose search
        reached the implicit end-of-context default, and `context_families`
        the IP versions each searched context has a rule for. `reach` is
        True for a must_reach (connectivity) answer, which `reach_blockers`
        also block."""
        out: List[Reason] = list(self.blockers)
        if reach:
            out += self.reach_blockers
        if 4 in families:
            out += self.v4_blockers
        if 6 in families:
            out += self.v6_blockers
        if fell_through:
            out += self.fallthrough
            v6_icmp = proto in ("icmpv6", "ip", "any", "ipv6")
            if v6_icmp and any(fam == 6 for _, fam in fell_through):
                out += self.v6_icmp_fallthrough
            for acl, fam in sorted(fell_through):
                if fam not in context_families.get(acl, set()):
                    out.append(Reason("acl-family-mismatch",
                                      f"{acl}: no IPv{fam} rule"))
        return out


# --------------------------------------------------------------------------- #
# Cisco IOS / ASA / NX-OS / EOS: bindings and roles
# --------------------------------------------------------------------------- #
# Transit packet-filter bindings. Interface-level forms are honoured only
# inside an `interface` stanza; the ASA forms are global commands.
_CISCO_IF_BIND = re.compile(
    r"^\s+(?:ip\s+access-group|ipv6\s+traffic-filter|ipv6\s+access-group|"
    r"ip\s+port\s+access-group|ipv6\s+port\s+traffic-filter|"
    r"ipv4\s+access-group)\s+(\S+)\s+(?:in|out|ingress|egress)\b",
    re.IGNORECASE)
_ASA_BIND = re.compile(
    r"^\s*access-group\s+(\S+)\s+(?:(?:in|out)\s+interface\s+\S+|global)\b",
    re.IGNORECASE)
# Roles that are not transit packet filters, for the message only: anything
# without a transit binding is UNKNOWN whatever references it.
_CISCO_NON_TRANSIT = [
    ("line vty/con access-class",
     re.compile(r"^\s*(?:ipv6\s+)?access-class\s+(\S+)", re.IGNORECASE)),
    ("SNMP", re.compile(r"^\s*snmp-server\s+.*?\b(?:RO|RW|access|ipv6)\s+(\S+)\s*$",
                        re.IGNORECASE)),
    ("route-map / class-map / PBR match",
     re.compile(r"^\s*match\s+(?:ip(?:v6)?\s+)?(?:address|access-group)\s+"
                r"(?:name\s+|prefix-list\s+)?(\S+)", re.IGNORECASE)),
    ("NAT", re.compile(r"^\s*ip\s+nat\s+.*?\blist\s+(\S+)", re.IGNORECASE)),
    ("crypto map", re.compile(r"^\s*(?:crypto\s+map\s+.*\s)?match\s+address\s+(\S+)",
                              re.IGNORECASE)),
    ("distribute-list", re.compile(r"^\s*distribute-list\s+(\S+)", re.IGNORECASE)),
    ("NTP", re.compile(r"^\s*ntp\s+access-group\s+\S+\s+(\S+)", re.IGNORECASE)),
    ("HTTP server", re.compile(r"^\s*ip\s+http\s+access-class\s+(?:ipv4\s+)?(\S+)",
                               re.IGNORECASE)),
    ("ASA class-map / VPN / capture",
     re.compile(r"^\s*(?:match\s+access-list|vpn-filter\s+value|"
                r"split-tunnel-network-list\s+value|capture\s+\S+\s+access-list)\s+(\S+)",
                re.IGNORECASE)),
]
_ASA_DIALECT = re.compile(
    r"(?im)^\s*(?:(?:ASA|PIX|FWSM)\s+Version\b|nameif\s+\S|security-level\s+\d|"
    r"access-group\s+\S+\s+(?:(?:in|out)\s+interface\b|global\s*$))")
_NUMBERED_FLAT = re.compile(
    r"(?im)^\s*access-list\s+\d+\s+(?:permit|deny|dynamic)\b")


_NUMBERED_LINE_KW = re.compile(
    r"(?im)^\s*access-list\s+\d+\s+line\s+\d+\s+(?:permit|deny)\b")


def cisco_dialect_ambiguous(text: str) -> bool:
    """A numbered flat ACL line with no `extended` keyword in a config with a
    PIX/ASA marker (or written with the ASA-only `line N` keyword): its mask
    is a PIX netmask or an IOS wildcard."""
    return bool(_NUMBERED_LINE_KW.search(text)
                or (_NUMBERED_FLAT.search(text) and _ASA_DIALECT.search(text)))


_SHUTDOWN_ONLY = "bound only on a shutdown interface"


def _cisco_bindings(text: str) -> Tuple[Set[str], Dict[str, str]]:
    """(ACLs with a transit binding, ACL -> first non-transit role). A
    binding on a `shutdown` interface filters nothing, so an ACL bound only
    there has no transit binding."""
    transit: Set[str] = set()
    other: Dict[str, str] = {}
    shut_bound: Set[str] = set()
    in_interface = False
    here: Set[str] = set()
    shut = False

    def close() -> None:
        (shut_bound if shut else transit).update(here)

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        if raw[:1] not in (" ", "\t"):
            if in_interface:
                close()
            in_interface = bool(re.match(r"(?i)^interface\s", raw))
            here, shut = set(), False
        if in_interface:
            if re.match(r"(?i)^\s+shutdown\s*$", raw):
                shut = True
                continue
            if re.match(r"(?i)^\s+no\s+shutdown\s*$", raw):
                shut = False
                continue
            m = _CISCO_IF_BIND.match(raw)
            if m:
                here.add(m.group(1))
                continue
        m = _ASA_BIND.match(raw)
        if m:
            transit.add(m.group(1))
            continue
        for role, rx in _CISCO_NON_TRANSIT:
            m = rx.match(raw)
            if m:
                other.setdefault(m.group(1), role)
                break
    if in_interface:
        close()
    for acl in shut_bound - transit:
        other.setdefault(acl, _SHUTDOWN_ONLY)
    return transit, other


def _role_reasons(acls: Sequence[str], transit: Set[str],
                  other: Dict[str, str]) -> List[Reason]:
    out: List[Reason] = []
    for acl in acls:
        if acl in transit:
            continue
        if other.get(acl) == _SHUTDOWN_ONLY:
            out.append(Reason("acl-role-unknown", f"{acl}: {_SHUTDOWN_ONLY}"))
        elif acl in other:
            out.append(Reason("acl-not-packet-filter", f"{acl}: {other[acl]}"))
        else:
            out.append(Reason("acl-role-unknown", f"{acl}: no transit binding"))
    return out


# --------------------------------------------------------------------------- #
# Unfiltered paths: an interface that admits a family unfiltered, paired with
# another that emits it unfiltered, is a way across the device that meets no
# audited rule.
# --------------------------------------------------------------------------- #
_CISCO_IF_FAMILY_BIND = re.compile(
    r"^\s+(ip\s+access-group|ip\s+port\s+access-group|ipv4\s+access-group|"
    r"ipv6\s+traffic-filter|ipv6\s+access-group|ipv6\s+port\s+traffic-filter)"
    r"\s+\S+\s+(in|out|ingress|egress)\b", re.IGNORECASE)
_NO_FORWARD_IF = re.compile(r"(?i)^(?:loopback|null)")


def _bypasses(paths: Dict[str, Dict[str, Set[int]]], fam: int) -> List[Reason]:
    """`paths[name]` = {"fams": families it carries, "in": families filtered
    inbound, "out": families filtered outbound}."""
    carry = [n for n, p in paths.items() if fam in p["fams"]]
    no_in = [n for n in carry if fam not in paths[n]["in"]]
    no_out = [n for n in carry if fam not in paths[n]["out"]]
    # One interface with neither filter is a bypass on its own: a packet can
    # arrive on it and be routed back out of it (a hairpin between two
    # subnets on the same interface, primary and secondary).
    for n in no_in:
        if n in no_out:
            return [Reason("unfiltered-path",
                           f"IPv{fam}: {n} has no filter in either direction")]
    for i in no_in:
        for e in no_out:
            if i != e:
                return [Reason("unfiltered-path", f"IPv{fam}: in {i}, out {e}")]
    return []


def _cisco_paths(text: str) -> Dict[str, Dict[str, Set[int]]]:
    paths: Dict[str, Dict[str, Set[int]]] = {}
    cur: Optional[str] = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        if raw[:1] not in (" ", "\t"):
            m = re.match(r"(?i)^interface\s+(\S+)", raw)
            cur = m.group(1) if m and not _NO_FORWARD_IF.match(m.group(1)) else None
            if cur is not None:
                paths.setdefault(cur, {"fams": {4, 6}, "in": set(), "out": set(),
                                       "shutdown": set()})
            continue
        if cur is None:
            continue
        if re.match(r"(?i)^\s+shutdown\s*$", raw):
            paths[cur]["shutdown"].add(1)
        elif re.match(r"(?i)^\s+no\s+shutdown\s*$", raw):
            paths[cur]["shutdown"].clear()
        m = _CISCO_IF_FAMILY_BIND.match(raw)
        if m:
            fam = 6 if m.group(1).lower().startswith("ipv6") else 4
            d = "in" if m.group(2).lower() in ("in", "ingress") else "out"
            paths[cur][d].add(fam)
    return {n: p for n, p in paths.items() if not p["shutdown"]}


_JUNOS_FAMILY = {"inet": {4}, "inet6": {6}, "ethernet-switching": {4, 6},
                 "bridge": {4, 6}, "vpls": {4, 6}}
# Any other family (mpls, iso, ccc, tcc, ...) is not filtered by an inet or
# inet6 filter, and traffic it carries can leave as IP (an MPLS label popped
# here and forwarded out an IP interface), so it counts as a path that admits
# and emits every IP family unfiltered. It gets its own path entry: an inet
# filter on the same unit does not cover it.


def _junos_paths(text: str) -> Dict[str, Dict[str, Set[int]]]:
    """Interface units, the families they carry and which are filtered. An L2
    family (ethernet-switching, bridge, vpls) carries every IP family and is
    never filtered by an inet/inet6 filter."""
    from .parse_junos import _tokenize
    paths: Dict[str, Dict[str, Set[int]]] = {}

    def leaf(words: List[str]) -> None:
        words = [w.strip('"') for w in words]
        if "interfaces" not in words:
            return
        k = words.index("interfaces")
        if k + 1 >= len(words):
            return
        ifname = words[k + 1]
        if ifname.startswith("lo"):
            return
        rest = words[k + 2:]
        unit = rest[rest.index("unit") + 1] if "unit" in rest and \
            rest.index("unit") + 1 < len(rest) else "0"
        if "family" not in rest or rest.index("family") + 1 >= len(rest):
            return
        famname = rest[rest.index("family") + 1]
        fams = _JUNOS_FAMILY.get(famname)
        key = f"{ifname}.{unit}"
        if not fams:
            fams = {4, 6}
            key = f"{ifname}.{unit} (family {famname})"
        p = paths.setdefault(key, {"fams": set(), "in": set(), "out": set()})
        p["fams"] |= fams
        if famname in ("inet", "inet6") and "filter" in rest:
            tail = rest[rest.index("filter") + 1:]
            if "input" in tail or "input-list" in tail:
                p["in"] |= fams
            if "output" in tail or "output-list" in tail:
                p["out"] |= fams

    for raw in text.splitlines():
        if re.match(r"^\s*set\s", raw):
            leaf(raw.split()[1:])
    stack: List[List[str]] = []
    stmt: List[str] = []
    for t in _tokenize(text):
        if t == "{":
            stack.append(stmt)
            stmt = []
        elif t == "}":
            if stack:
                stack.pop()
            stmt = []
        elif t == ";":
            leaf([w for part in stack for w in part] + stmt)
            stmt = []
        else:
            stmt.append(t)
    return paths


def _path_blockers(ctx: "FailClosedContext", paths) -> None:
    ctx.v4_blockers += _bypasses(paths, 4)
    ctx.v6_blockers += _bypasses(paths, 6)


# --------------------------------------------------------------------------- #
# Junos: interface filter bindings
# --------------------------------------------------------------------------- #
_JUNOS_SET_BIND = re.compile(
    r"^\s*set\s+(?:logical-systems\s+\S+\s+)?interfaces\s+(\S+)\s+.*?\bfilter\s+"
    r"(?:input|output|input-list|output-list)\s+(.+?)\s*$")


def _junos_bindings(text: str) -> Tuple[Set[str], Dict[str, str]]:
    """(filters bound on a non-loopback interface, filter -> lo0 role)."""
    from .parse_junos import _tokenize
    transit: Set[str] = set()
    other: Dict[str, str] = {}

    def bind(ifname: str, names: Iterable[str]) -> None:
        for nm in names:
            nm = nm.strip('"')
            if nm in ("[", "]", ";") or not nm:
                continue
            if ifname.startswith("lo"):
                other.setdefault(nm, f"{ifname} control-plane filter")
            else:
                transit.add(nm)

    for raw in text.splitlines():
        m = _JUNOS_SET_BIND.match(raw)
        if m:
            bind(m.group(1), m.group(2).replace("[", " ").replace("]", " ").split())

    toks = _tokenize(text)
    stack: List[str] = []
    stmt: List[str] = []
    for t in toks:
        if t == "{":
            stack.append(stmt[-1] if stmt else "")
            stmt = []
        elif t == "}":
            if stack:
                stack.pop()
            stmt = []
        elif t == ";":
            _junos_stmt(stack, stmt, bind)
            stmt = []
        else:
            stmt.append(t)
    return transit, other


def _junos_stmt(stack: List[str], stmt: List[str], bind) -> None:
    if not stmt or "interfaces" not in stack:
        return
    k = stack.index("interfaces")
    if k + 1 >= len(stack):
        return
    ifname = stack[k + 1]
    words = list(stmt)
    if words and words[0] == "filter":          # `filter input NAME;`
        words = words[1:]
    elif "filter" not in stack[k + 1:]:
        return
    if words and words[0] in ("input", "output", "input-list", "output-list"):
        bind(ifname, words[1:])


# --------------------------------------------------------------------------- #
# per-vendor scans
# --------------------------------------------------------------------------- #
_PANOS_RULE_LINE = re.compile(r"(?m)^\s*set\s+.*?\b(?:pre-|post-)?rulebase\s+security\s+rules\s.*$")
_PANOS_UNMODELED_FIELDS = ("source-user", "schedule", "category", "source-hip",
                           "destination-hip", "hip-profiles", "source-device",
                           "destination-device", "rule-type", "target")
_PANOS_FIELD_EXACT = {"any", "universal"}


def _panos_unmodeled_fields(text: str) -> List[str]:
    found: List[str] = []
    for m in _PANOS_RULE_LINE.finditer(text):
        toks = m.group(0).split()
        for k, t in enumerate(toks[:-1]):
            if t in _PANOS_UNMODELED_FIELDS:
                val = toks[k + 1].strip('"[').lower()
                if val not in _PANOS_FIELD_EXACT and t not in found:
                    found.append(t)
    return found


# A removed or deactivated binding (review of #42, round 3, H1/H2). The
# removal is not applied; any such line makes which interfaces are filtered
# unknown.
_CISCO_NEGATED_BIND = re.compile(
    r"(?im)^\s*(?:no|default)\s+(?:(?:ip|ipv4|ipv6)\s+(?:port\s+)?"
    r"(?:access-group|traffic-filter|access-class)|access-group|access-class|"
    r"ipv6\s+port\s+traffic-filter)\b.*$|"
    r"^(?:no|default)\s+in(?:t(?:e(?:r(?:f(?:a(?:ce?)?)?)?)?)?)?\s.*$")
_JUNOS_SET_NEGATED = re.compile(
    r"(?m)^\s*(?:deactivate|delete)\s+(?:logical-systems\s+\S+\s+)?"
    r"(?:interfaces\b|firewall\s+(?:family\s+\S+\s+)?filter\s+\S+\s*$).*$")

# NAT (M1, H8): addresses are checked before translation only.
_NAT = {
    "cisco": re.compile(
        r"(?im)^\s*(?:ip|ipv6)\s+nat\b|^\s*nat\s*\(|^\s*static\s*\(|"
        r"^\s*nat(?:64|66)\b"),
    "panos": re.compile(r"(?m)^\s*set\s.*\b(?:pre-|post-)?rulebase\s+nat\b"),
    "junos": re.compile(
        r"(?m)^\s*(?:set\s+(?:\S+\s+)*?(?:security|services)\s+nat\b|"
        r"nat\s*\{)"),
    "iptables": re.compile(r"(?m)^\s*\*nat\b|(?:^|\s)(?:-t|--table)\s+nat\b"),
}
# nftables text anywhere in the input (H7).
_NFT_ANY = re.compile(
    r"(?m)^\s*(?:sudo\s+)?(?:nft\s|table\s+(?:inet|ip6?|arp|bridge|netdev)\s+"
    r"\S+\s*\{|flush\s+ruleset\b)")
_PANOS_OBJECT = re.compile(
    r"(?m)^\s*set\s+(?:(shared)\s+|(vsys|device-group)\s+(\S+)\s+)?"
    r"(address|address-group|service|service-group)\s+(\S+)")


_PANOS_NS = {"address": "address", "address-group": "address",
             "service": "service", "service-group": "service"}


def _panos_scope_collisions(text: str) -> List[str]:
    """Names defined as more than one (kind, scope): address and
    address-group share a namespace, as do service and service-group."""
    where: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
    for m in _PANOS_OBJECT.finditer(text):
        scope = m.group(1) or (f"{m.group(2)} {m.group(3)}" if m.group(2) else "")
        where.setdefault((_PANOS_NS[m.group(4)], m.group(5).strip('"')),
                         set()).add((m.group(4), scope))
    return [f"{k} {n}" for (k, n), sc in sorted(where.items()) if len(sc) > 1]


def _junos_inactive(text: str) -> List[str]:
    """Where an `inactive:` marks an interface, unit, family, filter binding
    or a whole filter (terms are modelled by the parser and noted)."""
    from .parse_junos import _tokenize
    out: List[str] = []
    stack: List[List[str]] = []
    stmt: List[str] = []
    pending = False
    for t in _tokenize(text):
        if t == "inactive:":
            pending = True
            continue
        if t in ("{", ";"):
            if pending:
                path = [w for part in stack for w in part] + stmt
                if ("interfaces" in path or "firewall" in path) and \
                        "term" not in stmt[:1]:
                    out.append(" ".join(path))
                pending = False
            if t == "{":
                stack.append(stmt)
            stmt = []
        elif t == "}":
            if stack:
                stack.pop()
            stmt = []
        else:
            stmt.append(t)
    for m in _JUNOS_SET_NEGATED.finditer(text):
        out.append(m.group(0).strip())
    return out


# --------------------------------------------------------------------------- #
# Cisco IOS / ASA / NX-OS / EOS interfaces: an allowlist (review of #42,
# round 4). A PASS rests on the interface ACLs being the only thing on the
# path that decides a packet's fate, so every line in an `interface` stanza
# (other than Loopback / Null, which carry no transit traffic) must be one
# that cannot change it. Each entry is whitespace-normalised and matched in
# full, case-insensitively: a `default` form, an abbreviation (`access-gr`) or
# any other feature does not match and makes the answer UNKNOWN
# (interface-feature-unmodeled). The list is kept small on purpose; adding to
# it needs a reason the line cannot drop, permit, rewrite or divert a packet.
# --------------------------------------------------------------------------- #
_IF_ALLOW = [
    # Free text.
    r"description(?: .*)?",
    # Addresses: they say which subnets the interface is on, not what crosses
    # it. Every interface is already treated as carrying both families.
    r"ip address [0-9.]+(?: [0-9.]+|/\d{1,2})(?: secondary)?",
    r"ipv6 address [0-9a-f:]+/\d{1,3}(?: eui-64)?",
    r"ipv6 address [0-9a-f:]+ link-local",
    r"ipv6 enable",
    # The filter bindings themselves, full keyword only (modeled by
    # _cisco_bindings / _cisco_paths).
    r"(?:ip access-group|ipv6 traffic-filter|ipv6 access-group|"
    r"ip port access-group|ipv6 port traffic-filter|ipv4 access-group)"
    r" \S+ (?:in|out|ingress|egress)",
    # Admin state (modeled: a shutdown interface is not on a path).
    r"shutdown", r"no shutdown",
    # A routed port (NX-OS / EOS): the interface then routes, as modeled.
    r"no switchport",
    # Physical layer: link speed and duplex do not select packets.
    r"speed (?:auto|\d+)", r"duplex (?:auto|full|half)", r"negotiation auto",
    # Counter sampling interval only.
    r"load-interval \d+",
    # Turning off messages the router itself originates: ICMP unreachables
    # and redirects (RFC 1812 sections 5.2.7.1 and 5.2.7.2) and proxy-ARP
    # replies (RFC 1027). None of them lets a transit packet through or
    # stops one.
    r"no ip redirects", r"no ip unreachables", r"no ip proxy-arp",
    r"no ipv6 redirects", r"no ipv6 unreachables",
    # CDP is a link-local discovery protocol the device terminates.
    r"cdp enable", r"no cdp enable",
]
_IF_ALLOW_RX = re.compile("(?i)(?:" + "|".join(_IF_ALLOW) + ")")
# Words after which the next word is still part of the keyword, so the detail
# names `ip verify` or `no ip access-gr`, never an argument (an ACL name, an
# address).
_KW_PREFIX = frozenset({"no", "default", "ip", "ipv4", "ipv6", "mpls",
                        "switchport", "crypto", "tunnel", "service-policy",
                        "zone-member"})
_KW_TOKEN = re.compile(r"^[A-Za-z][A-Za-z-]*$")


def _keyword(line: str) -> str:
    out: List[str] = []
    for t in line.split():
        if len(out) == 3 or not _KW_TOKEN.match(t):
            break
        out.append(t.lower())
        if t.lower() not in _KW_PREFIX:
            break
    return " ".join(out) or "(not a keyword)"


_IF_ABBREV = re.compile(r"(?i)^(in(?:t(?:e(?:r(?:f(?:a(?:ce?)?)?)?)?)?)?)\s+(\S+)")


def _cisco_unallowed(text: str) -> List[str]:
    """`interface: keyword` for each interface line not on the allowlist."""
    out: List[str] = []
    cur: Optional[str] = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        if raw[:1] not in (" ", "\t"):
            m = re.match(r"(?i)^interface\s+(\S+)", raw)
            cur = m.group(1) if m and not _NO_FORWARD_IF.match(m.group(1)) else None
            ab = _IF_ABBREV.match(raw)
            if ab and not m:
                # `int X`: the CLI accepts it, but the binding and path
                # passes only read `interface X`, so the stanza is unmodeled.
                cur = ab.group(2)
                out.append(f"{cur}: {ab.group(1).lower()} (abbreviated interface)")
            continue
        if cur is None:
            continue
        line = " ".join(raw.split())
        if not _IF_ALLOW_RX.fullmatch(line):
            item = f"{cur}: {_keyword(line)}"
            if item not in out:
                out.append(item)
    return out


# Global features that drop, permit statefully, rewrite or bypass traffic
# independently of the interface ACLs. Matched on any line, any indentation,
# so a stanza RuleHawk skips (a Loopback, a sub-block) still counts. `no X`
# forms do not match (they turn the feature off).
_CISCO_FEATURES = [
    ("zone-firewall", re.compile(
        r"(?im)^\s*(zone(?:-member)?\s+security|zone-pair\s+security)\b")),
    ("stateful-inspection", re.compile(r"(?im)^\s*((?:ip|ipv6)\s+inspect)\b")),
    ("qos-policy", re.compile(r"(?im)^\s*(service-policy)\b")),
    ("policy-routing", re.compile(
        r"(?im)^\s*((?:ip|ipv6)\s+(?:local\s+)?policy\s+route-map|"
        r"service-policy\s+type\s+pbr)\b")),
    ("mpls-forwarding", re.compile(
        r"(?im)^\s*(mpls\s+[a-z-]+|tag-switching\s+[a-z-]+|xconnect|l2vpn|"
        r"pseudowire)\b")),
]


_ALL_ONES_NONZERO = re.compile(
    r"(?im)^\s*(?:access-list\s+\S+\s+)?(?:\d+\s+)?(?:permit|deny)\b.*?"
    r"\b(?!0\.0\.0\.0\b)\d{1,3}(?:\.\d{1,3}){3}\s+255\.255\.255\.255\b")
_NFT = re.compile(r"(?m)^\s*table\s+(?:inet|ip6?|arp|bridge|netdev)\s+\S+\s*\{")


def _is_l4(a) -> bool:
    from .model import _PORTED
    if a.stateful:
        return True
    if a.proto in _PORTED and not (a.src_port.is_any() and a.dst_port.is_any()):
        return True
    return a.icmp_type is not None


def build_context(text: str, aces: Sequence, notes: Sequence[str],
                  vendor: str) -> FailClosedContext:
    """Check every assumption a PASS on this config rests on."""
    v = normalise_vendor(vendor)
    ctx = FailClosedContext(vendor=v, n_rules=len(aces))
    b = ctx.blockers
    if not aces:
        b.append(Reason("no-rules-parsed"))
        if _NFT.search(text):
            b.append(Reason("nftables-unsupported"))
    elif _NFT_ANY.search(text):
        b.append(Reason("nftables-present",
                        _NFT_ANY.search(text).group(0).strip()[:60]))
    if notes:
        first = str(notes[0])
        if len(first) > 160:
            first = first[:157] + "..."
        b.append(Reason("parse-note", f"{len(notes)} note(s); first: {first}"))

    transit_aces = [a for a in aces if a.transit]
    acls = sorted({a.acl for a in transit_aces})

    if v in _CISCO:
        from .parse import strip_banners
        text = strip_banners(text)[0]          # banner text is not config
        neg = _CISCO_NEGATED_BIND.search(text)
        if neg:
            b.append(Reason("acl-binding-negated", neg.group(0).strip()))
        if _NAT["cisco"].search(text):
            b.append(Reason("nat-present",
                            _NAT["cisco"].search(text).group(0).strip()))
        for code, rx in _CISCO_FEATURES:
            m = rx.search(text)
            if m:
                b.append(Reason(code, " ".join(m.group(1).lower().split())))
        unallowed = _cisco_unallowed(text)
        if unallowed:
            more = (f" (+{len(unallowed) - 3} more)" if len(unallowed) > 3 else "")
            b.append(Reason("interface-feature-unmodeled",
                            "; ".join(unallowed[:3]) + more))
        transit, other = _cisco_bindings(text)
        role = _role_reasons(acls, transit, other)
        b += role
        if acls and all(acl not in transit for acl in acls):
            b.append(Reason("no-transit-filter",
                            "no ACL has an interface or access-group binding"))
        defined = {a.acl for a in aces}
        for name in sorted(transit - defined):
            # Cisco: "If an access list is referenced by a name, but the access
            # list does not exist, all packets pass." (IOS XE 17 ACL guide)
            b.append(Reason("acl-binding-undefined", name))
        if re.search(r"(?im)^\s*(?:nameif\s+\S|security-level\s+\d|"
                     r"same-security-traffic\b)", text):
            b.append(Reason("asa-security-levels"))
        if _ASA_DIALECT.search(text):
            if not any(r.code == "asa-security-levels" for r in b):
                b.append(Reason("unfiltered-path",
                                "ASA interface coverage is not modelled"))
        else:
            _path_blockers(ctx, _cisco_paths(text))
        if cisco_dialect_ambiguous(text):
            b.append(Reason("numbered-acl-mask-ambiguous"))
        if _ALL_ONES_NONZERO.search(text) \
                and not _ASA_DIALECT.search(text):
            # `A 255.255.255.255` in an IOS ACL is an all-ones WILDCARD (any
            # address); the parser keeps the netmask reading (host A). The two
            # readings differ, so no PASS rests on either.
            b.append(Reason("ios-wildcard-all-ones"))
        if re.search(r"(?im)^\s*(?:access-list\s+\S+\s+)?(?:\d+\s+)?dynamic\s+\S+", text):
            b.append(Reason("ios-dynamic-entry"))
        v6_icmp = [a for a in transit_aces
                   if a.proto in ("icmp", "icmp6", "icmpv6")
                   and (a.src.version == 6 or a.dst.version == 6)]
        if v6_icmp or re.search(r"(?i)\bicmp6\b", text):
            ctx.v6_blockers.append(Reason("icmpv6-canonicalisation"))
        ctx.v6_icmp_fallthrough.append(Reason("ipv6-implicit-nd"))
    elif v == "junos":
        inactive = _junos_inactive(text)
        if inactive:
            b.append(Reason("acl-binding-negated", inactive[0][:120]))
        if _NAT["junos"].search(text):
            b.append(Reason("nat-present"))
        transit, other = _junos_bindings(text)
        _path_blockers(ctx, _junos_paths(text))
        b += _role_reasons(acls, transit, other)
        if acls and all(acl not in transit for acl in acls):
            b.append(Reason("no-transit-filter",
                            "no filter is applied on a transit interface"))
        if re.search(r"\blogical-systems\b", text):
            b.append(Reason("junos-logical-systems"))
        if re.search(r"(?m)^\s*(?:set\s+)?security\s+(?:\{|policies\b|zones\b)",
                     text) or \
                re.search(r"\bfrom-zone\s+\S+\s+to-zone\s+\S+", text) or \
                re.search(r"(?m)^\s*policies\s*\{", text):
            b.append(Reason("junos-srx-policies"))
        if re.search(r"(?m)^\s*(?:set\s+)?groups\b|\bapply-groups\b", text):
            b.append(Reason("junos-groups"))
    elif v == "panos":
        if _NAT["panos"].search(text):
            b.append(Reason("nat-present", "PAN-OS NAT rulebase"))
        coll = _panos_scope_collisions(text)
        if coll:
            b.append(Reason("object-scope-ambiguous", ", ".join(coll)))
        elif any("(object-scope-ambiguous)" in str(x) for x in notes):
            b.append(Reason("object-scope-ambiguous",
                            "a rule names an object defined outside its scope"))
        if "default-security-rules" in text:
            b.append(Reason("panos-default-security-rules"))
        fields = _panos_unmodeled_fields(text)
        if fields:
            b.append(Reason("panos-unmodeled-rule-field", ", ".join(fields)))
        if re.search(r"(?m)^\s*set\s.*\bsecurity\s+rules\s+\S+\s.*\bprofile-setting\b",
                     text):
            ctx.reach_blockers.append(Reason("panos-security-profile"))
        ctx.fallthrough.append(Reason("panos-implicit-default"))
    elif v == "iptables":
        if not transit_aces and any(not a.transit for a in aces):
            b.append(Reason("iptables-host-chain-only"))
            b.append(Reason("no-transit-filter",
                            "only INPUT/OUTPUT host chains carry rules"))
        if re.search(r"(?m)(?:^|\s)(?:-p|--protocol)\s+0(?:\s|$)", text):
            b.append(Reason("iptables-proto-zero"))
        if re.search(r"(?m)\bip6tables\b", text):
            b.append(Reason("ip6tables-family"))
        if re.search(r"(?m)(?:^|\s)(?:-D|--delete)\s+\S+", text):
            b.append(Reason("iptables-delete"))
        if _NAT["iptables"].search(text):
            b.append(Reason("nat-present", "iptables nat table"))
        # Every forwarded packet crosses FORWARD, whatever chain the rules are
        # in: with no FORWARD policy anywhere, its kernel default ACCEPT
        # decides whatever the parsed rules do not (H3: a user chain nothing
        # jumps to, and no FORWARD rule at all). The policy is the one the
        # parser applied (its trailing chain-policy entry), never a regex over
        # the text: a `-P FORWARD DROP` in a comment, a `--comment` or a
        # `--log-prefix` sets nothing (round 4, R1).
        if aces and not any(a.acl == "FORWARD" and
                            a.raw.startswith("FORWARD: default policy ")
                            for a in aces):
            b.append(Reason("iptables-chain-policy-unset",
                            "FORWARD has no policy: the kernel default is ACCEPT"))
        ctx.fallthrough.append(Reason("iptables-chain-policy-unset",
                                      "the search reached the end of a chain"))
        l4 = [x for x in transit_aces if _is_l4(x)]
        if l4:
            b.append(Reason("iptables-fragments",
                            f"{l4[0].acl} line {l4[0].line}" if l4[0].line
                            else l4[0].acl))
    elif v == "aws-sg":
        b.append(Reason("aws-sg-binding-unknown"))
    else:
        b.append(Reason("vendor-unknown", repr(vendor)))

    if v in _CISCO or v == "junos":
        if any(a.stateful for a in transit_aces):
            b.append(Reason("tcp-established"))
        l4 = [a for a in transit_aces if _is_l4(a)]
        if l4:
            b.append(Reason("l4-fragments",
                            f"{l4[0].acl} line {l4[0].line}" if l4[0].line
                            else l4[0].acl))
    return ctx


# What each frontend reads (review of #42, round 4, R7). Printed with every
# PASS, on every surface, and in the README; it must match the checks above.
KNOWN_LIMITS = (
    "Cisco reads ACLs, allowlisted interface lines and the listed global "
    "features (zone firewall, ip inspect, service-policy, policy routing, "
    "MPLS / xconnect, NAT); any other interface line is UNKNOWN and other "
    "global commands are not read",
    "PAN-OS resolves an object name only in the rule's own vsys or "
    "device-group and in shared; device-group inheritance is not followed",
    "iptables reads the filter table; a chain's policy comes only from its "
    "parsed -P or :CHAIN line",
    "Junos reads firewall filters and their interface bindings; SRX security "
    "zones or policies make the answer UNKNOWN",
)
LIMITS_STATEMENT = "known limits: " + "; ".join(KNOWN_LIMITS)

# What every positive verdict rests on, stated with it (review of #42, F8).
PASS_SCOPE = ("no audited ruleset permits this flow; assumes every interface is "
              "in the file; routing, NAT and topology not evaluated; "
              + LIMITS_STATEMENT)
REACH_SCOPE = ("every audited ruleset permits the whole flow; assumes every "
               "interface is in the file; routing, NAT and topology not "
               "evaluated; " + LIMITS_STATEMENT)


def families_of(nets: Iterable) -> Set[int]:
    out: Set[int] = set()
    for n in nets:
        try:
            out.add(ipaddress.ip_network(str(n), strict=False).version)
        except ValueError:
            continue
    return out


# --------------------------------------------------------------------------- #
# verdict helpers for the output surfaces
# --------------------------------------------------------------------------- #
def undecided(findings) -> list:
    """The policy-assertion findings whose verdict is UNKNOWN (fail-closed:
    an UNKNOWN, an indeterminate search or a policy error). Any one of them
    means the run is not a PASS."""
    return [f for f in findings
            if getattr(f, "verdict", None) == "UNKNOWN"
            and getattr(f, "accepted", None) is None]


def assertion_verdict(findings) -> Optional[str]:
    """The worst assertion verdict: FAIL > UNKNOWN > PASS; None when no
    policy assertion was checked."""
    vs = {getattr(f, "verdict", None) for f in findings}
    for v in ("FAIL", "UNKNOWN", "PASS"):
        if v in vs:
            return v
    return None
