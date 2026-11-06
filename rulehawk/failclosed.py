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
import unicodedata
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import (Callable, Dict, Hashable, Iterable, Iterator, List, Optional,
                    Sequence, Set, Tuple)

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
    "stanza-boundary-ambiguous":
        "an unindented line in Cisco / Arista interface, ACL or object-group "
        "mode is not a command RuleHawk knows ends that mode; the device "
        "ignores indentation, so the line may apply to the interface, ACL or "
        "group above it",
    "vlan-filter":
        "a VLAN ACL is configured (`vlan access-map`, `vlan filter`); it can "
        "drop or forward traffic inside a VLAN independently of the interface "
        "ACLs and is not modeled",
    "junos-keyword-case":
        "a Junos statement keyword is written with upper-case letters; Junos "
        "keywords are lower-case only, so the device rejects the statement "
        "and RuleHawk will not guess what was meant",
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


# --------------------------------------------------------------------------- #
# Line accounting (review of #42, round 8)
# --------------------------------------------------------------------------- #
# Every line inside an object on the evaluated path ends in exactly one of two
# states: consumed (the parser turned it into model state and read every
# token) or noted (a parse-note, which caps the verdict below PASS). Each
# frontend fills a Ledger: `add` puts a line in scope (from the mode or block
# it is in, never from whether a handler read it), `consume` only where model
# state was made, `note` where a note was written. The one central check is
# `close`: every line in scope that is neither consumed nor noted gets a
# note. A line both consumed and noted counts as noted.
_LEDGERS: "ContextVar[Optional[List[Ledger]]]" = ContextVar("rulehawk_ledgers",
                                                           default=None)


class Ledger:
    def __init__(self, frontend: str):
        self.frontend = frontend
        self.scope: Dict[Hashable, str] = {}
        self.consumed: Set[Hashable] = set()
        self.noted: Set[Hashable] = set()
        self.caught: List[Hashable] = []
        self.closed = False
        sink = _LEDGERS.get()
        if sink is not None:
            sink.append(self)

    def add(self, key: Hashable, text: str) -> None:
        self.scope.setdefault(key, text)

    def consume(self, key: Hashable) -> None:
        self.consumed.add(key)

    def note(self, key: Hashable, notes: Optional[List[str]] = None,
             text: str = "") -> None:
        self.noted.add(key)
        if notes is not None and text:
            notes.append(text)

    def close(self, notes: List[str],
              fmt: Optional[Callable[[Hashable, str], str]] = None,
              cap: int = 20) -> None:
        """Note every line in scope that no handler consumed or noted."""
        miss = [k for k in self.scope
                if k not in self.consumed and k not in self.noted]
        self.caught = miss
        for k in miss[:cap]:
            notes.append(fmt(k, self.scope[k]) if fmt else
                         f"{self.frontend} line {k} (`{self.scope[k][:60]}`) is not "
                         f"read by RuleHawk: what it changes is not modelled")
        if len(miss) > cap:
            notes.append(f"... and {len(miss) - cap} more {self.frontend} line(s) "
                         f"not read")
        self.closed = True

    def counts(self) -> Dict[str, int]:
        noted = {k for k in self.scope if k in self.noted}
        consumed = {k for k in self.scope if k in self.consumed} - noted
        caught = set(self.caught) - noted - consumed
        return {"scope": len(self.scope), "consumed": len(consumed),
                "noted": len(noted), "caught": len(caught),
                "unaccounted": len(self.scope) - len(consumed | noted | caught)}


@contextmanager
def collect_ledgers() -> Iterator[List[Ledger]]:
    """Every Ledger made inside the block, for the tests."""
    sink: List[Ledger] = []
    tok = _LEDGERS.set(sink)
    try:
        yield sink
    finally:
        _LEDGERS.reset(tok)


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
# Cisco IOS / ASA / NX-OS / EOS: the one lexer (review of #42, round 5).
# Every Cisco check (bindings, paths, the interface allowlist, the global
# features, NAT and negation regexes) reads the config through `cisco_lex`,
# so none of them can split lines or assign stanzas differently.
#
# - A line ends at "\n" only (one trailing "\r" is dropped): `str.splitlines`
#   also breaks at \v, \f, \x1c-\x1e, \x85, U+2028/U+2029, which the device
#   keeps inside a line. Any other control, format or line/paragraph
#   separator character, and any space character other than " ", is a
#   parse note: RuleHawk will not guess how the device reads it.
# - Words are split on " " and "\t" only.
# - Mode, not indentation, decides which stanza a line belongs to. The CLI
#   ignores leading whitespace: a line valid in interface mode applies to the
#   current interface wherever it starts, and `!` is a comment that does not
#   leave the mode. So after an `interface` (or ACL / object-group) header the
#   mode lasts until another header or a command from `_TOP_LEVEL`, each of
#   which is invalid in interface, ACL and object-group mode, so the device
#   leaves the sub-mode to run it. Any other unindented line in one of those
#   modes is `stanza-boundary-ambiguous`.
# - Interface names are normalised: the type is case-folded and a number
#   written as a separate word is joined (`GigabitEthernet 0/1` ==
#   `gigabitethernet0/1`). Repeated stanzas for one name are merged in order,
#   as IOS applies them. An abbreviated type (`Gi0/1`) stays a separate name:
#   that can only add an interface to the path model, never hide one.
# --------------------------------------------------------------------------- #
_BOM = "\ufeff"

# Top-level commands that end an interface / ACL / object-group mode. Each is
# not a command of those modes on IOS, NX-OS or EOS, so the device leaves the
# sub-mode to run it, indented or not (the device ignores indentation). Kept
# small; anything else unindented in those modes is ambiguous.
_TOP_LEVEL = re.compile(
    r"(?i)^(?:end"
    r"|banner \S+"                         # banner text (strip_banners keeps the header)
    r"|hostname \S+"                       # device identity
    r"|version \S+|boot \S+"               # image / boot
    r"|router \S+"                         # routing-process mode
    r"|line \S+"                           # console / vty mode
    r"|(?:ip|ipv4|ipv6|mac) access-list \S+"   # ACL mode (`ip access-group` binds)
    r"|access-list \S+"                    # numbered ACL entry
    r"|object-group \S+"                   # object-group mode
    r"|route-map \S+"                      # route-map mode (`ip policy` binds)
    r"|(?:ip|ipv6) prefix-list \S+"        # prefix list
    r"|(?:ip|ipv6) route \S+"              # static route (`ip route-cache` differs)
    r"|ip routing|ipv6 unicast-routing"    # global forwarding switch
    r"|class-map \S+|policy-map \S+"       # QoS definitions (`service-policy` binds)
    r"|control-plane"                      # CoPP mode
    r"|vrf (?:definition|context|instance) \S+"   # VRF definition (`vrf forwarding|member` binds)
    r"|management \S+"                     # EOS management API / SSH mode
    r"|snmp-server \S+"                    # SNMP agent (`snmp trap` is the interface form)
    r")(?: |$)")
# ACL mode is an allowlist, not a list of what ends it (review of #42, round
# 7, R6-1): IOS runs a command that the sub-mode lacks in global mode, so any
# line inside an ACL that is not an ACL entry may have ended the ACL. Kept to
# the ACL-mode commands the parser reads:
# - IOS extended / standard named ACL mode: an entry with an optional
#   sequence number, `remark`, `evaluate`, `dynamic`, and `no` / `default` of
#   an entry or a sequence number. Cisco, "Configure IP Access Lists" (Doc ID
#   23602, https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html):
#   "Router(config-ext-nacl)#5 deny tcp any any eq telnet",
#   "router(config-ext-nacl)#no permit icmp any any", "evaluate", "remark";
#   IOS XE 17 "IP Named Access Control Lists"
#   (https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-acl-named.html):
#   "Device(config-ext-nacl)# remark ...", "deny ...", "permit ...".
#   IPv6 entries are written `sequence N permit ...` (parse._entry_tokens).
# - NX-OS IP ACL mode: `[no] statistics per-entry`, which only counts.
#   Cisco Nexus 7000 NX-OS Security Command Reference, "statistics per-entry"
#   (https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus7000/sw/security/command/reference/n7k_sec_cmd/sec_cmd_r_to_s.html):
#   "To start recording statistics for how many packets are permitted or
#   denied by each entry ... Command Modes: IP access-list configuration".
# Anything else (EOS `counters per-entry`, NX-OS `fragments`, a global
# command, an abbreviation) is `ambiguous`.
_ACL_ACTION = r"(?:permit|deny|remark|evaluate|dynamic)"
_ACL_ENTRY = re.compile(
    r"(?ai)^(?:(?:(?:sequence )?[0-9]+ )?" + _ACL_ACTION + r"(?: |$)"
    r"|(?:no|default) (?:(?:sequence )?[0-9]+|" + _ACL_ACTION + r")(?: |$)"
    r"|(?:no )?statistics per-entry$)")
# `exit` and `end` as the device reads them: IOS accepts "the number of
# characters that allow a unique abbreviation" (IOS XE Configuration
# Fundamentals, "Using the Cisco IOS Command-Line Interface",
# https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/configuration/xe-16-8/fundamentals-xe-16-8-book/cf-cli-basics.html).
# Whether two letters are unique depends on the mode, so every prefix of
# two letters or more is read as the word, and is also `ambiguous`.
_EXIT_END = {"ex": "exit", "exi": "exit", "exit": "exit", "en": "end", "end": "end"}
# Openers of the sub-modes `exit` can close without leaving configuration
# mode. After any other line, or after a body RuleHawk does not check, an
# `exit` may leave configuration mode (round 7, R6-2). The whole opener must
# match, with its required arguments (round 8, R7-4): `router` alone, `line`
# alone or `control-plane xyzzy` is rejected by the device, which then runs
# the `exit` in global mode. `_SUBMODE_WORD` is the first word only: an
# opener that starts like one but is not fully recognised makes its `exit`
# `ambiguous`. `management` is EOS / NX-OS only, so it is not here.
_SUBMODE = re.compile(
    r"(?ai)^(?:router (?:ospf|ospfv3|eigrp) [0-9]+(?: vrf \S+)?"
    r"|router bgp [0-9]+(?:\.[0-9]+)?"
    r"|router (?:rip|isis(?: \S+)?)"
    r"|line (?:vty|con|console|aux) [0-9]+(?: [0-9]+)?|line [0-9]+(?: [0-9]+)?"
    r"|route-map \S+(?: (?:permit|deny))?(?: [0-9]+)?"
    r"|class-map (?:match-any |match-all )?\S+|policy-map \S+"
    r"|control-plane(?: host| transit| cef-exception)?"
    r"|vrf (?:definition|context|instance) \S+"
    r"|mac access-list (?:extended )?\S+)$")
_SUBMODE_WORD = re.compile(
    r"(?i)^(?:router|line|route-map|class-map|policy-map|control-plane|vrf"
    r"|mac)(?: |$)")
_IF_HEADER = re.compile(r"(?i)^(in(?:t(?:e(?:r(?:f(?:a(?:ce?)?)?)?)?)?)?)$")
_ACL_HEADER = re.compile(r"(?i)^(?:ip|ipv4|ipv6) access-list(?: |$)")
_OBJGROUP_HEADER = re.compile(r"(?i)^object-group(?: |$)")
_NO_FORWARD_IF = re.compile(r"(?i)^(?:loopback|null)")


def _bad_char(ch: str) -> bool:
    cat = unicodedata.category(ch)
    if ch in (" ", "\t"):
        return False
    return cat in ("Cc", "Cf", "Zl", "Zp", "Zs")


_ASCII_DIGITS = "0123456789"


def _if_name(words: List[str]) -> Tuple[str, bool]:
    """(normalised name, is a range) from the words after `interface`."""
    if not words:
        return "?", False
    if words[0].lower() == "range":
        return "range " + "".join(words[1:]).lower(), True
    name = words[0]
    if len(words) > 1 and words[1][:1] in _ASCII_DIGITS and \
            name[-1:] not in _ASCII_DIGITS:
        name += words[1]
    return name.lower(), False


@dataclass
class CiscoLine:
    no: int                        # 1-based line number
    norm: str                      # words joined by one space
    indented: bool
    mode: str                      # global | interface | acl | objgroup | other
    iface: Optional[str] = None    # normalised name, interface mode only
    header: bool = False
    opener: int = 0                # line that opened this mode (0: start of file)
    post_end: bool = False         # after `end` / a global `exit`: not config


@dataclass
class CiscoLex:
    lines: List[CiscoLine]
    text: str                                  # one normalised line per line
    bad_chars: List[Tuple[int, int]]           # (line, code point)
    ambiguous: List[Tuple[int, str, str]]      # (line, stanza, keyword)
    headers: List[Tuple[int, str, str]]        # (line, name, header word)
    ranges: List[str]
    post_end: List[int]                        # lines after `end` / a global `exit`

    def iface_lines(self, forwarding: bool = False) -> Iterator[CiscoLine]:
        for ln in self.lines:
            if ln.mode == "interface" and not ln.header and (
                    not forwarding or not _NO_FORWARD_IF.match(ln.iface or "")):
                yield ln


def _bad_chars(text: str, allow_cr: bool) -> List[Tuple[int, int]]:
    """(line, code point) of the first control, format or separator character
    on each line, for the frontends other than Cisco (whose lexer does the
    same). A line ends at "\\n" only. A CR before it is allowed only where the
    format says it is whitespace (JSON, RFC 8259 section 2): bash and
    iptables-restore keep it as part of the last word, and PAN-OS and Junos
    line ends are not modelled."""
    out: List[Tuple[int, int]] = []
    for no, raw in enumerate(split_lines(text, keep_cr=not allow_cr), 1):
        for ch in raw:
            if _bad_char(ch):
                out.append((no, ord(ch)))
                break
    return out


def split_lines(text: str, keep_cr: bool = False) -> List[str]:
    """Config lines: split at "\n" only, one trailing "\r" dropped (kept
    with `keep_cr`, for the character check)."""
    if keep_cr:
        return text.split("\n")
    return [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")]


def cisco_lex(text: str) -> CiscoLex:
    """The one reading of a Cisco config's lines and modes that every Cisco
    check (bindings, paths, the allowlist, global features) and the ACL
    parser use.

    - Lines end at "\n" only (`split_lines`); any other control or separator
      character is recorded in `bad_chars`.
    - The mode follows the device, which ignores indentation: an `interface`
      header (or an abbreviation of it), an ACL or object-group header, a
      `_TOP_LEVEL` command or `exit` changes it wherever it is indented. `!`
      is a comment.
    - Any other unindented line inside interface, ACL or object-group mode,
      and an indented `_TOP_LEVEL` command there, is `ambiguous`: whether the
      author meant it inside the stanza is not something RuleHawk can tell.
    - Inside an ACL, any line that is not ACL-entry grammar (`_ACL_ENTRY`),
      indented or not, is `ambiguous`: the device may have run it in global
      mode and left the ACL.
    - A prefix of `exit` / `end` of two letters or more is read as that word
      and is `ambiguous`.
    - `end`, or `exit` at the global level, leaves configuration mode; every
      later line is recorded in `post_end` and flagged. So does an `exit`
      after a line that opens no known sub-mode (`hostname`, `ip route`).
      An `exit` after the body of a mode whose lines are not checked (an
      object-group, a routing process) is `ambiguous`: a body line may have
      run in global mode. Modes are still tracked after `end`, so the
      interface checks keep adding their blockers; the ACL parser reads no
      flagged line."""
    from .parse import strip_banners
    text = strip_banners(text)[0]                 # banner text is not config
    if text.startswith(_BOM):
        text = text[1:]
    lines: List[CiscoLine] = []
    bad: List[Tuple[int, int]] = []
    amb: List[Tuple[int, str, str]] = []
    headers: List[Tuple[int, str, str]] = []
    ranges: List[str] = []
    post_end: List[int] = []
    mode, iface, stanza, opener = "global", None, "global", 0
    opener_norm, body = "", False                 # opener text; indented body seen
    ended = False
    for no, raw in enumerate(split_lines(text), 1):
        for ch in raw:
            if _bad_char(ch):
                bad.append((no, ord(ch)))
                break
        words = [w for w in re.split(r"[ \t]+", raw) if w]
        norm = " ".join(words)
        if not words or words[0].startswith("!"):
            continue
        indented = raw[:1] in (" ", "\t")
        if ended:
            post_end.append(no)
        first = words[0].lower()
        if _IF_HEADER.match(words[0]):
            if indented and mode in ("interface", "acl", "objgroup"):
                amb.append((no, stanza, _keyword(norm)))
            iface, is_range = _if_name(words[1:])
            mode, stanza, opener = "interface", f"interface {iface}", no
            opener_norm, body = norm, False
            headers.append((no, iface, first))
            if is_range:
                ranges.append(iface)
            lines.append(CiscoLine(no, norm, indented, mode, iface, True, opener, ended))
            continue
        word = _EXIT_END.get(first)
        if word:
            # `exit` stays a line of the mode it leaves (so an interface
            # `exit` is checked by the allowlist, as before); `end` is global.
            if word != first:
                amb.append((no, stanza, f"{words[0]} (read as {word})"))
            if word == "end":
                if indented and mode in ("interface", "acl", "objgroup"):
                    amb.append((no, stanza, "end"))
                mode, iface = "global", None
            lines.append(CiscoLine(no, norm, indented, mode, iface, False, opener, ended))
            if word == "end" or mode == "global":
                ended = True
            elif mode in ("other", "objgroup"):
                sub = mode == "objgroup" or bool(_SUBMODE.match(opener_norm))
                if body or (not sub and _SUBMODE_WORD.match(opener_norm)):
                    # A body RuleHawk does not check, or an opener that starts
                    # like a sub-mode but is not fully recognised (R7-4).
                    amb.append((no, f"the mode of line {opener}", "exit"))
                elif not sub:
                    ended = True                  # `hostname R1` / `exit`
            mode, iface, stanza, opener = "global", None, "global", no
            opener_norm, body = norm, False
            continue
        if _TOP_LEVEL.match(norm):
            if indented and mode in ("interface", "acl", "objgroup"):
                amb.append((no, stanza, _keyword(norm)))
            iface, opener = None, no
            opener_norm, body = norm, False
            mode = ("acl" if _ACL_HEADER.match(norm) else
                    "objgroup" if _OBJGROUP_HEADER.match(norm) else "other")
            stanza = {"acl": "an ACL", "objgroup": "an object-group"}.get(
                mode, "global")
        elif not indented:
            if mode in ("interface", "acl", "objgroup"):
                # Valid in the sub-mode or not, RuleHawk cannot tell which
                # mode the device runs it in.
                amb.append((no, stanza, _keyword(norm)))
            else:
                mode, iface, stanza, opener = "other", None, "global", no
                opener_norm, body = norm, False
        else:
            body = True
            if mode == "acl" and not _ACL_ENTRY.match(norm):
                # Not an ACL entry: the device may have run it in global mode,
                # which ends the ACL (R6-1).
                amb.append((no, stanza, _keyword(norm)))
        lines.append(CiscoLine(no, norm, indented, mode, iface, False, opener, ended))
    return CiscoLex(lines, "\n".join(ln.norm for ln in lines), bad, amb,
                    headers, ranges, post_end)


# Transit packet-filter bindings, read from interface-mode lines (full
# keyword only; anything else on an interface is caught by the allowlist).
_CISCO_IF_BIND = re.compile(
    r"(?i)^(ip access-group|ipv6 traffic-filter|ipv6 access-group|"
    r"ip port access-group|ipv6 port traffic-filter|ipv4 access-group) "
    r"(\S+) (in|out|ingress|egress)(?: |$)")


def _cisco_if_state(lex: CiscoLex) -> Dict[str, Dict]:
    """Per interface, merged over every stanza in order: the ACLs bound,
    the families filtered in / out, and whether it ends up shut down."""
    st: Dict[str, Dict] = {}
    for _, name, _w in lex.headers:
        st.setdefault(name, {"bound": set(), "in": set(), "out": set(),
                             "shut": False})
    for ln in lex.iface_lines():
        s = st[ln.iface]
        low = ln.norm.lower()
        if low == "shutdown":
            s["shut"] = True
        elif low == "no shutdown":
            s["shut"] = False
        m = _CISCO_IF_BIND.match(ln.norm)
        if m:
            s["bound"].add(m.group(2))
            fam = 6 if m.group(1).lower().startswith("ipv6") else 4
            s["in" if m.group(3).lower() in ("in", "ingress") else "out"].add(fam)
    return st


# --------------------------------------------------------------------------- #
# Cisco IOS / ASA / NX-OS / EOS: bindings and roles
# --------------------------------------------------------------------------- #
# The ASA forms are global commands.
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


# Positive dialect identification (review of #42, round 10, R9-1, R9-3). A
# Cisco PASS needs a line that only the labelled dialect writes; a label that
# came from a heuristic or the `ios-asa` default is a guess, and the guess
# decides which entry grammar reads the ACLs. Each marker, where it is cited:
_DIALECT_MARKERS = {
    "ios-asa": [
        # IOS `show running-config` (Cisco 800 Series ISR Software
        # Configuration Guide, "Basic Router Configuration"): "Building
        # configuration...", "Current configuration : 986 bytes",
        # "version 12.4", "boot-start-marker".
        # https://www.cisco.com/c/en/us/td/docs/routers/access/800/software/configuration/guide/SCG800Guide/SCG800_Guide_BookMap_chapter_010.html
        re.compile(r"(?m)^Building configuration\.\.\.[ \t\r]*$"),
        re.compile(r"(?m)^Current configuration : \d+ bytes[ \t\r]*$"),
        re.compile(r"(?m)^version \d+\.\d+[ \t\r]*$"),
        re.compile(r"(?m)^boot-start-marker[ \t\r]*$"),
        # IOS ACL headers `ip access-list { extended | standard } NAME`
        # (Catalyst 9400 IOS XE 16.10 command reference,
        # https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9400/software/release/16-10/command_reference/b_1610_9400_cr/security_commands.html);
        # NX-OS has no type word (NX-OS 10.5 security guide,
        # https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus3600/105x/configuration/security/cisco-nexus-3600-switch-nx-os-security-configuration-guide-105x/m-configuring-ip-acls.html). `standard` is left out: whether
        # EOS has a `standard` header is not cited.
        re.compile(r"(?m)^ip access-list extended \S+[ \t\r]*$"),
        # Numbered `access-list N {deny | permit | remark}` (IOS command
        # reference, `access-list (IP extended)`,
        # https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/access-list.htm);
        # NX-OS and EOS have only
        # named ACLs.
        re.compile(r"(?m)^access-list \d+ (?:permit|deny|remark)\s"),
        # ASA: ": Saved", "ASA Version 9.1(5)4" (Cisco document 72273,
        # "Configure DNS Doctoring for Three NAT Interfaces on ASA",
        # https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/72273-dns-doctoring-3zones.html)
        # and `access-list NAME extended | standard` (ASA 9.20 firewall
        # configuration guide,
        # https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config.pdf).
        re.compile(r"(?m)^ASA Version \d"),
        re.compile(r"(?m)^: Saved[ \t\r]*$"),
        re.compile(r"(?m)^access-list \S+ (?:extended|standard) "),
    ],
    "nxos": [
        # NX-OS `show running-config`: "version 9.3(1) Bios:version 05.39"
        # (Nexus 9000 NX-OS 9.3(x) System Management Configuration Guide,
        # "Configuration Replace and Commit-timeout",
        # https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/system-management/b-cisco-nexus-9000-series-nx-os-system-management-configuration-guide-93x/b-cisco-nexus-9000-series-nx-os-system-management-configuration-guide-93x_chapter_011000.html),
        # and the `feature` command ("switch(config)# feature interface-vlan",
        # "Enable the VLAN network interface feature using the feature
        # interface-vlan configuration", Nexus 9000 NX-OS 9.3(x) Interfaces
        # Configuration Guide, VLAN interfaces,
        # https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/interfaces/configuration/guide/b-cisco-nexus-9000-nx-os-interfaces-configuration-guide-93x/b-cisco-nexus-9000-nx-os-interfaces-configuration-guide-93x_chapter_0101.html). `interface EthernetN/N` is not one: IOS names Ethernet
        # ports the same way.
        re.compile(r"(?m)^version \d+\.\d+\(\d+\)"),
        re.compile(r"(?m)^feature \S+[ \t\r]*$"),
    ],
    "eos": [
        # EOS `show running-config`: "! device: r1 (cEOSLab, EOS-4.33.1F-...)"
        # (third-party: the annet tutorial,
        # https://annetutil.github.io/annet/main/usage/tutorial.html; Arista's
        # manual is behind a bot challenge). `! Command: show running-config`
        # is not one: NX-OS writes `!Command: show running-config` too.
        re.compile(r"(?m)^! device: \S+ \(.*\bEOS-\d"),
    ],
}


def dialect_unidentified(text: str, label: str) -> str:
    """Why the Cisco `label` is not positively identified, or "" when a line
    only that dialect writes is in the config (outside banners and after-`end`
    lines) and no other dialect's marker is."""
    from .parse import strip_banners
    body = strip_banners(text)[0]
    lex = cisco_lex(text)
    if lex.post_end:
        body = "\n".join(split_lines(body)[:lex.post_end[0] - 1])
    found = {d for d, rxs in _DIALECT_MARKERS.items() if any(rx.search(body) for rx in rxs)}
    if found == {label}:
        return ""
    if label not in found:
        return (f"the config's dialect is not positively identified: no line that "
                f"only {label} writes (a `show running-config` banner, version line "
                f"or a header form only {label} has) is in it, so the {label} label "
                f"is a guess and the entry grammar that reads its ACLs may be the "
                f"wrong one")
    others = ", ".join(sorted(found - {label}))
    return (f"the config's dialect is not positively identified: it holds markers "
            f"of {label} and of {others}")


_SHUTDOWN_ONLY = "bound only on a shutdown interface"


def _cisco_bindings(lex: CiscoLex) -> Tuple[Set[str], Dict[str, str]]:
    """(ACLs with a transit binding, ACL -> first non-transit role). A
    binding on an interface that ends up `shutdown` filters nothing, so an
    ACL bound only there has no transit binding."""
    transit: Set[str] = set()
    other: Dict[str, str] = {}
    shut_bound: Set[str] = set()
    for s in _cisco_if_state(lex).values():
        (shut_bound if s["shut"] else transit).update(s["bound"])
    for ln in lex.lines:
        if ln.mode == "interface" and _CISCO_IF_BIND.match(ln.norm):
            continue
        m = _ASA_BIND.match(ln.norm)
        if m:
            transit.add(m.group(1))
            continue
        for role, rx in _CISCO_NON_TRANSIT:
            m = rx.match(ln.norm)
            if m:
                other.setdefault(m.group(1), role)
                break
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


def _cisco_paths(lex: CiscoLex) -> Dict[str, Dict[str, Set[int]]]:
    """Every forwarding interface that is not shut down carries both
    families (the model never reads addresses: if it ever does, a
    `no ip address` must be applied there, not skipped)."""
    return {n: {"fams": {4, 6}, "in": s["in"], "out": s["out"]}
            for n, s in _cisco_if_state(lex).items()
            if not s["shut"] and not _NO_FORWARD_IF.match(n)}


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

    for words in _junos_leaves(text):
        leaf(words)
    return paths


def _junos_leaves(text: str) -> Iterator[List[str]]:
    """Every Junos statement as its full hierarchy path of words: a `set`
    line without `set`, or the enclosing block words plus the statement."""
    from .parse_junos import _tokenize
    for raw in split_lines(text):
        if re.match(r"^\s*set\s", raw):
            yield raw.split()[1:]
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
            yield [w for part in stack for w in part] + stmt
            stmt = []
        else:
            stmt.append(t)


def _junos_filter_redefined(text: str) -> Optional[str]:
    """An interface unit and family whose `filter input` (or `output`) names
    two different filters (round 10, R9-2). Juniper, "filter (Applying to a
    Logical Interface)",
    https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/filter-edit-interfaces-unit-family.html:
    `input filter-name`, "Name of one filter to evaluate
    when packets are received on the interface" (and `output` likewise); a
    second value is not one filter, and which one holds is not cited."""
    seen: Dict[Tuple[str, str, str, str], Set[str]] = {}
    for words in _junos_leaves(text):
        words = [w.strip('"') for w in words]
        if "interfaces" not in words or "filter" not in words:
            continue
        k = words.index("interfaces")
        if k + 1 >= len(words):
            continue
        rest = words[k + 2:]
        if "filter" not in rest:
            continue
        unit = rest[rest.index("unit") + 1] if "unit" in rest and \
            rest.index("unit") + 1 < len(rest) else "0"
        fam = rest[rest.index("family") + 1] if "family" in rest and \
            rest.index("family") + 1 < len(rest) else ""
        tail = rest[rest.index("filter") + 1:]
        if len(tail) >= 2 and tail[0] in ("input", "output"):
            key = (words[k + 1], unit, fam, tail[0])
            seen.setdefault(key, set()).add(tail[1])
    for (ifname, unit, fam, d), names in sorted(seen.items()):
        if len(names) > 1:
            return (f"interface {ifname} unit {unit} family {fam or '?'}: `filter "
                    f"{d}` is set more than once ({', '.join(sorted(names))}); it "
                    f"names one filter, and which one the device keeps is not "
                    f"cited — not modelled")
    return None


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

    for raw in split_lines(text):
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


# Junos statement keywords RuleHawk's Junos frontend reads or relies on.
# Junos keywords are lower-case only; an upper-case spelling is a syntax error
# on the device, and the frontend would skip the statement, so it is blocked
# (junos-keyword-case). Only the first word of a statement is checked: names
# (interfaces, filters, terms) may be any case.
_JUNOS_KW = frozenset("""
interfaces unit family inet inet6 filter input output input-list output-list
firewall term from then accept discard reject next count log inactive
security policies zones nat services groups apply-groups logical-systems
routing-instances system protocols policy-options address source-address
destination-address protocol destination-port source-port port vlan-id
vlan-tagging set delete deactivate activate insert replace edit prefix-list
source-prefix-list destination-prefix-list ethernet-switching bridge vpls
mpls iso ccc encapsulation description disable tcp-established
icmp-type icmp-code fragment-flags is-fragment first-fragment tcp-flags
""".split())


def _junos_keyword_case(text: str) -> Optional[str]:
    from .parse_junos import _tokenize
    toks = _tokenize(text)
    starts = [0] + [i + 1 for i, t in enumerate(toks) if t in ("{", "}", ";")]
    words = [toks[i] for i in starts if i < len(toks)]
    words += [ln.split()[0] for ln in split_lines(text) if ln.split()]
    for w in words:
        w = w.rstrip(":")
        if w.lower() in _JUNOS_KW and w != w.lower():
            return w
    # Round 10: a top-level statement is always a fixed hierarchy keyword (no
    # user-chosen name sits at the top of the hierarchy), so an upper-case
    # word there is a statement the device rejects, wherever it is off the
    # evaluated path (`SNMP { ... }`, `set SNMP ...`).
    depth = 0
    for i, tk in enumerate(toks):
        if tk == "{":
            depth += 1
        elif tk == "}":
            depth = max(depth - 1, 0)
        elif depth == 0 and (i == 0 or toks[i - 1] in ("{", "}", ";")) \
                and tk != tk.lower() and tk[:1].isalpha():
            return tk
    for ln in split_lines(text):
        w = ln.split()
        if len(w) > 1 and w[0] in ("set", "delete", "deactivate", "activate") \
                and w[1] != w[1].lower():
            return w[1]
    # Interface names are lower case too (ge-0/0/0, ae0, lo0, irb): one with
    # an upper-case letter does not name the device's interface.
    for name in _junos_interface_names(toks, text):
        if name != name.lower():
            return name
    return None


def _junos_interface_names(toks: List[str], text: str) -> List[str]:
    out = [m.group(1) for m in re.finditer(
        r"(?m)^\s*(?:set|delete|deactivate|activate)\s+interfaces\s+(\S+)", text)]
    for i, tk in enumerate(toks):
        if tk.lower() != "interfaces" or toks[i + 1:i + 2] != ["{"]:
            continue
        depth, j, at_start = 0, i + 1, False
        while j < len(toks):
            if toks[j] == "{":
                depth += 1
                at_start = depth == 1
            elif toks[j] == "}":
                depth -= 1
                if depth == 0:
                    break
                at_start = depth == 1
            elif toks[j] == ";":
                at_start = depth == 1
            elif at_start:
                if toks[j] not in ("inactive:", "interface-range"):
                    out.append(toks[j])
                at_start = False
            j += 1
    return out


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
    r"ip address [0-9.]+(?: [0-9.]+|/[0-9]{1,2})(?: secondary)?",
    r"ipv6 address [0-9a-f:]+/[0-9]{1,3}(?: eui-64)?",
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
    # Physical layer: link speed, duplex and the connector (rj45, sfp,
    # auto-select) do not select packets. One word, so nothing hides after it.
    r"speed (?:auto|[0-9]+)", r"duplex (?:auto|full|half)", r"negotiation auto",
    r"media-type [A-Za-z0-9-]+",
    # Removing an address. The path model never reads addresses (every
    # forwarding interface carries both families), so a removal can only take
    # away a path the model already counts. If the model ever reads
    # addresses, this must be applied there, not skipped.
    r"no ip address", r"no ip address [0-9.]+ [0-9.]+(?: secondary)?",
    # Counter sampling interval only.
    r"load-interval [0-9]+",
    # Turning off messages the router itself originates: ICMP unreachables
    # and redirects (RFC 1812 sections 5.2.7.1 and 5.2.7.2) and proxy-ARP
    # replies (RFC 1027). None of them lets a transit packet through or
    # stops one.
    r"no ip redirects", r"no ip unreachables", r"no ip proxy-arp",
    r"no ipv6 redirects", r"no ipv6 unreachables",
    # CDP is a link-local discovery protocol the device terminates.
    r"cdp enable", r"no cdp enable",
]
# ASCII: `[A-Za-z]` under IGNORECASE would otherwise also match the Kelvin
# sign and the long s, and the entries name ASCII digits only.
_IF_ALLOW_RX = re.compile("(?ai)(?:" + "|".join(_IF_ALLOW) + ")")
# Words after which the next word is still part of the keyword, so the detail
# names `ip verify` or `no ip access-gr`, never an argument (an ACL name, an
# address).
_KW_PREFIX = frozenset({"no", "default", "ip", "ipv4", "ipv6", "mpls",
                        "switchport", "crypto", "tunnel", "service-policy",
                        "zone-member"})
_KW_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


def _keyword(line: str) -> str:
    out: List[str] = []
    for t in line.split():
        if len(out) == 3 or not _KW_TOKEN.match(t):
            break
        out.append(t.lower())
        if t.lower() not in _KW_PREFIX:
            break
    return " ".join(out) or "(not a keyword)"


def _cisco_unallowed(lex: CiscoLex) -> List[str]:
    """`interface: keyword` for each interface line not on the allowlist,
    each abbreviated `int X` header and each `interface range`."""
    out: List[str] = []

    def add(item: str) -> None:
        if item not in out:
            out.append(item)
    for _, name, word in lex.headers:
        if word != "interface":
            add(f"{name}: {word} (abbreviated interface)")
    for name in lex.ranges:
        add(f"{name}: interface range")
    # Line accounting (round 8): every line of a forwarding interface is in
    # scope; an allowlisted line (whole line, every word) is consumed, any
    # other is noted by this blocker.
    led = Ledger("cisco-interface")
    for ln in lex.iface_lines(forwarding=True):
        led.add(ln.no, ln.norm)
        if not _IF_ALLOW_RX.fullmatch(ln.norm):
            add(f"{ln.iface}: {_keyword(ln.norm)}")
            led.note(ln.no)
        else:
            led.consume(ln.no)
    rest: List[str] = []
    led.close(rest)
    for item in rest:
        add(item)
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
    ("vlan-filter", re.compile(r"(?im)^\s*(vlan\s+(?:filter|access-map))\b")),
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

    if v not in _CISCO:
        bad = _bad_chars(text, allow_cr=(v == "aws-sg"))
        if bad:
            no, cp = bad[0]
            b.append(Reason("parse-note",
                            f"line {no}: character U+{cp:04X} is not part of a "
                            f"config line RuleHawk can read (a line ends at "
                            f"\\n only); {len(bad)} line(s)"))

    if v in _CISCO:
        why = dialect_unidentified(text, v)
        if why:
            b.append(Reason("parse-note", why))
        lex = cisco_lex(text)
        text = lex.text                        # normalised lines, banners blank
        if lex.bad_chars:
            no, cp = lex.bad_chars[0]
            b.append(Reason("parse-note",
                            f"line {no}: character U+{cp:04X} is not part of a "
                            f"config line RuleHawk can read (a line ends at "
                            f"\\n only); {len(lex.bad_chars)} line(s)"))
        if lex.ambiguous:
            no, where, kw = lex.ambiguous[0]
            more = (f" (+{len(lex.ambiguous) - 1} more)" if len(lex.ambiguous) > 1
                    else "")
            b.append(Reason("stanza-boundary-ambiguous",
                            f"line {no}: `{kw}` in {where}" + more))
        if lex.post_end:
            b.append(Reason("parse-note",
                            f"line {lex.post_end[0]}: after `end` (or a global "
                            f"`exit`), so not configuration; "
                            f"{len(lex.post_end)} line(s)"))
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
        unallowed = _cisco_unallowed(lex)
        if unallowed:
            more = (f" (+{len(unallowed) - 3} more)" if len(unallowed) > 3 else "")
            b.append(Reason("interface-feature-unmodeled",
                            "; ".join(unallowed[:3]) + more))
        transit, other = _cisco_bindings(lex)
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
            _path_blockers(ctx, _cisco_paths(lex))
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
        kw = _junos_keyword_case(text)
        if kw:
            b.append(Reason("junos-keyword-case", kw.lower()))
        inactive = _junos_inactive(text)
        if inactive:
            b.append(Reason("acl-binding-negated", inactive[0][:120]))
        if _NAT["junos"].search(text):
            b.append(Reason("nat-present"))
        redef = _junos_filter_redefined(text)
        if redef:
            b.append(Reason("parse-note", redef))
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
    "On every vendor a line ends at \\n only, and a control or separator "
    "character on any line is UNKNOWN (a CR before the newline is accepted "
    "only in Cisco configs and AWS JSON); each line on the evaluated path (a "
    "Cisco ACL, ACL header, flat access-list or forwarding interface line, "
    "any other Cisco line that names an ACL, every iptables and PAN-OS line, "
    "every statement of a Junos term and any Junos stanza that names a "
    "filter) is consumed by a handler or makes the answer UNKNOWN; a "
    "handler's forms follow a cited vendor document where one is named in "
    "the code (EOS has none), so a consumed line is not proven against the "
    "whole vendor grammar; object-group bodies are not in that accounting, "
    "and every ACL entry that references an object-group is UNKNOWN",
    "A Cisco PASS needs the dialect positively identified: a line only that "
    "dialect writes (IOS `Building configuration...`, `Current "
    "configuration :`, `version X.Y`, `boot-start-marker`, an `ip "
    "access-list extended` header or a numbered `access-list N` line; ASA "
    "`ASA Version`, `: Saved` or `access-list NAME extended|standard`; NX-OS "
    "`version X.Y(Z)` or `feature`; EOS `! device: ... EOS-`) outside banners "
    "and before `end`, and no line of another dialect; a label from a "
    "heuristic, the `ios-asa` default or `--vendor` alone is UNKNOWN, and so "
    "is an ACL header form the identified dialect does not have (an untyped "
    "`ip access-list NAME` on IOS, a typed one on NX-OS or EOS)",
    "A field that holds one value, set more than once with different values, "
    "is UNKNOWN unless the replace semantics are cited (iptables -P is): a "
    "PAN-OS service protocol, port or source-port, rule action, disabled or "
    "negate flag, or address value; a Junos interface `filter input` or "
    "`output`; an iptables rule option given twice or a chain declared twice "
    "in one iptables-restore block; a PAN-OS list holding `any` and another "
    "member is UNKNOWN; a port name is read only from the vendor's cited "
    "table for that protocol (IOS, ASA, Junos) and is UNKNOWN elsewhere "
    "(NX-OS, EOS, PAN-OS, iptables)",
    "Cisco reads ACLs, allowlisted interface lines and the listed global "
    "features (zone firewall, ip inspect, service-policy, policy routing, "
    "MPLS / xconnect, VLAN filters, NAT); interface, ACL and object-group "
    "mode end at a header, `exit` or a recognised top-level command, "
    "indented or not; inside an ACL a line is read only if it is a `permit` "
    "or `deny` entry, a `remark` or `exit`, with the sequence-number form of "
    "its vendor and family (`N` on IOS IPv4, NX-OS and EOS, `sequence N` on "
    "IOS IPv6) and a number in range (1-2147483647 on IOS IPv4 and EOS, "
    "1-4294967295 on IOS IPv6 and NX-OS, no leading zero); an unnumbered "
    "entry is numbered the last number + 10 on IOS IPv4 and NX-OS and the "
    "ACL is evaluated in number order; on EOS and IOS IPv6 an ACL that mixes "
    "numbered and unnumbered entries is UNKNOWN; `no N` (IOS IPv4, NX-OS, "
    "EOS) and `no sequence N` (IOS IPv6) delete that entry; NX-OS "
    "`statistics per-entry` is read on NX-OS only; keywords are "
    "case-insensitive on IOS, and on NX-OS and EOS a keyword not in lower "
    "case is UNKNOWN; an IPv4 `A/len` operand in an IOS `extended` / "
    "`standard` or numbered ACL or on an ASA line, and anything after `log` "
    "other than the ASA log arguments on an ASA line, are UNKNOWN; an ACL "
    "whose number order differs from its text, that has a deletion, or where "
    "a remark and an entry share a number, and every other line in an ACL "
    "(`default`, `evaluate`, `dynamic`, `resequence`, another `no` or "
    "sequence form, any other command), are UNKNOWN; a line outside ACL mode "
    "that names an ACL is UNKNOWN unless it is `access-class`, `match ip "
    "address`, `snmp-server community` or ASA `access-group`; any other line "
    "in interface mode, an unindented line in those modes that is not a "
    "recognised top-level command, `ex` or `en` for `exit` or `end`, an "
    "`exit` after a line that opens no known sub-mode, after an opener that "
    "is not complete (`router`, `line vty`) or after a sub-mode body that is "
    "not checked, and any line after `end` are UNKNOWN; other global "
    "commands are not read",
    "PAN-OS resolves an object name only in the rule's own vsys or "
    "device-group and in shared; device-group inheritance is not followed; a "
    "quoted name with leading or trailing whitespace, and an address object "
    "with a word after its value, are UNKNOWN",
    "iptables reads the filter table; a chain's policy comes only from a "
    "parsed -P or :CHAIN line naming a built-in chain and ACCEPT or DROP "
    "(exact case), with nothing after the policy; in an iptables-restore "
    "file only the exact line `COMMIT` commits, only a line that starts with "
    "`#` is a comment and only an empty line is skipped; an iptables-restore "
    "table block without `COMMIT`, and a line outside a table block, are "
    "UNKNOWN",
    "Junos reads firewall filters and their interface bindings; in a term "
    "the latest terminating action wins and a term with more than one is "
    "noted; a term statement other than `from`, `then` and `filter`, a "
    "then-action with an argument count the model does not have, a term name "
    "used twice in a filter, `protect:`, a stanza outside `firewall` and "
    "`interfaces` that names a filter, SRX security zones or policies, a "
    "comment marker, brace, bracket or `;` inside a quoted string, a `#` "
    "glued to a word, and braces that do not balance make the answer UNKNOWN",
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
