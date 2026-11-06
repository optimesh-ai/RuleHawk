"""Parse Cisco IOS extended/standard ACLs, IPv6 ACLs and Cisco ASA access-lists
into `ACE`s.

Address operand forms: `any` | `host A.B.C.D` | `A.B.C.D/len` | `A.B.C.D MASK`.
The `A.B.C.D MASK` form is the tricky one: IOS uses an INVERSE wildcard
(`0.0.0.255`) while ASA uses a NORMAL subnet mask (`255.255.255.0`). We
auto-detect by the mask's bit pattern rather than guessing the vendor; a
non-contiguous or genuinely ambiguous mask marks the entry `imprecise` and emits
a parse note, so it can never be used to (wrongly) prove another rule dead.

Service port operators are modeled honestly and, where soundly possible,
PRECISELY: `eq`/`range` -> one exact range; `lt P` -> [MIN, P-1]; `gt P` ->
[P+1, MAX]; `neq P` -> the EXACT union of [MIN, P-1] and [P+1, MAX] (expanded to
one ACE per sub-range, so it stays exact, never widened). `established` ->
stateful. ICMP type qualifiers are captured so `echo` and `echo-reply` aren't
treated as the same packet space.
Unmodeled lines (object-group, etc.) are surfaced as notes, never silently dropped.
Match-narrowing trailing qualifiers (`fragments`, `time-range`, `dscp`, `tos`,
`precedence`, `ttl`) restrict what an ACE matches on a real device; they are not
modeled, so the ACE is marked `imprecise` (fail closed) — a narrowed deny can
never silently prove a segment isolated, and a narrowed permit can never assert
a concrete violation. Any OTHER unrecognized trailing token (a TCP flag such as
`syn`/`ack`, an `eq`-list service name outside the named-port table, pasted
`show access-list` residue) also marks the ACE `imprecise` with a note — never
silently ignored. `log`/`log-input` (including ASA log arguments) never narrow
and stay exact.
"""

from __future__ import annotations

import contextvars
import ipaddress
import re
from typing import List, Optional, Tuple

from .failclosed import _EXIT_END, cisco_dialect_ambiguous, cisco_lex, split_lines
from .model import (ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet,
                    _PORTED)

# IANA protocol numbers Cisco IOS/ASA/NX-OS/EOS accept verbatim in the proto
# slot (`permit 47 ...` == `permit gre ...`). Cisco keeps the raw number in the
# config; RuleHawk normalizes so a numeric proto matches a named-proto policy
# assertion — the Junos/iptables frontends already do this via their own maps.
_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
              "51": "ah", "58": "icmpv6", "88": "eigrp", "89": "ospf",
              "103": "pim", "112": "vrrp", "132": "sctp"}


def _norm_proto(tok: str) -> str:
    """Lower-case a Cisco proto token and fold a numeric protocol to its name."""
    t = tok.lower()
    return _PROTO_NUM.get(t, t)


# Canonical ICMP type: fold the IOS keyword forms and their numeric equivalents
# to ONE token so `echo`, `echo-request` and `8` compare equal (covers() and the
# segmentation search treat the type as an opaque string). A type we don't map is
# passed through unchanged (still exact against an identical spelling; a differing
# spelling merely under-reports coverage — sound). ICMP *code* keeps the
# TYPE/CODE form the caller builds.
_ICMP_TYPE_CANON = {
    "8": "echo", "echo-request": "echo", "echo": "echo",
    "0": "echo-reply", "echo-reply": "echo-reply",
    "3": "unreachable", "unreachable": "unreachable",
    "5": "redirect", "redirect": "redirect",
    "11": "time-exceeded", "time-exceeded": "time-exceeded",
    "time-exceeded-in-transit": "time-exceeded",
    "12": "parameter-problem", "parameter-problem": "parameter-problem",
    "13": "timestamp-request", "timestamp-request": "timestamp-request",
    "14": "timestamp-reply", "timestamp-reply": "timestamp-reply",
    "4": "source-quench", "source-quench": "source-quench",
    "9": "router-advertisement", "router-advertisement": "router-advertisement",
    "10": "router-solicitation", "router-solicitation": "router-solicitation",
    # IOS / NX-OS names that pin the CODE too
    "ttl-exceeded": "time-exceeded/0", "reassembly-timeout": "time-exceeded/1",
    "net-unreachable": "unreachable/0", "host-unreachable": "unreachable/1",
    "protocol-unreachable": "unreachable/2", "port-unreachable": "unreachable/3",
    "packet-too-big": "unreachable/4", "source-route-failed": "unreachable/5",
    "administratively-prohibited": "unreachable/13",
}
_ICMP_CANON_NAMES = {v.partition("/")[0] for v in _ICMP_TYPE_CANON.values()}


def _canon_icmp_type(tok: Optional[str], proto: str = "icmp") -> Optional[str]:
    """Canonical ICMP type string, or None when an ICMPv4 name is unknown (the
    caller then treats the token as an unrecognized qualifier: imprecise,
    any type — never an exact type that matches nothing)."""
    if tok is None:
        return None
    t = tok.lower()
    if "/" in t:                       # TYPE/CODE — canonicalize the type half
        ty, _, code = t.partition("/")
        out = f"{_ICMP_TYPE_CANON.get(ty, ty)}/{code}"
    else:
        out = _ICMP_TYPE_CANON.get(t, t)
    if proto == "icmp":
        ty, _, code = out.partition("/")
        if not (ty.isdigit() or ty in _ICMP_CANON_NAMES) or (code and not code.isdigit()):
            return None
    return out


_NAMED_PORTS = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "dns": 53, "tftp": 69, "http": 80, "www": 80, "pop3": 110,
    "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139,
    "snmp": 161, "snmptrap": 162, "bgp": 179, "ldap": 389, "https": 443,
    "microsoft-ds": 445, "isakmp": 500, "syslog": 514, "rip": 520,
    "ldaps": 636, "mssql": 1433, "sqlnet": 1521, "mysql": 3306, "rdp": 3389,
    "postgres": 5432, "postgresql": 5432, "redis": 6379, "rtsp": 554,
    "vnc": 5900, "sip": 5060, "elasticsearch": 9200, "mongodb": 27017,
    "memcached": 11211, "nfs": 2049, "winrm": 5985,
    # Arista EOS names (its default control-plane ACL uses them)
    "bfd": 3784, "bfd-echo": 3785, "multihop-bfd": 4784, "micro-bfd": 6784,
    "sbfd": 7784, "mlag": 4432, "ldp": 646, "msdp": 639, "lsp-ping": 3503,
    "netconf-ssh": 830,
    "bootps": 67, "bootpc": 68, "imap4": 143, "imap": 143, "sunrpc": 111,
    "nntp": 119, "lpd": 515, "non500-isakmp": 4500, "tacacs": 49, "time": 37,
    "whois": 43, "finger": 79, "gopher": 70, "echo": 7, "discard": 9,
    "chargen": 19, "ident": 113, "irc": 194, "klogin": 543, "kshell": 544,
    "login": 513, "cmd": 514, "talk": 517, "uucp": 540,
    "pim-auto-rp": 496, "xdmcp": 177, "radius": 1812, "radius-acct": 1813,
}
_ACTIONS = ("permit", "deny")
# Match-NARROWING trailing qualifiers: on a real device each of these RESTRICTS
# the packets the ACE matches (`fragments` -> non-initial fragments only,
# `time-range` -> only inside the named window, dscp/tos/precedence/ttl -> only
# matching-marked packets). Modeling such an ACE full-width is unsound: a
# narrowed DENY evaluated full-width shadows a later broad permit and lets
# segcheck FALSE-PASS a real leak. We don't model the narrowing itself; we mark
# the ACE `imprecise` so downstream checks fail closed (indeterminate), exactly
# like the iptables frontend does for `-f`/unknown options. `log`/`log-input`
# do NOT narrow (stay exact); `established` is modeled exactly via `stateful`;
# `inactive` (ASA) disables the rule on the device entirely (caller skips it).
_NARROWING_QUALS = {"fragments", "time-range", "dscp", "tos", "precedence",
                    "ttl"}
# Trailing keywords that CONSUME following argument token(s), so the argument is
# never mistaken for an ICMP type (`time-range WORKHOURS` is not type
# "WORKHOURS"). `ttl` takes an operator plus value(s) and is handled inline.
_QUAL_ARGC = {"time-range": 1, "dscp": 1, "tos": 1, "precedence": 1}
# Surfaced whenever a port operator could not be modeled exactly (an `eq` /
# `range` / `neq` service name outside the named-port table, or a degenerate
# `gt 65535` / `lt 0`): the unmodeled port(s) are treated as ANY and the ACE
# is marked imprecise. Widening silently left no audit trail — the only trace
# was a segmentation INDETERMINATE with no stated cause.
_PORT_OP_NOTE = ("port operator not modeled exactly (unknown service name or "
                 "degenerate bound) — unmodeled port(s) treated as ANY, marked "
                 "imprecise, verify manually: ")

_ANY_NET = ipaddress.ip_network("0.0.0.0/0")
_ANY6_NET = ipaddress.ip_network("::/0")


def _scan_trailer(rest: List[str]
                  ) -> Tuple[List[str], Optional[str], List[str], bool, bool]:
    """Scan an ACE's trailing tokens. Returns (narrowing, first_type_token,
    extra_unknown, stateful, inactive): `narrowing` lists the match-narrowing
    qualifiers present (caller marks the ACE imprecise), `first_type_token` is
    the first token that is neither a known trailing keyword nor a consumed
    keyword argument (the ICMP type slot for icmp ACEs), and `extra_unknown`
    lists every FURTHER such token. Unrecognized trailing tokens are a
    false-PASS hazard: a TCP flag (`syn`/`ack`/`rst`/`match-any`), an `eq`-list
    service name outside our table, or pasted `show access-list` residue all
    NARROW or EXTEND what the device really matches, so the caller must treat
    them as unknown (fail closed -> imprecise), never silently ignore them. ASA
    `log` arguments ([level] [interval N] | disable | default) are consumed so
    an exact logged ACE is not falsely flagged. `established` -> stateful;
    `inactive` (ASA) -> the rule is disabled on the device (caller skips it).
    A numeric type token immediately followed by a numeric code is paired as
    "TYPE/CODE" — distinct ICMP codes must never compare equal (covers() uses
    string equality)."""
    narrowing: List[str] = []
    first_type: Optional[str] = None
    extra_unknown: List[str] = []
    stateful = inactive = False
    j = 0
    while j < len(rest):
        t = rest[j].lower()
        if t in _NARROWING_QUALS:
            narrowing.append(t)
            if t == "ttl":
                # ttl OP V [V2]: consume the operator and one value (two for
                # `range`).
                j += 1
                if j < len(rest):
                    op = rest[j].lower()
                    j += 1 + (2 if op == "range" else 1)
                continue
            j += 1 + _QUAL_ARGC.get(t, 0)
            continue
        if t in ("log", "log-input"):
            # `log` never narrows the match; what may follow it depends on
            # the dialect (review of #42, round 9, R8-6). A word that is not
            # in the dialect's cited grammar is left for the unknown-token
            # check (imprecise + note).
            d = _DIALECT.get()
            j += 1
            if d == "asa":
                if t == "log-input":
                    # Not in the ASA grammar (below): an unknown word.
                    extra_unknown.append(rest[j - 1])
                    continue
                # ASA: `log [[level] [interval secs] | disable | default]`,
                # level 0-7, interval 1-600. Cisco Secure Firewall ASA
                # Firewall CLI Configuration Guide 9.20, "Access Control
                # Lists" (https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config.pdf):
                # "level—A severity level between 0 and 7" and "interval
                # secs—The time interval in seconds between syslog messages,
                # from 1 to 600".
                if j < len(rest) and rest[j].lower() in ("disable", "default"):
                    j += 1
                    continue
                if j < len(rest) and rest[j].isdigit() and 0 <= int(rest[j]) <= 7:
                    j += 1
                if (j + 1 < len(rest) and rest[j].lower() == "interval"
                        and rest[j + 1].isdigit() and 1 <= int(rest[j + 1]) <= 600):
                    j += 2
                continue
            # IOS, NX-OS, EOS: nothing after `log` / `log-input` is read. (An
            # IOS command reference has `log [word]`, a cookie; a word there
            # stays noted, as in round 7: no lift.)
            continue
        if t == "established":
            stateful = True
            j += 1
            continue
        if t == "inactive":
            inactive = True
            j += 1
            continue
        if first_type is None:
            if rest[j].isdigit() and j + 1 < len(rest) and rest[j + 1].isdigit():
                first_type = f"{rest[j]}/{rest[j + 1]}"      # type + code
                j += 1
            else:
                first_type = rest[j]
        else:
            extra_unknown.append(rest[j])
        j += 1
    return narrowing, first_type, extra_unknown, stateful, inactive


def _port_num(tok: str) -> int:
    if tok.isdigit():
        return max(PORT_MIN, min(PORT_MAX, int(tok)))
    return _NAMED_PORTS.get(tok.lower(), -1)


def _is_port_token(tok: str) -> bool:
    """True if `tok` looks like a port literal (a number or a known service
    name) — used to detect the trailing ports of a multi-port `eq a b c`."""
    return tok.isdigit() or tok.lower() in _NAMED_PORTS


def _classify_mask(mask: str) -> Tuple[int, str]:
    """Return (prefix_len, kind) for a dotted mask.

    kind: "netmask" (ASA, 255.255.255.0), "wildcard" (IOS, 0.0.0.255),
    "ambiguous" (0.0.0.0 / 255.255.255.255 — both readings valid but differ),
    or "noncontiguous" (not a valid mask either way).
    """
    try:
        bits = int(ipaddress.IPv4Address(mask))
    except ipaddress.AddressValueError:
        return 32, "noncontiguous"
    pc = bin(bits).count("1")
    netmask = (0xFFFFFFFF << (32 - pc)) & 0xFFFFFFFF if pc else 0
    wildcard = (1 << pc) - 1
    is_nm, is_wc = (bits == netmask), (bits == wildcard)
    if is_nm and is_wc:
        # Only 0.0.0.0 or 255.255.255.255 satisfy both readings. With a nonzero
        # address these denote a single host (/32): the IOS wildcard-0.0.0.0 /
        # ASA /32-netmask idioms. (_parse_addr special-cases address 0.0.0.0,
        # where both real-world idioms mean "any".)
        return 32, "host"
    if is_nm:
        return pc, "netmask"
    if is_wc:
        return 32 - pc, "wildcard"
    # Non-contiguous (a legal IOS wildcard, e.g. 0.255.0.255): the COVERING
    # prefix is the mask's leading-zero run — every matched address differs from
    # the base only in mask-1 bits, all of which lie below that run, so the
    # prefix is a guaranteed superset. (A popcount-derived length was a SUBSET:
    # real matches spilled outside it.) Caller marks imprecise.
    return 32 - bits.bit_length(), "noncontiguous"


# True while parsing an entry of an `ip/ipv4/ipv6 access-list` block (IOS,
# IOS-XR, NX-OS, EOS): there a dotted mask is ALWAYS a wildcard, never an ASA
# netmask, whatever it looks like.
_WILDCARD_ONLY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "_WILDCARD_ONLY", default=False)
# The entry grammar of the line being parsed (review of #42, round 9, R8-6):
# "ios" (IOS / IOS XE IPv4, named ACL mode or a numbered `access-list N`
# line), "ios6" (IOS IPv6 ACL mode), "asa" (an ASA `access-list NAME
# extended|standard` line), "nxos", "eos". It decides which operand and
# trailer forms are read; any other form is noted.
_DIALECT: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_DIALECT", default="ios")


def _parse_addr(tokens: List[str], i: int, v6: bool = False) -> Tuple[_IPNet, int, bool]:
    """Parse an address operand; return (net, next_i, imprecise). `v6` is the
    enclosing ACL's family (`ipv6 access-list`) — it sizes `any`; `host` sizes
    itself from the address (/32 v4, /128 v6)."""
    # Cisco keywords are case-insensitive on the device, and ASA writes `any4`
    # (IPv4 any) / `any6` (IPv6 any) explicitly. Fold both here so `ANY`, `Host`
    # and `any4` parse EXACT instead of degrading to an opaque imprecise ACE.
    t = tokens[i].lower()
    if t == "any":                     # family follows the enclosing ACL
        return (_ANY6_NET if v6 else _ANY_NET), i + 1, False
    if t == "any4":                    # ASA: IPv4 any, explicitly
        return _ANY_NET, i + 1, False
    if t == "any6":                    # ASA: IPv6 any, explicitly
        return _ANY6_NET, i + 1, False
    if t == "host":
        return _host_net(tokens[i + 1]), i + 2, False
    if "/" in t:
        return ipaddress.ip_network(t, strict=False), i + 1, False
    addr, mask = tokens[i], tokens[i + 1]
    plen, kind = _classify_mask(mask)
    if kind == "netmask" and _WILDCARD_ONLY.get():
        # e.g. 255.192.0.0 in an IOS block: a non-contiguous WILDCARD. Covering
        # prefix = the mask's leading-zero run (see _classify_mask).
        plen = 32 - int(ipaddress.IPv4Address(mask)).bit_length()
        kind = "noncontiguous"
    if kind == "host" and addr == "0.0.0.0":
        # `0.0.0.0 0.0.0.0` (ASA netmask) and `0.0.0.0 255.255.255.255` (IOS
        # wildcard) are both real-world spellings of "any"; the competing
        # host-0.0.0.0 readings never occur in practice. Exact ANY — reading it
        # as host 0.0.0.0/32 narrowed the space and false-PASSed segcheck.
        return _ANY_NET, i + 2, False
    imprecise = kind in ("ambiguous", "noncontiguous")
    return ipaddress.ip_network(f"{addr}/{plen}", strict=False), i + 2, imprecise


def _parse_port_op(tokens: List[str], i: int) -> Tuple[List[PortRange], int, bool, int]:
    """Parse an optional port operator; return (ranges, next_i, imprecise, extra).

    Returns a LIST of port ranges so a multi-port `eq a b c` is expanded to the
    EXACT union of per-port rules (mirrors the Junos/iptables/PAN-OS frontends),
    instead of keeping only the first port. Dropping the extra ports used to be a
    silent FALSE-PASS: `permit tcp CORP PCI eq www 445` really permits 445, but
    the model kept only port 80 and segcheck wrongly concluded PASS. `extra` is
    the count of additional `eq` ports (surfaced as a note for the audit trail)."""
    if i >= len(tokens):
        return [ANY_PORTS], i, False, 0
    op = tokens[i].lower()             # eq/gt/lt/neq/range are case-insensitive
    if op == "eq":
        ports: List[int] = [_port_num(tokens[i + 1])]
        j = i + 2
        while j < len(tokens) and _is_port_token(tokens[j]):  # extra eq ports
            ports.append(_port_num(tokens[j]))
            j += 1
        ranges = [PortRange(p, p) for p in ports if p >= 0]
        imprecise = any(p < 0 for p in ports)
        if not ranges:                       # all unparsable -> ANY + imprecise
            return [ANY_PORTS], j, True, 0
        return ranges, j, imprecise, len(ports) - 1
    if op == "range":
        lo, hi = _port_num(tokens[i + 1]), _port_num(tokens[i + 2])
        if lo < 0 or hi < 0:
            return [ANY_PORTS], i + 3, True, 0
        return [PortRange(min(lo, hi), max(lo, hi))], i + 3, False, 0
    if op == "gt":
        p = _port_num(tokens[i + 1])
        if p < 0 or p >= PORT_MAX:
            return [ANY_PORTS], i + 2, True, 0
        return [PortRange(p + 1, PORT_MAX)], i + 2, False, 0
    if op == "lt":
        p = _port_num(tokens[i + 1])
        if p <= PORT_MIN:
            return [ANY_PORTS], i + 2, True, 0
        return [PortRange(PORT_MIN, p - 1)], i + 2, False, 0
    if op == "neq":
        # neq P's true space is non-contiguous (every port EXCEPT P), i.e. the
        # EXACT union of two contiguous ranges [MIN, P-1] and [P+1, MAX]. The IR
        # already expands a port LIST into one ACE per range (the same mechanism
        # as a multi-port `eq a b c`), so we can model neq PRECISELY rather than
        # over-approximating to ANY+imprecise: emit both sub-ranges. Each emitted
        # range is exact (never widened), so this can only turn an INDETERMINATE
        # into a precise PASS/CRITICAL — it can never manufacture a false PASS
        # (a port P stays uncovered, exactly as `neq P` intends). Degenerate ends
        # collapse cleanly: `neq 0` -> just [1, MAX]; `neq 65535` -> just [0, 65534].
        p = _port_num(tokens[i + 1])
        if p < 0:                            # unparsable service name -> fail closed
            return [ANY_PORTS], i + 2, True, 0
        ranges: List[PortRange] = []
        if p > PORT_MIN:
            ranges.append(PortRange(PORT_MIN, p - 1))
        if p < PORT_MAX:
            ranges.append(PortRange(p + 1, PORT_MAX))
        if not ranges:                       # unreachable after clamp; stay sound
            return [ANY_PORTS], i + 2, True, 0
        return ranges, i + 2, False, 0
    return [ANY_PORTS], i, False, 0


def _entry_tokens(line: str) -> List[str]:
    s = line.strip()
    # Leading sequence number: the bare IOS/NX-OS/EOS form (`10 permit ...`)
    # and the IOS IPv6 form (`sequence 10 permit ...` — `show running-config`
    # renders EVERY `ipv6 access-list` entry with the explicit keyword).
    # Leaving the keyword in place made toks[0] "sequence", not an action, so
    # every v6 entry was dropped as "unparsed": a SUBSET model of the ACL that
    # false-PASSed IPv6 segmentation assertions while the v4 ACLs parsed fine.
    s = re.sub(r"(?i)^(?:sequence\s+)?\d+\s+", "", s)
    # ASA prefix: name, optional `line N` (from `show access-list`), optional
    # `extended`/`standard` (parse_acls has already noted which one it was).
    s = re.sub(r"(?i)^access-list\s+\S+\s+(?:line\s+\d+\s+)?(?:extended\s+|standard\s+)?",
               "", s)
    return s.split()


# Lines we recognize as an ACE (start with permit/deny) but cannot reduce to an
# L3/L4 rectangle: object-group / object / service-object references, or an
# unparseable operand. Matched on the original line.
_OPAQUE_RE = re.compile(
    r"(?i)\b(object-group|object|addrgroup|portgroup|service-object|"
    r"port-object|group-object)\b")


def _opaque_ace(action: str, seq: int, acl: str, raw: str, line: int = 0) -> ACE:
    """A fail-CLOSED stand-in for a permit/deny line we can't model (object-group
    /object reference, or an unparseable operand). Over-approximated to ANY
    proto/src/dst and marked `imprecise`, so:
      * analyze() never uses it to prove another rule dead and emits no spurious
        any/any or exposure finding (imprecise is excluded from both), and
      * segcheck() turns it into segmentation-INDETERMINATE for any flow it could
        touch — an unmodeled permit can no longer FALSE-PASS a real CORP->PCI leak
        hidden behind the group. Dropping the line (the old behavior) was the bug.
    Mirrors the iptables custom-chain-jump fail-closed marker."""
    return ACE(seq=seq, action=action, proto="ip", src=_ANY_NET, dst=_ANY_NET,
               imprecise=True, raw=raw, acl=acl, line=line)


# --- object-group / object resolution (two-pass) ---------------------------
# ASA/IOS configs name reusable address & service sets (`object-group network`,
# `object network`, `object-group service`, `object service`) and reference them
# from ACEs. Pass 1 (`_collect_defs`) reads the definitions; pass 2 (`_resolve_
# entry`) expands a referencing ACE to the EXACT union of member ACEs (mirrors
# the Junos/PAN-OS multi-value union).
#
# SOUNDNESS (never manufacture a false PASS): a reference is resolved ONLY when
# every member resolves to an exact L3/L4 space. Anything we cannot fully and
# exactly resolve — an UNDEFINED group, an unparseable member, a reference cycle,
# an empty/degenerate group, or an expansion that exceeds `_MAX_EXPAND` — is NOT
# resolved; it falls back to the existing fail-closed opaque ACE (any/any,
# imprecise -> segmentation INDETERMINATE), never to empty / any-isolated. So
# resolution can only turn an INDETERMINATE into a PRECISE verdict; it can never
# weaken a real leak into a (false) PASS.
_MAX_EXPAND = 256
_PORT_OPS = frozenset({"eq", "range", "neq", "lt", "gt"})

# Net members:  ("net", _IPNet) | ("ng", name) | ("no", name) | ("bad",)
# Svc members:  ("svc", proto, PortRange) | ("sg", name) | ("so", name) | ("bad",)
# ("malformed",) marks a corrupt DEFINITION line (bare `group-object`): the
# containing group fails closed entirely, even under partial resolution.


class _Defs:
    """Collected object-group / object definitions (the pass-1 result)."""

    def __init__(self) -> None:
        self.net_groups: dict = {}   # name -> [net member, ...]
        self.net_objs: dict = {}     # name -> [net member, ...]
        self.svc_groups: dict = {}   # name -> [svc member, ...]
        self.svc_objs: dict = {}     # name -> [svc member, ...]


def _host_net(addr: str) -> _IPNet:
    return ipaddress.ip_network(addr + ("/128" if ":" in addr else "/32"),
                                strict=False)


def _net_member(rest: List[str]) -> Tuple:
    """A `network-object ...` operand -> a single net member (fail-closed on any
    form we can't reduce exactly)."""
    try:
        if not rest:
            return ("bad",)
        t0 = rest[0].lower()
        if t0 == "host":
            return ("net", _host_net(rest[1]))
        if t0 == "object":
            return ("no", rest[1])
        if "/" in rest[0]:
            return ("net", ipaddress.ip_network(rest[0], strict=False))
        if len(rest) >= 2:
            plen, kind = _classify_mask(rest[1])
            if kind in ("ambiguous", "noncontiguous"):
                return ("bad",)              # non-exact mask -> fail closed
            return ("net", ipaddress.ip_network(f"{rest[0]}/{plen}", strict=False))
        return ("net", _host_net(rest[0]))   # bare address == host
    except (ValueError, IndexError):
        return ("bad",)


def _obj_net_members(rest: List[str]) -> List[Tuple]:
    """An `object network` body line (`host`/`subnet`/`range`) -> net members.
    A `range A B` summarizes to the EXACT set of CIDRs covering [A, B]."""
    try:
        if not rest:
            return [("bad",)]
        kw = rest[0].lower()
        if kw == "host":
            return [("net", _host_net(rest[1]))]
        if kw == "subnet":
            if "/" in rest[1]:
                return [("net", ipaddress.ip_network(rest[1], strict=False))]
            plen, kind = _classify_mask(rest[2])
            if kind in ("ambiguous", "noncontiguous"):
                return [("bad",)]
            return [("net", ipaddress.ip_network(f"{rest[1]}/{plen}", strict=False))]
        if kw == "range":
            lo = ipaddress.ip_address(rest[1])
            hi = ipaddress.ip_address(rest[2])
            return [("net", n) for n in ipaddress.summarize_address_range(lo, hi)]
        return [("bad",)]                    # fqdn / unsupported -> fail closed
    except (ValueError, IndexError, TypeError):
        return [("bad",)]                    # TypeError: mixed v4/v6 range


def _expand_proto(p: Optional[str]) -> Optional[List[str]]:
    if p is None:
        return None
    p = p.lower()
    if p == "tcp-udp":
        return ["tcp", "udp"]
    if p in ("tcp", "udp", "icmp", "ip", "ipv6"):
        return [p]
    # Other IANA protocols a service object can name — `service-object gre` /
    # `service-object esp` / `service-object 50` are the VPN idiom in nearly
    # every ASA config. Each is an exact, port-less protocol space that
    # covers()/segcheck already compare by name, so resolving it is exact.
    # Only the numbers and names the Cisco frontend itself normalizes are
    # accepted; any other token stays fail-closed (never minted as a proto).
    n = _norm_proto(p)
    if p in _PROTO_NUM or n in _PROTO_NUM.values():
        return [n]
    return None                              # unknown -> fail closed


def _svc_port(rest: List[str], idx: int) -> Optional[PortRange]:
    """Parse an exact, contiguous service-port operator at rest[idx:] -> one
    PortRange. Handles `eq P` / `range LO HI` / `lt P` -> [MIN, P-1] / `gt P` ->
    [P+1, MAX]. `neq` is non-contiguous (two ranges) and cannot be expressed as a
    single PortRange here, so it stays unmodeled (-> caller fails closed,
    INDETERMINATE) — never widened into a (possibly false) PASS."""
    if idx >= len(rest):
        return None
    op = rest[idx].lower()
    if op == "eq":
        p = _port_num(rest[idx + 1])
        return PortRange(p, p) if p >= 0 else None
    if op == "range":
        lo, hi = _port_num(rest[idx + 1]), _port_num(rest[idx + 2])
        if lo < 0 or hi < 0:
            return None
        return PortRange(min(lo, hi), max(lo, hi))
    if op == "lt":
        p = _port_num(rest[idx + 1])
        return PortRange(PORT_MIN, p - 1) if p > PORT_MIN else None
    if op == "gt":
        p = _port_num(rest[idx + 1])
        return PortRange(p + 1, PORT_MAX) if 0 <= p < PORT_MAX else None
    return None


def _svc_members(rest: List[str], header_proto: Optional[str]) -> List[Tuple]:
    """A `service-object ...` / `port-object ...` / `service ...` body -> svc
    members. `header_proto` is the `object-group service NAME <proto>` protocol
    used by bare `port-object` lines."""
    try:
        if not rest:
            return [("bad",)]
        t0 = rest[0].lower()
        if t0 == "object":
            return [("so", rest[1])]
        if t0 in _PORT_OPS:                  # port-object: proto from the header
            protos = _expand_proto(header_proto)
            pr = _svc_port(rest, 0)
            if protos is None or pr is None or any(p not in _PORTED for p in protos):
                return [("bad",)]            # ports on a port-less proto -> fail closed
            return [("svc", p, pr) for p in protos]
        protos = _expand_proto(t0)           # service-object PROTO ...
        if protos is None:
            return [("bad",)]
        idx = 1
        if idx < len(rest) and rest[idx].lower() in ("source", "destination"):
            if rest[idx].lower() == "source":
                return [("bad",)]            # source-port set: we model dst -> fail closed
            idx += 1
        if idx >= len(rest):                 # protocol only -> any port
            return [("svc", p, ANY_PORTS) for p in protos]
        pr = _svc_port(rest, idx)
        if pr is None or any(p not in _PORTED for p in protos):
            # Unparseable port operator, or a port on a port-less protocol
            # (covers()/segcheck ignore ports there, so the member would claim
            # the whole protocol) -> fail closed.
            return [("bad",)]
        return [("svc", p, pr) for p in protos]
    except (ValueError, IndexError):
        return [("bad",)]


def _collect_defs(text: str, lex=None) -> _Defs:
    """Pass 1: read every object-group / object definition in the config.

    A member line counts only when the lexer puts it in the mode its group's
    header opened (indentation does not matter to the device). A member-like
    line anywhere else makes that group fail closed (a malformed member)."""
    lex = lex if lex is not None else cisco_lex(text)
    by_no = {ln.no: ln for ln in lex.lines}
    defs = _Defs()
    cur = None          # ("ng"|"no"|"sg"|"so"|"other", name)
    cur_no = -1         # header line of `cur`
    header_proto = None
    for lineno, raw in enumerate(split_lines(text), 1):
        s = raw.strip()
        lx = by_no.get(lineno)
        if lx is None or lx.post_end or not s.split() or s.startswith("!"):
            continue
        if cur is not None and lx.opener != cur_no and not (
                lx.opener == lineno or lx.header):
            # The mode changed since the header (a top-level command, `exit`,
            # an interface): later member lines are not in this group.
            if cur[0] in ("ng", "no", "sg", "so") and re.match(
                    r"(?i)^(?:network-object|group-object|service-object|"
                    r"port-object|host|subnet|range|service)\b", s):
                (defs.net_groups if cur[0] == "ng" else defs.net_objs if cur[0] == "no"
                 else defs.svc_groups if cur[0] == "sg" else defs.svc_objs
                 )[cur[1]].append(("malformed",))
            cur = None
        low = s.lower()
        m = re.match(r"(?i)^object-group\s+network\s+(\S+)", s)
        if m:
            cur, header_proto, cur_no = ("ng", m.group(1)), None, lx.opener
            defs.net_groups.setdefault(m.group(1), [])
            continue
        m = re.match(r"(?i)^object-group\s+service\s+(\S+)(?:\s+(\S+))?", s)
        if m:
            cur, header_proto = ("sg", m.group(1)), (m.group(2) or "").lower() or None
            cur_no = lx.opener
            defs.svc_groups.setdefault(m.group(1), [])
            continue
        m = re.match(r"(?i)^object\s+network\s+(\S+)", s)
        if m:
            cur, header_proto, cur_no = ("no", m.group(1)), None, lx.opener
            defs.net_objs.setdefault(m.group(1), [])
            continue
        m = re.match(r"(?i)^object\s+service\s+(\S+)", s)
        if m:
            cur, header_proto, cur_no = ("so", m.group(1)), None, lx.opener
            defs.svc_objs.setdefault(m.group(1), [])
            continue
        if low.startswith("object-group "):          # protocol / icmp-type / ... groups
            cur = ("other", "")
            continue
        if (low.startswith("access-list") or low.startswith("ip access-list")
                or low.startswith("ipv6 access-list") or low.startswith("object ")):
            cur = None
            continue
        if cur is None or cur[0] == "other":
            continue
        toks = s.split()
        kw, ctype, name = toks[0].lower(), cur[0], cur[1]
        if kw == "network-object" and ctype == "ng":
            defs.net_groups[name].append(_net_member(toks[1:]))
        elif kw == "group-object":
            # bare `group-object` (no name) is a MALFORMED definition line (not
            # merely an unmodelable member): the whole group fails closed, even
            # under partial resolution — we cannot trust a corrupt definition.
            mem = (ctype, toks[1]) if len(toks) >= 2 else ("malformed",)
            if ctype == "ng":
                defs.net_groups[name].append(mem)
            elif ctype == "sg":
                defs.svc_groups[name].append(mem)
        elif kw in ("service-object", "port-object") and ctype == "sg":
            defs.svc_groups[name].extend(_svc_members(toks[1:], header_proto))
        elif kw in ("host", "subnet", "range") and ctype == "no":
            defs.net_objs[name].extend(_obj_net_members(toks))
        elif kw == "service" and ctype == "so":
            defs.svc_objs[name].extend(_svc_members(toks[1:], None))
    return defs


def _resolve_nets(defs: _Defs, kind: str, name: str, seen: frozenset):
    """Resolve a network group/object to an EXACT list of nets, or None if it is
    undefined / has an unparseable member / cycles / is empty (all fail-closed)."""
    key = (kind, name)
    if key in seen:
        return None                                  # cycle -> fail closed
    members = (defs.net_groups if kind == "ng" else defs.net_objs).get(name)
    if members is None:
        return None                                  # undefined -> fail closed
    seen = seen | {key}
    out: List[_IPNet] = []
    for mem in members:
        if mem[0] == "net":
            out.append(mem[1])
        elif mem[0] in ("ng", "no"):
            sub = _resolve_nets(defs, mem[0], mem[1], seen)
            if sub is None:
                return None
            out.extend(sub)
        else:                                        # ("bad",)
            return None
    return out or None                               # empty group -> fail closed


def _resolve_nets_partial(defs: _Defs, kind: str, name: str, seen: frozenset
                          ) -> Tuple[Optional[List[_IPNet]], bool]:
    """Like _resolve_nets but tolerates bad members instead of failing on the first.

    Returns ``(resolved, has_unresolved)``.

    * ``(None, True)``  — the group is entirely unresolvable (undefined, cycle,
      or all members bad / empty); caller must still fail closed.
    * ``(nets, False)`` — all members resolved exactly (same as _resolve_nets).
    * ``(nets, True)``  — *some* members resolved (returned in *nets*) and at
      least one member could not be resolved.  The caller can emit precise ACEs
      for the resolved subset PLUS one opaque ACE for the remainder.

    Used only from _operand_addr in partial mode."""
    key = (kind, name)
    if key in seen:
        return None, True                       # cycle -> fail closed
    members = (defs.net_groups if kind == "ng" else defs.net_objs).get(name)
    if members is None:
        return None, True                       # undefined -> fail closed
    seen = seen | {key}
    out: List[_IPNet] = []
    has_unresolved = False
    for mem in members:
        if mem[0] == "net":
            out.append(mem[1])
        elif mem[0] in ("ng", "no"):
            sub, sub_unres = _resolve_nets_partial(defs, mem[0], mem[1], seen)
            if sub is not None:
                out.extend(sub)
            has_unresolved = has_unresolved or sub_unres
        elif mem[0] == "malformed":
            return None, True                   # corrupt definition -> all fail closed
        else:                                   # ("bad",)
            has_unresolved = True
    return (out if out else None), has_unresolved


def _resolve_svcs(defs: _Defs, kind: str, name: str, seen: frozenset):
    """Resolve a service group/object to an EXACT list of (proto, PortRange), or
    None (fail-closed) on undefined / unparseable member / cycle / empty."""
    key = (kind, name)
    if key in seen:
        return None
    members = (defs.svc_groups if kind == "sg" else defs.svc_objs).get(name)
    if members is None:
        return None
    seen = seen | {key}
    out: List[Tuple[str, PortRange]] = []
    for mem in members:
        if mem[0] == "svc":
            out.append((mem[1], mem[2]))
        elif mem[0] in ("sg", "so"):
            sub = _resolve_svcs(defs, mem[0], mem[1], seen)
            if sub is None:
                return None
            out.extend(sub)
        else:
            return None
    return out or None


def _resolve_svcs_partial(defs: _Defs, kind: str, name: str, seen: frozenset
                          ) -> Tuple[Optional[List[Tuple[str, PortRange]]], bool]:
    """Like _resolve_svcs but tolerates bad members instead of failing on the first.

    Returns ``(resolved, has_unresolved)``.

    * ``(None, True)``  — the group is entirely unresolvable (undefined, cycle,
      or all members bad / empty); caller must still fail closed.
    * ``(svcs, False)`` — all members resolved exactly (same as _resolve_svcs).
    * ``(svcs, True)``  — *some* members resolved (returned in *svcs*) and at
      least one member could not be resolved.  The caller can emit precise ACEs
      for the resolved subset PLUS one opaque ACE for the remainder.

    Used only from _resolve_entry in partial mode."""
    key = (kind, name)
    if key in seen:
        return None, True                       # cycle -> fail closed
    members = (defs.svc_groups if kind == "sg" else defs.svc_objs).get(name)
    if members is None:
        return None, True                       # undefined -> fail closed
    seen = seen | {key}
    out: List[Tuple[str, PortRange]] = []
    has_unresolved = False
    for mem in members:
        if mem[0] == "svc":
            out.append((mem[1], mem[2]))
        elif mem[0] in ("sg", "so"):
            sub, sub_unres = _resolve_svcs_partial(defs, mem[0], mem[1], seen)
            if sub is not None:
                out.extend(sub)
            has_unresolved = has_unresolved or sub_unres
        elif mem[0] == "malformed":
            return None, True                   # corrupt definition -> all fail closed
        else:                                   # ("bad",)
            has_unresolved = True
    return (out if out else None), has_unresolved


def _operand_addr(toks: List[str], i: int, defs: _Defs, v6: bool = False,
                  partial: bool = False) -> Tuple:
    """Parse a src/dst address operand, resolving object(-group) refs.
    Returns (nets|None, next_i, imprecise, has_unresolved).
    None nets means the caller must fail closed. `v6` is the enclosing ACL's
    family (sizes a literal `any`). has_unresolved is True only
    when partial=True and the group has members that could not be resolved
    (the returned nets cover only the resolvable subset)."""
    t = toks[i].lower()
    if t == "object-group":
        if partial:
            nets, has_unres = _resolve_nets_partial(defs, "ng", toks[i + 1], frozenset())
        else:
            nets, has_unres = _resolve_nets(defs, "ng", toks[i + 1], frozenset()), False
        return nets, i + 2, False, has_unres
    if t == "object":
        if partial:
            nets, has_unres = _resolve_nets_partial(defs, "no", toks[i + 1], frozenset())
        else:
            nets, has_unres = _resolve_nets(defs, "no", toks[i + 1], frozenset()), False
        return nets, i + 2, False, has_unres
    net, ni, imp = _parse_addr(toks, i, v6)
    return [net], ni, imp, False


def _is_svc_ref(toks: List[str], i: int, defs: _Defs) -> bool:
    if i + 1 >= len(toks):
        return False
    t = toks[i].lower()
    return ((t == "object-group" and toks[i + 1] in defs.svc_groups)
            or (t == "object" and toks[i + 1] in defs.svc_objs))


def _resolve_entry(toks: List[str], defs: _Defs, seq: int, acl: str, raw: str,
                   line: int = 0, v6: bool = False, partial: bool = False):
    """Pass 2: expand one object-referencing ACE to the exact union of member
    ACEs, or return None to fall back to the fail-closed opaque ACE.

    When *partial* is True, address operands are resolved via
    _resolve_nets_partial AND service operands via _resolve_svcs_partial: if
    some group members are unresolvable the returned list contains precise ACEs
    for the resolved subset PLUS one opaque (any/any, imprecise) ACE for the
    unresolved remainder.  This is SOUND: the proven-reachable subset is modeled
    exactly (never widened), and the unresolved remainder stays INDETERMINATE —
    never silently PASS."""
    action = toks[0].lower()
    n = len(toks)
    i = 1
    proto: Optional[str] = None
    proto_combos = None                      # service group occupying the proto slot
    has_unres_svc = False
    if i < n and _is_svc_ref(toks, i, defs):
        kind = "sg" if toks[i].lower() == "object-group" else "so"
        if partial:
            proto_combos, has_unres_svc = _resolve_svcs_partial(
                defs, kind, toks[i + 1], frozenset())
        else:
            proto_combos = _resolve_svcs(defs, kind, toks[i + 1], frozenset())
        if proto_combos is None:
            return None
        i += 2
    elif i < n:
        proto = _norm_proto(toks[i])
        i += 1
    else:
        return None
    if i >= n:
        return None

    srcs, i, imp_s, has_unres_s = _operand_addr(toks, i, defs, v6, partial)
    if srcs is None:
        return None
    imprecise = imp_s
    port_imprecise = False                   # a port operator we could not model exactly
    ported = proto in ("tcp", "udp") if proto else True

    # Optional source port (only a literal operator; a source SERVICE group is
    # rare — leave it unresolved/fail-closed rather than grow the model).
    src_ports: List[PortRange] = [ANY_PORTS]
    if i < n and ported and toks[i].lower() in _PORT_OPS:
        src_ports, i, imp_sp, _ = _parse_port_op(toks, i)
        imprecise = imprecise or imp_sp
        port_imprecise = port_imprecise or imp_sp
    elif i < n and _is_svc_ref(toks, i, defs):
        return None

    if i >= n:
        return None
    dsts, i, imp_d, has_unres_d = _operand_addr(toks, i, defs, v6, partial)
    if dsts is None:
        return None
    imprecise = imprecise or imp_d

    # Build the (proto, dst_port) combinations.
    combos: List[Tuple[str, PortRange]] = []
    if proto_combos is not None:             # service group set proto + dst port
        combos = list(proto_combos)
    elif i < n and toks[i].lower() in ("object-group", "object"):
        if not _is_svc_ref(toks, i, defs):
            # The name in the service slot does not resolve as a service set
            # (undefined, or an icmp-type/protocol group we don't model).
            # Treating it as an inert trailer claimed exact ANY ports/types — a
            # narrowing. Fail closed (opaque ACE -> INDETERMINATE).
            return None
        kind = "sg" if toks[i].lower() == "object-group" else "so"
        if partial:
            svcs, _unres_dst = _resolve_svcs_partial(defs, kind, toks[i + 1], frozenset())
            has_unres_svc = has_unres_svc or _unres_dst
        else:
            svcs = _resolve_svcs(defs, kind, toks[i + 1], frozenset())
        if svcs is None:
            return None
        i += 2
        for cproto, dp in svcs:              # keep only members compatible with the ACE proto
            if proto in (None, "ip", "ipv4", "ipv6") or cproto == "ip" or cproto == proto:
                combos.append((proto if proto and cproto == "ip" else cproto, dp))
        if not combos:                       # tcp ACE over a udp-only group, etc.
            return None
    elif i < n and ported and toks[i].lower() in _PORT_OPS:
        dst_ports, i, imp_dp, _ = _parse_port_op(toks, i)
        imprecise = imprecise or imp_dp
        port_imprecise = port_imprecise or imp_dp
        combos = [(proto, dp) for dp in dst_ports]
    else:
        combos = [(proto or "ip", ANY_PORTS)]

    if len(srcs) * len(dsts) * len(src_ports) * len(combos) > _MAX_EXPAND:
        return None                          # over-cap -> fail closed (one opaque ACE)

    rest = toks[i:]
    cidr = _v4_prefix_operands(toks[2:i]) if not v6 else []
    narrowing, type_tok, extra_unknown, stateful, inactive = _scan_trailer(rest)
    if inactive:
        # ASA `inactive`: the rule is DISABLED on the device — its true match
        # space is empty, so emitting no ACE is exact (not a narrowing).
        return [], [f"inactive (disabled on device, not enforced) -> skipped: {raw}"]
    # For an icmp ACE the first free trailing token is the (modeled) ICMP type —
    # it stays exact and threads into the emitted ACEs. When a service group
    # occupies the proto slot (`proto` is None) there is no icmp context, so the
    # token stays unknown (fail closed below).
    icmp_type = _canon_icmp_type(type_tok, proto) if proto in ("icmp", "icmpv6") else None
    rnotes: List[str] = []
    if port_imprecise:
        rnotes.append(_PORT_OP_NOTE + raw)
    if narrowing:
        # Same soundness rule as _parse_entry: a narrowed ACE modeled full-width
        # could shadow a real leak (deny) or fake one (permit) — fail closed.
        imprecise = True
        rnotes.append("match-narrowing qualifier "
                      + "/".join(sorted(set(narrowing)))
                      + " not modeled — match space narrowed, kept as a "
                      + f"superset (imprecise), verify manually: {raw}")
    # Any OTHER unknown trailing token fails closed: a TCP flag (`syn`), an
    # unresolvable service name, or `show access-list` residue narrows or
    # extends the match unmodeled — the same hazard as in _parse_entry.
    unknown = list(extra_unknown)
    if type_tok is not None and icmp_type is None:
        unknown.insert(0, type_tok)
    if unknown:
        imprecise = True
        rnotes.append("unrecognized trailing qualifier "
                      + "/".join(unknown)
                      + f" — marked imprecise, verify manually: {raw}")
    aces: List[ACE] = []
    m = seq
    for s in srcs:
        for d in dsts:
            for sp in src_ports:
                for cproto, dp in combos:
                    m += 1
                    aces.append(ACE(
                        seq=m, action=action, proto=cproto, src=s, dst=d,
                        src_port=sp, dst_port=dp, icmp_type=icmp_type,
                        stateful=stateful, imprecise=imprecise, raw=raw,
                        acl=acl, line=line))
    note = (f"resolved object-group/object reference to {len(aces)} exact "
            f"ACE(s): {raw}")

    # Partial-resolution mode: if any address operand or service group had
    # unresolvable members, append one opaque (any/any, imprecise) ACE for the
    # unresolved remainder so those members stay INDETERMINATE and never silently
    # PASS.
    if partial and (has_unres_s or has_unres_d or has_unres_svc):
        m += 1
        aces.append(_opaque_ace(action, m, acl, raw, line))
        note = (
            f"partially resolved object-group/object reference: "
            f"{len(aces) - 1} exact ACE(s) + 1 opaque (unresolved members): {raw}"
        )

    return aces, rnotes + [note]


# Commands that contain permit/deny but are not packet filters.
_NON_FILTER_HDR = re.compile(
    r"(?i)^(?:route-map\s|ipv?6?\s*prefix-list\s|ip\s+prefix-list\s|"
    r"ipv6\s+prefix-list\s|ip\s+(?:extcommunity|community|large-community)-list\s|"
    r"ip\s+as-path\s|mac\s+access-list\s|xlate\s|same-security-traffic\s|"
    r"no\s+arp\s|description\s)")

_ASA_NAME_RE = re.compile(r"(?im)^\s*name\s+(\S+)\s+(\S+)")


def _apply_asa_names(text: str) -> Tuple[str, int]:
    """ASA `name ADDRESS ALIAS` (under `names`) lets ACLs and objects use ALIAS
    for ADDRESS. Substitute it, token-exact, in access-list and object lines
    (where an unknown word otherwise fails the ACE closed as imprecise). Only
    aliases bound to a literal IP address are used, and an alias that is also
    a keyword we parse is never substituted."""
    names = {}
    for m in _ASA_NAME_RE.finditer(text):
        addr, alias = m.group(1), m.group(2)
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            continue
        if alias.lower() in _ALIAS_RESERVED or alias in names:
            continue
        names[alias] = addr
    if not names:
        return text, 0
    out = []
    for ln in split_lines(text):
        st = ln.lstrip().lower()
        if st.startswith(("access-list ", "permit ", "deny ", "host ", "subnet ",
                          "range ", "network-object ")):
            toks = ln.split(" ")
            # never rewrite an ACL / object / group NAME that happens to equal
            # an alias — only address operands
            ln = " ".join(t if (k and toks[k - 1].lower() in (
                "access-list", "object", "object-group", "time-range"))
                else names.get(t, t) for k, t in enumerate(toks))
        out.append(ln)
    return "\n".join(out) + ("\n" if text.endswith("\n") else ""), len(names)


_ALIAS_RESERVED = frozenset({"any", "any4", "any6", "host", "object", "object-group",
                             "interface", "eq", "neq", "lt", "gt", "range", "log",
                             "permit", "deny", "ip", "tcp", "udp", "icmp"})


_BANNER_RE = re.compile(
    r"(?i)^\s*banner(?:\s+(exec|login|motd|incoming|slip-ppp|prompt-timeout|"
    r"config-save|asdm))?(?:\s+(.*))?$")


def strip_banners(text: str) -> Tuple[str, List[str]]:
    """Blank every banner line, so banner text is never read as config.

    IOS / NX-OS: `banner TYPE D text D`, where D is the first character after
    the type (running-config shows Ctrl-C as `^C`); the text may span lines
    and ends at the next D. Arista EOS: `banner TYPE` alone, then text lines
    up to a line `EOF`. ASA: `banner TYPE text`, one line each. A delimiter
    RuleHawk cannot determine (a letter or digit, which ASA uses as text and
    IOS as a delimiter) or a banner that never ends gets a note, so no PASS
    rests on it. Line numbers are kept (blanked lines stay as empty lines).

    `banner` is a global command wherever it is indented, so the first line
    keeps a bare `banner TYPE ^C^C` header: the lexer reads it as the top-level
    command that ends an interface / ACL / object-group mode."""
    lines = text.split("\n")
    notes: List[str] = []
    asa = bool(re.search(r"(?im)^\s*(?:ASA|PIX|FWSM)\s+Version\b", text))
    i, n = 0, len(lines)
    while i < n:
        m = _BANNER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        start, rest = i, (m.group(2) or "").lstrip()
        lead = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
        # `^C^C` makes the header a closed one-line banner, so a second pass
        # leaves it as it is.
        header = f"{lead}banner {(m.group(1) or 'motd').lower()} ^C^C"
        if asa:
            lines[i] = header
            i += 1
            continue
        if not rest:
            # EOS form: text lines up to `EOF`.
            j = next((k for k in range(i + 1, n) if lines[k].strip() == "EOF"), None)
            if j is None:
                notes.append(f"banner without a delimiter (line {start + 1}): "
                             f"`{lines[i].strip()}` — its extent is unknown")
                lines[i] = header
                i += 1
                continue
            for k in range(i + 1, j + 1):
                lines[k] = ""
            lines[i] = header
            i = j + 1
            continue
        delim = "^C" if rest.startswith("^C") else rest[0]
        if delim.isalnum():
            notes.append(f"banner delimiter could not be determined (line "
                         f"{start + 1}): `{lines[i].strip()}`")
            lines[i] = header
            i += 1
            continue
        body = rest[len(delim):]
        if delim in body:
            lines[i] = header
            i += 1
            continue
        j = next((k for k in range(i + 1, n) if delim in lines[k]), None)
        if j is None:
            notes.append(f"banner with no closing delimiter {delim!r} (line "
                         f"{start + 1}): the rest of the file was read as banner "
                         f"text")
            j = n - 1
        for k in range(i + 1, j + 1):
            lines[k] = ""
        lines[i] = header
        i = j + 1
    return "\n".join(lines), notes


_NO_ACL_RE = re.compile(r"(?i)^no\s+(?:(?:ip|ipv4|ipv6)\s+)?access-list\b")
_NO_ENTRY_RE = re.compile(r"(?i)^no\s+(?:\d+|permit|deny)\b")


def parse_acls(text: str, vendor: str = "ios") -> Tuple[List[ACE], List[str]]:
    """Parse all ACLs in `text`; return (entries, notes).

    `notes` records lines recognized as ACEs but not fully modeled — surfaced,
    never silently dropped. `vendor` (`ios`, `nxos`, `eos`) selects the
    sequence-number grammar of ACL mode (round 8, R7-3)."""
    tok = _WILDCARD_ONLY.set(False)
    dtok = _DIALECT.set(vendor)
    try:
        return _parse_acls(text, vendor)
    finally:
        _DIALECT.reset(dtok)
        _WILDCARD_ONLY.reset(tok)


# The sequence-number forms of ACL mode, per vendor and family (review of
# #42, round 8, R7-3). Any other form is read as a number and noted.
# - IOS / IOS XE IPv4: a bare number. IOS XE 17 "IP Access List Entry
#   Sequence Numbering" (https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-acl-seq-num.html):
#   "Device(config-std-nacl)# 105 permit ...".
# - IOS / IOS XE IPv6: the `sequence` keyword. Cisco IOS XE Catalyst SD-WAN
#   Qualified Command Reference, ACL Commands, `sequence`
#   (https://www.cisco.com/c/en/us/td/docs/routers/sdwan/command/iosxe/qualified-cli-command-reference-guide/m-acl-commands.html):
#   "Command Modes: IPv6 access-list configuration",
#   "Device(config-ipv6-acl)# sequence 100 permit ipv6 any 2001:DB8::/32".
# - NX-OS IPv4 and IPv6: a bare number. Nexus 3600 NX-OS Security
#   Configuration Guide 10.5(x), "Configuring IP ACLs"
#   (https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus3600/105x/configuration/security/cisco-nexus-3600-switch-nx-os-security-configuration-guide-105x/m-configuring-ip-acls.html):
#   "[sequence-number] { permit | deny} protocol ...".
# - EOS: a bare number (what RuleHawk read before; not cited, the Arista
#   manual is behind a bot challenge).
def _seq_form_ok(vendor: str, v6: bool, form: str) -> bool:
    if form == "sequence":
        return vendor == "ios" and v6
    return not (vendor == "ios" and v6)


# The sequence-number range per vendor and family (review of #42, round 9,
# R8-2). A number outside it, 0, or a number written with a leading zero
# (how the device reads `010` is not cited) is noted.
# - IOS / IOS XE IPv4: 1-2147483647. IOS XE 17 "IP Access List Entry Sequence
#   Numbering" (URL above): "the range is from 1 to 2147483647" and "The
#   maximum sequence number is 2147483647. If the generated sequence number
#   exceeds this maximum number, the following message is displayed:
#   Exceeded maximum sequence number."
# - IOS / IOS XE IPv6: 1-4294967295. Catalyst 9800 IOS XE 17.14 "IPv6 ACL"
#   (https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-14/config-guide/b_wl_17_14_cg/m_ipv6_acl_ewlc.html):
#   "Enter a sequence value to assign a sequence number to the access list
#   statement. Valid values range from 1 to 4,294,967,295."
# - NX-OS: 1-4294967295. Nexus 3600 10.5(x) "Configuring IP ACLs" (URL
#   above): "The sequence-number argument can be a whole number between 1 and
#   4294967295."
# - EOS: not cited (the Arista manual is behind a bot challenge); the
#   smallest cited bound is used, so a larger number is noted.
_SEQ_MAX = {("ios", False): 2147483647, ("ios", True): 4294967295,
            ("nxos", False): 4294967295, ("nxos", True): 4294967295,
            ("eos", False): 2147483647, ("eos", True): 2147483647}


def _seq_max(vendor: str, v6: bool) -> int:
    return _SEQ_MAX.get((vendor, v6), 2147483647)


# +10 for an unnumbered entry is cited for IOS IPv4 and NX-OS only (see
# `_device_numbers`). Elsewhere an ACL that mixes numbered and unnumbered
# entries is noted (R8-7).
def _plus_ten_cited(vendor: str, v6: bool) -> bool:
    return (vendor == "ios" and not v6) or vendor == "nxos"


# Keywords whose case the device rule decides (round 9). IOS: "You can enter
# commands in uppercase, lowercase, or mixed case. Only passwords are case
# sensitive." (Cisco IOS Configuration Fundamentals Configuration Guide
# 12.2SR, "Using the Cisco IOS Command-Line Interface",
# https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/configuration/guide/12_2sr/cf_12_2sr_book/cf_cli-basics.html).
# NX-OS and EOS: no case rule is cited, so a keyword that is not lower case
# is noted there.
_CASE_KEYWORDS = frozenset({
    "permit", "deny", "remark", "sequence", "any", "host", "eq", "gt", "lt",
    "neq", "range", "log", "log-input", "established", "fragments",
    "time-range", "dscp", "tos", "precedence", "ttl", "ip", "ipv4", "ipv6",
    "tcp", "udp", "icmp", "icmpv6", "access-list", "extended", "standard",
    "object-group", "addrgroup", "portgroup", "statistics", "per-entry",
    "gre", "esp", "ahp", "ah", "ospf", "eigrp", "pim", "sctp", "igmp"})


_SEQ_FORM = re.compile(r"(?i)^(sequence\s+)?(\d+)\s+(\S.*)$")
# `no N` / `no sequence N` delete entry N. IOS XE 17 "IP Access List Entry
# Sequence Numbering" (URL above): "Use the no sequence-number command to
# delete an entry."; IOS XE IPv6 `sequence` (URL above): "To remove a
# sequence number from an IP access list, use the no form of this command.";
# NX-OS (URL above): "switch(config-acl)# no 101". The deletion is applied
# and also noted (the answer is UNKNOWN or, if the leak is proven, FAIL).
_DEL_SEQ = re.compile(r"(?ai)^no\s+(sequence\s+)?([0-9]+)$")
_ACL_HEADER_FULL = re.compile(
    r"(?ai)^(?:ip|ipv4|ipv6) access-list (?:(?:extended|standard) )?\S+$")
_STATS = re.compile(r"(?ai)^(?:no )?statistics per-entry$")
_FLAT_REMARK = re.compile(r"(?i)^access-list\s+\S+\s+(?:line\s+\d+\s+)?remark(?:\s|$)")
_REMARK = re.compile(r"(?i)^remark(?:\s|$)")


_RESEQ = re.compile(r"(?i)^(?:(?:ip|ipv4|ipv6)\s+access-list\s+resequence|resequence)(?:\s|$)")
_FLAT = re.compile(r"(?i)^access-list(?:\s|$)")
# Reference-only forms of a line that names an ACL outside ACL mode
# (round 9): the ACL is used as a match list (vty access, SNMP, a route-map
# or class-map `match`), or bound by the ASA `access-group` command, which
# the path model reads. Group `n` is the ACL name.
_ACL_REF_OK = [
    re.compile(r"(?ai)(?:ipv6 )?access-class (?P<n>\S+) (?:in|out)(?: vrf-also)?"),
    re.compile(r"(?ai)match (?:ip|ipv6) address (?P<n>\S+)"),
    re.compile(r"(?ai)snmp-server community \S+ (?:RO|RW) (?P<n>\S+)"),
    re.compile(r"(?ai)access-group (?P<n>\S+) (?:(?:in|out) interface \S+|global)"),
]


def _bad_case(line: str) -> Optional[str]:
    """The first keyword of an NX-OS / EOS ACL line that is not lower case
    (the words of a remark are free text)."""
    for w in line.split():
        lw = w.lower()
        if w != lw and lw in _CASE_KEYWORDS:
            return w
        if lw == "remark":
            break
    return None


def _parse_acls(text: str, vendor: str = "ios") -> Tuple[List[ACE], List[str]]:
    from .failclosed import Ledger
    entries: List[ACE] = []
    notes: List[str] = []
    text, notes_b = strip_banners(text)
    notes += notes_b
    text, n_alias = _apply_asa_names(text)
    if n_alias:
        notes.append(f"ASA `name` aliases resolved: {n_alias} name(s) substituted "
                     f"with their address")
    # Stanza membership comes from the lexer, as the device reads modes: an
    # entry belongs to the named ACL whose header opened the mode it is in,
    # whatever its indentation (review of #42, round 6, N1).
    lex = cisco_lex(text)
    by_no = {ln.no: ln for ln in lex.lines}
    srcs = split_lines(text)
    defs = _collect_defs(text, lex)          # pass 1: object-group / object defs
    pix_dialect = cisco_dialect_ambiguous(text)
    current_acl = "(unnamed)"
    acl_opener = -1                          # header line of the current named ACL
    cur_v6 = cur_std = False                 # family/kind of the current named ACL
    cur_typed = False                        # header says extended / standard
    seq = 0
    # Line accounting (round 8): the scope is every line the lexer puts in ACL
    # mode, every ACL header and every flat `access-list` line, whatever the
    # handlers below make of it.
    led = Ledger("cisco-acl")
    for lx in lex.lines:
        if lx.post_end:
            continue
        if (lx.mode == "acl" or re.match(r"(?i)^access-list(?: |$)", lx.norm)):
            led.add(lx.no, lx.norm)
    # Per ACL, in text order: (kind, line, explicit number or None, v6) with
    # kind entry | remark | delete, for the device numbering (R7-1, R7-2).
    events: "dict[str, list]" = {}
    acl_meta: "dict[str, tuple]" = {}         # ACL -> (vendor, v6)
    names: set = set()                        # every ACL name defined

    def event(kind: str, lineno: int, n: Optional[int]) -> None:
        if current_acl != "(unnamed)":
            events.setdefault(current_acl, []).append((kind, lineno, n))

    if lex.post_end:
        no = lex.post_end[0]
        notes.append(f"line {no} (`{srcs[no - 1].strip()[:60]}`) and "
                     f"{len(lex.post_end) - 1} more come after `end` (or a global "
                     f"`exit`): not configuration, not read")
    for lineno, raw in enumerate(srcs, 1):
        stripped = raw.strip()
        lx = by_no.get(lineno)
        if lx is None or lx.post_end or not stripped.split() or stripped.startswith("!"):
            continue                         # blank, `!`, or after `end`
        in_acl = lx.mode == "acl" and lx.opener == acl_opener
        opener_txt = srcs[lx.opener - 1].strip() if lx.opener else ""
        in_block = (lx.mode != "acl" and not lx.header
                    and lx.opener != lineno and bool(_NON_FILTER_HDR.match(opener_txt)))
        if lx.mode == "acl" and lx.norm.lower() in _EXIT_END:
            # `exit` ends ACL mode; the lexer reads it (and flags `ex`, `en`).
            led.consume(lineno)
            continue
        if _RESEQ.match(lx.norm):
            # `resequence` renumbers an ACL's entries (round 9, R8-5): NX-OS
            # global `resequence ip access-list NAME START INC` (Nexus 3600
            # 10.5(x) "Configuring IP ACLs": "Assigns sequence numbers to the
            # rules contained in the ACL, where the first rule receives the
            # starting sequence number that you specify."), IOS `ip
            # access-list resequence NAME START INC`, and `resequence` inside
            # ACL mode. Wherever it is, it names an ACL: in scope, noted.
            led.add(lineno, lx.norm)
            led.note(lineno, notes,
                     f"`{lx.norm[:60]}` (line {lineno}) renumbers an ACL's "
                     f"entries; the order after it is not modelled")
            continue
        if vendor in ("nxos", "eos") and (lx.mode == "acl" or _FLAT.match(lx.norm)):
            bad = _bad_case(lx.norm)
            if bad:
                led.add(lineno, lx.norm)
                led.note(lineno, notes,
                         f"`{bad}` (line {lineno}) is not lower case: the case "
                         f"rule of {vendor} keywords is not cited, so the line "
                         f"is not read as the lower-case keyword")
        mdel = _DEL_SEQ.match(lx.norm) if in_acl else None
        if mdel:
            kw = bool(mdel.group(1))
            ok = _seq_form_ok(vendor, cur_v6, "sequence" if kw else "bare")
            if ok:
                event("delete", lineno, int(mdel.group(2)))
            led.note(lineno, notes,
                     f"`{lx.norm}` (line {lineno}) in {current_acl}: "
                     + ("the deletion is applied (Cisco: `no` of a sequence "
                        "number deletes the entry)" if ok else
                        "this deletion form is not cited for this ACL mode, so it "
                        "is not applied")
                     + "; the answer rests on it, so it is not a PASS")
            continue
        if _NO_ACL_RE.match(stripped) or (in_acl and _NO_ENTRY_RE.match(stripped)) \
                or (in_acl and re.match(r"(?i)^no\s+(?:sequence|remark|evaluate|"
                                        r"dynamic)\b", stripped)):
            # IOS deletes the ACL (or the entry) at this point in the file;
            # RuleHawk does not replay deletions, so it keeps rules the device
            # no longer has. Fail closed: the note blocks every PASS.
            led.note(lineno, notes,
                     f"unmodeled `{stripped}` (line {lineno}): the deletion "
                     f"is not applied, so the parsed ACL may hold rules the "
                     f"device removed")
            continue
        if in_acl and re.match(r"(?i)^default(?:\s|$)", stripped):
            # `default N`, `default sequence N`, `default remark`: what the
            # device does is not cited (R7-2). Noted, not applied.
            led.note(lineno, notes,
                     f"`{lx.norm}` (line {lineno}) in {current_acl}: a `default` "
                     f"line in ACL mode is not modelled (what it restores or "
                     f"removes is not known)")
            continue
        if in_acl and _STATS.match(lx.norm):
            # NX-OS `statistics per-entry` only counts matches (Nexus 7000
            # NX-OS Security Command Reference, "statistics per-entry",
            # Command Modes: IP access-list configuration). Only NX-OS
            # (R7-7): elsewhere it is not cited.
            if vendor == "nxos":
                led.consume(lineno)
            else:
                led.note(lineno, notes,
                         f"`{lx.norm}` (line {lineno}) in {current_acl}: an NX-OS "
                         f"ACL command in a config read as {vendor}; not modelled")
            continue
        m = re.match(r"(?i)^(ip|ipv4|ipv6)\s+access-list\s+(?:(extended|standard)\s+)?(\S+)",
                     stripped)
        if m:
            _WILDCARD_ONLY.set(True)
            current_acl, seq = m.group(3), 0
            acl_opener = lineno if lx.mode == "acl" and lx.opener == lineno else -2
            cur_v6 = m.group(1).lower() == "ipv6"
            cur_std = (m.group(2) or "").lower() == "standard"
            cur_typed = bool(m.group(2))
            acl_meta.setdefault(current_acl, (vendor, cur_v6))
            names.add(current_acl)
            if _ACL_HEADER_FULL.match(lx.norm):
                led.consume(lineno)
            else:
                led.note(lineno, notes,
                         f"ACL header line {lineno} (`{lx.norm[:60]}`) holds words "
                         f"RuleHawk does not read")
            continue
        if _NON_FILTER_HDR.match(stripped):
            # Routing policy (route-map / prefix-list / community-list /
            # as-path) and ASA global knobs that merely contain the words
            # permit/deny are not packet filters. A block header starts a
            # non-filter context: its indented `seq N permit ...` lines belong
            # to it, never to the last IP ACL.
            if stripped.lower().startswith("mac access-list"):
                notes.append(f"L2 {stripped} not modeled (MAC filtering is out "
                             f"of scope; its entries are not IP rules)")
            continue
        if in_block:
            continue                         # body line of a non-filter block
        # The sequence-number prefix and its form (R7-1, R7-3).
        explicit: Optional[int] = None
        sm = _SEQ_FORM.match(lx.norm) if in_acl else None
        if sm:
            explicit = int(sm.group(2))
            digits = sm.group(2)
            top = _seq_max(vendor, cur_v6)
            if explicit < 1 or explicit > top or (len(digits) > 1 and digits[0] == "0"):
                led.note(lineno, notes,
                         f"sequence number {digits} (line {lineno}) in {current_acl} "
                         + ("is written with a leading zero, whose reading is not "
                            "cited" if 1 <= explicit <= top else
                            f"is outside the {vendor} {'IPv6' if cur_v6 else 'IPv4'} "
                            f"range 1-{top}: the device does not take the entry")
                         + "; not a PASS")
            form = "sequence" if sm.group(1) else "bare"
            if not _seq_form_ok(vendor, cur_v6, form):
                led.note(lineno, notes,
                         f"`{sm.group(1) or ''}{sm.group(2)}` (line {lineno}) in "
                         f"{current_acl}: this sequence-number form is not cited "
                         f"for {vendor} {'IPv6' if cur_v6 else 'IPv4'} ACL mode; "
                         f"read as a sequence number, not a PASS")
        body_txt = sm.group(3) if sm else lx.norm
        if in_acl and _REMARK.match(body_txt):
            event("remark", lineno, explicit)
            led.consume(lineno)
            continue
        if _FLAT_REMARK.match(stripped):
            led.consume(lineno)
            continue
        line_v6, line_std = cur_v6, cur_std
        m = re.match(r"(?i)^access-list\s+(\S+)\s+(?:line\s+\d+\s+)?(standard\s+)?",
                     stripped)
        if m and re.search(r"(?i)\b(permit|deny)\b", stripped):
            # Flat access-list. An IOS NUMBERED ACL (`access-list 101 permit
            # ...`, no `extended`/`standard` keyword) always carries WILDCARD
            # masks; only an ASA line (`access-list NAME extended|standard ...`)
            # carries netmasks. A numbered line in a config with a PIX/ASA
            # dialect marker is ambiguous (PIX 6 wrote numbered lines with
            # netmasks): keep the auto-detect there, and the fail-closed layer
            # reports `numbered-acl-mask-ambiguous` so no PASS rests on it.
            _WILDCARD_ONLY.set(bool(
                _IOS_NUMBERED.match(stripped) and not pix_dialect))
            current_acl = m.group(1)
            names.add(current_acl)
            # Flat `access-list` lines (ASA / IOS numbered) carry their own IPv4
            # context; standard = the explicit keyword, or an IOS standard number.
            line_v6 = False
            nm = m.group(1)
            line_std = bool(m.group(2)) or (nm.isdigit() and (
                1 <= int(nm) <= 99 or 1300 <= int(nm) <= 1999))
        if re.match(r"(?i)^evaluate\s+\S+", body_txt):
            # IOS reflexive ACL: `evaluate NAME` splices in the dynamic
            # return-traffic entries that `reflect NAME` permits created. They
            # match mirrored sessions only (return traffic, like `established`),
            # so they never decide a NEW flow and cannot prove a rule dead —
            # but the line must be surfaced, never dropped without a trace.
            led.note(lineno, notes,
                     f"IOS reflexive ACL `{stripped}` in {current_acl}: "
                     f"dynamic return-traffic entries not modeled (stateful, "
                     f"never a new-flow decision) — verify manually")
            continue
        if not re.search(r"(?i)\b(permit|deny)\b", stripped):
            continue                         # unaccounted: the ledger notes it
        if not m and not in_acl:
            # Not a flat `access-list` line and not in the mode of a named ACL
            # header: on the device this line is rejected (or belongs to a
            # mode that is not a packet filter), so it is in no named ACL. It
            # is kept under "(unnamed)", which nothing binds, with a note.
            where = (f"after line {lx.opener} (`{opener_txt[:40]}`)" if lx.opener
                     else "before any ACL header")
            led.note(lineno, notes,
                     f"line {lineno}: `{stripped[:60]}` is not in ACL mode "
                     f"on the device ({where}); not added to any named ACL")
            if current_acl != "(unnamed)":
                current_acl, seq, acl_opener = "(unnamed)", 0, -3
            cur_v6 = cur_std = line_v6 = line_std = False
        if m:
            _DIALECT.set("ios" if vendor == "ios" and _IOS_NUMBERED.match(stripped)
                         and not pix_dialect else "asa" if vendor == "ios" else vendor)
        elif vendor == "ios" and not line_v6 and not cur_typed:
            # `ip access-list NAME` with no `extended` / `standard` is the
            # NX-OS / EOS header form, which writes `A/len` operands: the
            # file's dialect is not IOS here, so the IOS operand rule does not
            # apply (its other rules do).
            _DIALECT.set("ios-untyped")
        else:
            _DIALECT.set(("ios6" if line_v6 else "ios") if vendor == "ios" else vendor)
        toks = _entry_tokens(raw.strip())
        if not toks or toks[0].lower() not in _ACTIONS:
            if "remark" not in stripped.lower():
                led.note(lineno, notes, f"unparsed: {stripped}")
            continue
        action = toks[0].lower()
        n0 = len(notes)
        if line_std:
            try:
                aces, enotes = _parse_std_entry(toks, seq, current_acl, stripped,
                                                lineno)
            except (IndexError, ValueError, ipaddress.AddressValueError):
                led.note(lineno, notes, f"unparsed (kept fail-closed): {stripped}")
                seq += 1
                entries.append(_opaque_ace(action, seq, current_acl, stripped,
                                           lineno))
                event("entry", lineno, explicit)
                continue
            seq += len(aces)
            entries.extend(aces)
            notes.extend(enotes)
            event("entry", lineno, explicit)
            (led.note if len(notes) > n0 else led.consume)(lineno)
            continue
        # Object-group / object references expand a permit in ways we don't model.
        # DROPPING such a line let segcheck FALSE-PASS a real leak hidden behind
        # the group (the line carries an action on the transit path). Fail closed:
        # emit an opaque imprecise stand-in (segcheck -> indeterminate, not OK).
        if _OPAQUE_RE.search(stripped):
            # Pass 2: try to expand the reference precisely from the collected
            # definitions. Only a FULLY-exact resolution is accepted; anything
            # else (undefined / unparseable member / cycle / over-cap) returns
            # None and we try partial resolution next.
            resolved = None
            try:
                resolved = _resolve_entry(toks, defs, seq, current_acl, stripped,
                                          lineno, line_v6)
            except (IndexError, ValueError, ipaddress.AddressValueError):
                resolved = None
            if resolved is None:
                # Partial-resolution pass: resolved address-group members emit
                # precise ACEs; unresolved members get one trailing opaque ACE
                # (any/any, imprecise -> INDETERMINATE, never silently PASS).
                # This lets a proven leak via a resolved member be reported as
                # CRITICAL instead of INDETERMINATE (soundness: the resolved
                # member's space is exact; adding unresolved members can only
                # EXPAND reachability, never remove the already-proven leak).
                try:
                    resolved = _resolve_entry(toks, defs, seq, current_acl,
                                              stripped, lineno, line_v6,
                                              partial=True)
                except (IndexError, ValueError, ipaddress.AddressValueError):
                    resolved = None
            if resolved is not None:
                races, rnotes = resolved
                seq += len(races)
                entries.extend(races)
                notes.extend(rnotes)
                event("entry", lineno, explicit)
                (led.note if len(notes) > n0 else led.consume)(lineno)
                continue
            led.note(lineno, notes, f"unmodeled (object-group): {stripped}")
            seq += 1
            entries.append(_opaque_ace(action, seq, current_acl, stripped, lineno))
            event("entry", lineno, explicit)
            continue
        try:
            aces, enotes = _parse_entry(toks, seq, current_acl, stripped, lineno,
                                        line_v6)
        except (IndexError, ValueError, ipaddress.AddressValueError):
            # Recognized as an ACE but unparseable — fail closed rather than drop,
            # so an unreadable permit can't be silently treated as isolated.
            led.note(lineno, notes, f"unparsed (kept fail-closed): {stripped}")
            seq += 1
            entries.append(_opaque_ace(action, seq, current_acl, stripped, lineno))
            event("entry", lineno, explicit)
            continue
        seq += len(aces)
        entries.extend(aces)
        notes.extend(enotes)
        event("entry", lineno, explicit)
        (led.note if len(notes) > n0 else led.consume)(lineno)
    entries = _apply_numbering(entries, notes, events, acl_meta)
    # Every other line that names an ACL is in scope too (round 9): it is
    # consumed only in a reference-only form (`_ACL_REF_OK`), which uses the
    # list and does not change it or bind it to a forwarding interface.
    # Interface lines are the interface ledger's.
    for lx in lex.lines:
        if lx.post_end or lx.mode in ("acl", "interface") or lx.no in led.scope:
            continue
        if lx.no in led.noted:               # a deletion line, noted above
            led.add(lx.no, lx.norm)
            continue
        words = lx.norm.split()
        if not any(w in names for w in words):
            continue
        led.add(lx.no, lx.norm)
        if any(r.fullmatch(lx.norm) and r.fullmatch(lx.norm).group("n") in names
               for r in _ACL_REF_OK):
            led.consume(lx.no)
        else:
            led.note(lx.no, notes,
                     f"line {lx.no} (`{lx.norm[:60]}`) names an ACL outside ACL "
                     f"mode; what it does to the ACL is not modelled")
    led.close(notes, lambda k, t: (
        f"line {k} (`{t[:60]}`) in ACL mode is not read by RuleHawk: what it "
        f"changes is not modelled"))
    return entries, notes


# An IOS numbered ACL line: a numeric name followed directly by the action (no
# ASA `extended` / `standard` / `webtype` / `ethertype` keyword).
# Its mask is always a wildcard. Cisco, "Configure IP Access Lists" (Document
# ID 23602, updated 2025-10-15, fetched 2026-11-05):
#   "In contrast, ACLs use a wildcard mask (also called an inverse mask)"
#   https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html
# and the IOS `access-list` command reference names the field so:
#   "source-wildcard (Optional) Wildcard bits to be applied to the source."
#   https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/access-list.htm
_IOS_NUMBERED = re.compile(
    r"(?i)^access-list\s+\d+\s+(?:permit|deny|dynamic)\b")


def _device_numbers(evs: list, remark_counts: bool):
    """Each line's sequence number as the device assigns it, and the lines a
    deletion removed. IOS XE 17 "IP Access List Entry Sequence Numbering"
    (https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-acl-seq-num.html):
    "If you enter an entry without a sequence number, it is assigned a
    sequence number that is 10 greater than the last sequence number in that
    access list and is placed at the end of the list." and "if entries with no
    sequence numbers are applied, the first entry is assigned a sequence
    number of 10". NX-OS says the same ("assigns a sequence number that is 10
    greater than the sequence number of the preceding rule", Nexus 3600 10.5
    "Configuring IP ACLs"). Whether an unnumbered `remark` takes a number is
    not cited: the caller computes both readings."""
    live: "dict[int, int]" = {}                # line -> number, entries on the list
    nums: "dict[int, int]" = {}
    deleted: set = set()
    for kind, ln, n in evs:
        if kind == "delete":
            for victim in [k for k, v in live.items() if v == n]:
                del live[victim]
                deleted.add(victim)
            continue
        if n is None:
            if kind == "remark" and not remark_counts:
                continue
            n = (max(live.values()) if live else 0) + 10
        live[ln] = n
        nums[ln] = n
    return nums, deleted


def _apply_numbering(entries: List[ACE], notes: List[str], events: "dict",
                     acl_meta: "Optional[dict]" = None) -> List[ACE]:
    """Put each ACL in device order and apply its deletions (round 8, R7-1,
    R7-2). An ACL with no explicit number and no deletion keeps text order.
    Otherwise every entry gets its device number (`_device_numbers`), the
    entries are sorted by it, and a change from text order is noted. When
    the two readings of an unnumbered remark give different orders or
    deletions, that is noted too."""
    import dataclasses

    order: List[str] = []
    by_acl: "dict[str, List[ACE]]" = {}
    for a in entries:
        if a.acl not in by_acl:
            by_acl[a.acl] = []
            order.append(a.acl)
        by_acl[a.acl].append(a)

    out: List[ACE] = []
    for acl in order:
        group = by_acl[acl]
        evs = events.get(acl, [])
        if acl == "(unnamed)" or not any(n is not None or k == "delete"
                                         for k, _, n in evs):
            out.extend(group)
            continue
        nums, deleted = _device_numbers(evs, True)
        nums_b, deleted_b = _device_numbers(evs, False)
        vend, v6 = (acl_meta or {}).get(acl, ("ios", False))
        fam = "IPv6" if v6 else "IPv4"
        # Round 9 (R8-7): +10 only where it is cited; elsewhere a mixed ACL
        # is noted. Explicit numbers are range-checked where they are read;
        # a generated number past the maximum is noted here (IOS XE 17:
        # "If the generated sequence number exceeds this maximum number ...
        # Exceeded maximum sequence number.").
        unnumbered = [k for k, _, n in evs if k != "delete" and n is None]
        if unnumbered and not _plus_ten_cited(vend, v6):
            notes.append(f"ACL {acl}: numbered and unnumbered entries are mixed; "
                         f"the number {vend} {fam} gives an unnumbered entry is not "
                         f"cited, so the device order is not known")
        top = _seq_max(vend, v6)
        if any(n > top for n in list(nums.values()) + list(nums_b.values())):
            notes.append(f"ACL {acl}: an unnumbered entry would get a number past "
                         f"the {vend} {fam} maximum {top} (\"Exceeded maximum "
                         f"sequence number\"); the device does not take it")
        # A numbered remark takes its number (IOS XE 16.12: "remarks can be
        # added with or without sequence number"; "If you enter a sequence
        # number that is already present, the following error message is
        # generated: Duplicate sequence number."). Whether an entry with the
        # same number is then rejected is not cited: noted.
        rem_nums = {n for k, _, n in evs if k == "remark" and n is not None}
        ent_nums = {nums.get(ln) for k, ln, n in evs if k == "entry"}
        if rem_nums & ent_nums:
            notes.append(f"ACL {acl}: sequence number(s) {sorted(rem_nums & ent_nums)} "
                         f"held by both a remark and an entry; which one the "
                         f"device keeps is not modelled")
        lines = [ln for k, ln, _ in evs if k == "entry"]
        pos = {ln: i for i, ln in enumerate(lines)}
        rank_a = sorted(lines, key=lambda ln: (nums.get(ln, 0), pos[ln]))
        rank_b = sorted(lines, key=lambda ln: (nums_b.get(ln, 0), pos[ln]))
        if [ln for ln in rank_a if ln not in deleted] != \
                [ln for ln in rank_b if ln not in deleted_b]:
            notes.append(f"ACL {acl}: the device order depends on whether an "
                         f"unnumbered remark takes a sequence number, which is "
                         f"not known")
        deleted &= deleted_b
        group = [a for a in group if a.line not in deleted]
        # One sequence number = ONE entry on the device. A config that
        # carries the same ACL twice (concatenated `show run` sections) or
        # re-enters `10 permit ...` repeats the number: an identical re-entry
        # is the same entry (keep the first; reporting the copy as
        # "redundant" was noise the device never has). Different text under
        # the same number is not modeled — keep both, marked imprecise.
        first_line: "dict[int, tuple]" = {}
        drop, clash = set(), set()
        for a in group:
            k = nums.get(a.line, 0)
            txt = re.sub(r"\s+", " ", a.raw.strip()).lower()
            if k not in first_line:
                first_line[k] = (a.line, txt)
            elif first_line[k][0] != a.line:
                (drop if first_line[k][1] == txt else clash).add(a.line)
                if first_line[k][1] != txt:
                    clash.add(first_line[k][0])
        if drop:
            notes.append(f"ACL {acl}: {len(drop)} entr(ies) repeat an existing "
                         f"sequence number with identical text — one entry "
                         f"on the device, duplicates ignored")
        if clash:
            notes.append(f"ACL {acl}: sequence number(s) "
                         f"{sorted({nums.get(ln, 0) for ln in clash})} appear with "
                         f"different entries — not modeled, marked imprecise")
        group = [dataclasses.replace(a, imprecise=True) if a.line in clash else a
                 for a in group if a.line not in drop]
        keyed = sorted(range(len(group)),
                       key=lambda i: (nums.get(group[i].line, 0), i))
        if keyed != list(range(len(group))):
            group = [group[i] for i in keyed]
            notes.append(f"ACL {acl}: entries reordered by explicit sequence "
                         f"number (an unnumbered entry is the last number + 10) "
                         f"to match device first-match evaluation")
        group = [dataclasses.replace(a, seq=n) for n, a in enumerate(group, 1)]
        out.extend(group)
    return out


def _parse_entry(toks: List[str], seq: int, acl: str, raw: str, line: int = 0,
                 v6: bool = False):
    """Parse one ACE line into a LIST of ACEs (a multi-port `eq` expands to the
    exact union of per-port rules). ACEs are numbered seq+1, seq+2, ...; the
    caller advances its counter by len(result)."""
    action = toks[0].lower()
    proto = _norm_proto(toks[1])
    ported = proto in ("tcp", "udp")
    i = 2
    extra_sp = extra_dp = 0
    src, i, imp_s = _parse_addr(toks, i, v6)
    if ported:
        src_ports, i, imp_sp, extra_sp = _parse_port_op(toks, i)
    else:
        src_ports, imp_sp = [ANY_PORTS], False
    dst, i, imp_d = _parse_addr(toks, i, v6)
    if ported:
        dst_ports, i, imp_dp, extra_dp = _parse_port_op(toks, i)
    else:
        dst_ports, imp_dp = [ANY_PORTS], False
    rest = toks[i:]
    cidr = _v4_prefix_operands(toks[2:i]) if not v6 else []
    narrowing, type_tok, extra_unknown, stateful, inactive = _scan_trailer(rest)
    if inactive:
        # ASA `inactive`: the rule is DISABLED on the device — its true match
        # space is empty, so emitting no ACE is exact (not a narrowing).
        return [], [f"inactive (disabled on device, not enforced) -> skipped: {raw}"]
    icmp_type = _canon_icmp_type(type_tok, proto) if proto in ("icmp", "icmpv6") else None
    # Unknown trailing tokens: for icmp the first free token is the (modeled)
    # ICMP type; every other free token — and for non-icmp protos the first one
    # too — is an unrecognized qualifier (a TCP flag like `syn`, an `eq`-list
    # service name outside our table, pasted `show access-list` residue). Such
    # a token changes what the device really matches in a way we don't model,
    # so silently ignoring it is a false-PASS path (a `syn`-narrowed deny can
    # "prove" isolation the device doesn't enforce; a dropped `exec` port can
    # hide a real leak). Fail closed: mark imprecise and surface a note.
    unknown = list(extra_unknown)
    if type_tok is not None and icmp_type is None:
        # Mirrors _resolve_entry: the first free token is the modeled ICMP type
        # for BOTH ICMP families (`permit 58 any any 128` is icmpv6 type 128,
        # not an unknown qualifier); only a non-ICMP proto makes it unknown.
        unknown.insert(0, type_tok)
    imprecise = (imp_s or imp_d or imp_sp or imp_dp or bool(narrowing)
                 or bool(unknown) or bool(cidr))
    notes: List[str] = []
    if cidr:
        notes.append(_CIDR_NOTE.format("/".join(cidr)) + raw)
    if imp_s or imp_d:
        notes.append(f"imprecise mask (treated conservatively): {raw}")
    if imp_sp or imp_dp:
        notes.append(_PORT_OP_NOTE + raw)
    if narrowing:
        notes.append("match-narrowing qualifier "
                     + "/".join(sorted(set(narrowing)))
                     + " not modeled — match space narrowed, kept as a "
                     + f"superset (imprecise), verify manually: {raw}")
    if unknown:
        notes.append("unrecognized trailing qualifier "
                     + "/".join(unknown)
                     + f" — marked imprecise, verify manually: {raw}")
    if extra_sp or extra_dp:
        notes.append("multi-port `eq` expanded to the exact union of per-port "
                     f"rules ({extra_sp + extra_dp} extra port(s) now modeled, "
                     f"not dropped): {raw}")
    aces: List[ACE] = []
    n = seq
    for sp in src_ports:
        for dp in dst_ports:
            n += 1
            aces.append(ACE(seq=n, action=action, proto=proto, src=src, dst=dst,
                            src_port=sp, dst_port=dp, icmp_type=icmp_type,
                            stateful=stateful, imprecise=imprecise, raw=raw,
                            acl=acl, line=line))
    return aces, notes


# IPv4 operand grammar per dialect (round 9, R8-6). IOS: "sequence-number deny
# protocol source source-wildcard destination destination-wildcard ..." (IOS
# XE 17 "IP Access List Entry Sequence Numbering", URL above). ASA: "ip_address
# mask—Specifies an IPv4 network address and subnet mask" and
# "ipv6-address/prefix-length" for IPv6 only (ASA 9.20 Firewall CLI
# Configuration Guide, URL above). Neither has an IPv4 `A/len` operand, so on
# IOS and ASA one is noted (NX-OS and EOS write `A/len`).
_CIDR_NOTE = ("IPv4 prefix operand(s) {} are not in the IOS / ASA entry grammar "
              "(address + wildcard or mask); the device may reject the line — "
              "marked imprecise: ")


def _v4_prefix_operands(ops: List[str]) -> List[str]:
    if _DIALECT.get() not in ("ios", "asa"):
        return []
    return [t for t in ops if "/" in t and _is_v4(t.split("/", 1)[0])]


def _is_v4(tok: str) -> bool:
    try:
        ipaddress.IPv4Address(tok)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _parse_std_entry(toks: List[str], seq: int, acl: str, raw: str,
                     line: int = 0):
    """Parse one STANDARD ACL entry (IOS numbered 1-99/1300-1999, `ip access-list
    standard`, ASA `access-list N standard`): action + SOURCE operand only; the
    destination is implicitly any and the protocol ip. Source forms: `any` |
    `host A` | `A` (bare = host) | `A MASK` (IOS wildcard / ASA netmask,
    auto-detected by _classify_mask like extended operands)."""
    action = toks[0].lower()
    t = toks[1].lower()
    if t in ("any", "host") or "/" in toks[1]:
        src, nxt, imp = _parse_addr(toks, 1)
    elif len(toks) > 2 and _is_v4(toks[2]):
        src, nxt, imp = _parse_addr(toks, 1)   # A MASK
    else:
        src, nxt, imp = _host_net(toks[1]), 2, False  # bare address == host
    notes = [f"imprecise mask (treated conservatively): {raw}"] if imp else []
    cidr = _v4_prefix_operands(toks[1:nxt])
    if cidr:
        imp = True
        notes.append(_CIDR_NOTE.format("/".join(cidr)) + raw)
    # Every token is read (round 8): after the source only `log` / `log-input`
    # (which do not change the match) may follow. Anything else means the
    # device rejects or reads the line differently: imprecise and noted.
    rest = [w.lower() for w in toks[nxt:]]
    if rest and rest not in (["log"], ["log-input"]):
        imp = True
        notes.append(f"unrecognized trailing word(s) {'/'.join(toks[nxt:])} in a "
                     f"standard ACL entry — marked imprecise, verify manually: {raw}")
    return [ACE(seq=seq + 1, action=action, proto="ip", src=src, dst=_ANY_NET,
                imprecise=imp, raw=raw, acl=acl, line=line)], notes
