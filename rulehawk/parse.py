"""Parse Cisco IOS extended ACLs and Cisco ASA access-lists into `ACE`s.

Address operand forms: `any` | `host A.B.C.D` | `A.B.C.D/len` | `A.B.C.D MASK`.
The `A.B.C.D MASK` form is the tricky one: IOS uses an INVERSE wildcard
(`0.0.0.255`) while ASA uses a NORMAL subnet mask (`255.255.255.0`). We
auto-detect by the mask's bit pattern rather than guessing the vendor; a
non-contiguous or genuinely ambiguous mask marks the entry `imprecise` and emits
a parse note, so it can never be used to (wrongly) prove another rule dead.

`neq` ports and `established` are modeled honestly: `neq` -> imprecise (its true
space is non-contiguous), `established` -> stateful. ICMP type qualifiers are
captured so `echo` and `echo-reply` aren't treated as the same packet space.
Unmodeled lines (object-group, etc.) are surfaced as notes, never silently dropped.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple

from .model import ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet

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
}
_ACTIONS = ("permit", "deny")
_TRAILING_NONTYPE = {"log", "log-input", "established", "fragments", "ttl",
                     "dscp", "time-range", "tos", "precedence"}


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
        # Only 0.0.0.0 or 255.255.255.255 satisfy both readings. In real ACLs an
        # address paired with one of these denotes a single host (/32) — "any" is
        # written as `any`, not `0.0.0.0 255.255.255.255` in this operand slot.
        # Resolve to an EXACT host so it never widens to /0 (which would falsely
        # trip the over-permissive checks) and isn't needlessly marked imprecise.
        return 32, "host"
    if is_nm:
        return pc, "netmask"
    if is_wc:
        return 32 - pc, "wildcard"
    return 32 - pc, "noncontiguous"     # best-effort; caller marks imprecise


def _parse_addr(tokens: List[str], i: int) -> Tuple[_IPNet, int, bool]:
    """Parse an address operand; return (net, next_i, imprecise)."""
    t = tokens[i]
    if t == "any":
        return ipaddress.ip_network("0.0.0.0/0"), i + 1, False
    if t == "host":
        return ipaddress.ip_network(f"{tokens[i + 1]}/32", strict=False), i + 2, False
    if "/" in t:
        return ipaddress.ip_network(t, strict=False), i + 1, False
    addr, mask = tokens[i], tokens[i + 1]
    plen, kind = _classify_mask(mask)
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
    op = tokens[i]
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
        # neq's true space is non-contiguous (everything EXCEPT p). We cannot
        # represent that as one range, so over-approximate to ANY and mark the
        # entry imprecise — it must never be used to prove another rule dead.
        return [ANY_PORTS], i + 2, True, 0
    return [ANY_PORTS], i, False, 0


def _entry_tokens(line: str) -> List[str]:
    s = line.strip()
    s = re.sub(r"^\d+\s+", "", s)                                  # IOS seq num
    # ASA prefix: name, optional `line N` (from `show access-list`), optional `extended`.
    s = re.sub(r"(?i)^access-list\s+\S+\s+(?:line\s+\d+\s+)?(?:extended\s+)?", "", s)
    return s.split()


_ANY_NET = ipaddress.ip_network("0.0.0.0/0")
# Lines we recognize as an ACE (start with permit/deny) but cannot reduce to an
# L3/L4 rectangle: object-group / object / service-object references, or an
# unparseable operand. Matched on the original line.
_OPAQUE_RE = re.compile(
    r"(?i)\b(object-group|object|addrgroup|portgroup|service-object|"
    r"port-object|group-object)\b")


def _opaque_ace(action: str, seq: int, acl: str, raw: str) -> ACE:
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
               imprecise=True, raw=raw, acl=acl)


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
    except (ValueError, IndexError):
        return [("bad",)]


def _expand_proto(p: Optional[str]) -> Optional[List[str]]:
    if p is None:
        return None
    p = p.lower()
    if p == "tcp-udp":
        return ["tcp", "udp"]
    if p in ("tcp", "udp", "icmp", "ip", "ipv6"):
        return [p]
    return None                              # unknown -> fail closed


def _svc_port(rest: List[str], idx: int) -> Optional[PortRange]:
    """Parse `eq P` / `range LO HI` at rest[idx:]. Only exact, contiguous forms;
    lt/gt/neq stay unmodeled (-> caller fails closed)."""
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
            if protos is None or pr is None:
                return [("bad",)]
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
        if pr is None:
            return [("bad",)]
        return [("svc", p, pr) for p in protos]
    except (ValueError, IndexError):
        return [("bad",)]


def _collect_defs(text: str) -> _Defs:
    """Pass 1: read every object-group / object definition in the config."""
    defs = _Defs()
    cur = None          # ("ng"|"no"|"sg"|"so"|"other", name)
    header_proto = None
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("!"):
            continue
        low = s.lower()
        m = re.match(r"(?i)^object-group\s+network\s+(\S+)", s)
        if m:
            cur, header_proto = ("ng", m.group(1)), None
            defs.net_groups.setdefault(m.group(1), [])
            continue
        m = re.match(r"(?i)^object-group\s+service\s+(\S+)(?:\s+(\S+))?", s)
        if m:
            cur, header_proto = ("sg", m.group(1)), (m.group(2) or "").lower() or None
            defs.svc_groups.setdefault(m.group(1), [])
            continue
        m = re.match(r"(?i)^object\s+network\s+(\S+)", s)
        if m:
            cur, header_proto = ("no", m.group(1)), None
            defs.net_objs.setdefault(m.group(1), [])
            continue
        m = re.match(r"(?i)^object\s+service\s+(\S+)", s)
        if m:
            cur, header_proto = ("so", m.group(1)), None
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
            if ctype == "ng":
                defs.net_groups[name].append(("ng", toks[1]))
            elif ctype == "sg":
                defs.svc_groups[name].append(("sg", toks[1]))
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


def _operand_addr(toks: List[str], i: int, defs: _Defs):
    """Parse a src/dst address operand, resolving object(-group) refs.
    Returns (nets|None, next_i, imprecise). None nets -> caller fails closed."""
    t = toks[i].lower()
    if t == "object-group":
        return _resolve_nets(defs, "ng", toks[i + 1], frozenset()), i + 2, False
    if t == "object":
        return _resolve_nets(defs, "no", toks[i + 1], frozenset()), i + 2, False
    net, ni, imp = _parse_addr(toks, i)
    return [net], ni, imp


def _is_svc_ref(toks: List[str], i: int, defs: _Defs) -> bool:
    if i + 1 >= len(toks):
        return False
    t = toks[i].lower()
    return ((t == "object-group" and toks[i + 1] in defs.svc_groups)
            or (t == "object" and toks[i + 1] in defs.svc_objs))


def _resolve_entry(toks: List[str], defs: _Defs, seq: int, acl: str, raw: str):
    """Pass 2: expand one object-referencing ACE to the exact union of member
    ACEs, or return None to fall back to the fail-closed opaque ACE."""
    action = toks[0].lower()
    n = len(toks)
    i = 1
    proto: Optional[str] = None
    proto_combos = None                      # service group occupying the proto slot
    if i < n and _is_svc_ref(toks, i, defs):
        kind = "sg" if toks[i].lower() == "object-group" else "so"
        proto_combos = _resolve_svcs(defs, kind, toks[i + 1], frozenset())
        if proto_combos is None:
            return None
        i += 2
    elif i < n:
        proto = toks[i].lower()
        i += 1
    else:
        return None
    if i >= n:
        return None

    srcs, i, imp_s = _operand_addr(toks, i, defs)
    if srcs is None:
        return None
    imprecise = imp_s
    ported = proto in ("tcp", "udp") if proto else True

    # Optional source port (only a literal operator; a source SERVICE group is
    # rare — leave it unresolved/fail-closed rather than grow the model).
    src_ports: List[PortRange] = [ANY_PORTS]
    if i < n and ported and toks[i].lower() in _PORT_OPS:
        src_ports, i, imp_sp, _ = _parse_port_op(toks, i)
        imprecise = imprecise or imp_sp
    elif i < n and _is_svc_ref(toks, i, defs):
        return None

    if i >= n:
        return None
    dsts, i, imp_d = _operand_addr(toks, i, defs)
    if dsts is None:
        return None
    imprecise = imprecise or imp_d

    # Build the (proto, dst_port) combinations.
    combos: List[Tuple[str, PortRange]] = []
    if proto_combos is not None:             # service group set proto + dst port
        combos = list(proto_combos)
    elif i < n and _is_svc_ref(toks, i, defs):
        kind = "sg" if toks[i].lower() == "object-group" else "so"
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
        combos = [(proto, dp) for dp in dst_ports]
    else:
        combos = [(proto or "ip", ANY_PORTS)]

    if len(srcs) * len(dsts) * len(src_ports) * len(combos) > _MAX_EXPAND:
        return None                          # over-cap -> fail closed (one opaque ACE)

    rest = toks[i:]
    stateful = any(t.lower() == "established" for t in rest)
    aces: List[ACE] = []
    m = seq
    for s in srcs:
        for d in dsts:
            for sp in src_ports:
                for cproto, dp in combos:
                    m += 1
                    aces.append(ACE(
                        seq=m, action=action, proto=cproto, src=s, dst=d,
                        src_port=sp, dst_port=dp, stateful=stateful,
                        imprecise=imprecise, raw=raw, acl=acl))
    note = (f"resolved object-group/object reference to {len(aces)} exact "
            f"ACE(s): {raw}")
    return aces, [note]


def parse_acls(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse all ACLs in `text`; return (entries, notes).

    `notes` records lines recognized as ACEs but not fully modeled — surfaced,
    never silently dropped.
    """
    entries: List[ACE] = []
    notes: List[str] = []
    defs = _collect_defs(text)               # pass 1: object-group / object defs
    current_acl = "(unnamed)"
    seq = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("!"):
            continue
        m = re.match(r"(?i)^ip(?:v6)?\s+access-list\s+(?:extended\s+|standard\s+)?(\S+)",
                     stripped)
        if m:
            current_acl, seq = m.group(1), 0
            continue
        m = re.match(r"(?i)^access-list\s+(\S+)\s+", stripped)
        if m and re.search(r"(?i)\b(permit|deny)\b", stripped):
            current_acl = m.group(1)
        if not re.search(r"(?i)\b(permit|deny)\b", stripped):
            continue
        toks = _entry_tokens(raw.strip())
        if not toks or toks[0].lower() not in _ACTIONS:
            if "remark" not in stripped.lower():
                notes.append(f"unparsed: {stripped}")
            continue
        action = toks[0].lower()
        # Object-group / object references expand a permit in ways we don't model.
        # DROPPING such a line let segcheck FALSE-PASS a real leak hidden behind
        # the group (the line carries an action on the transit path). Fail closed:
        # emit an opaque imprecise stand-in (segcheck -> indeterminate, not OK).
        if _OPAQUE_RE.search(stripped):
            # Pass 2: try to expand the reference precisely from the collected
            # definitions. Only a FULLY-exact resolution is accepted; anything
            # else (undefined / unparseable member / cycle / over-cap) returns
            # None and we keep the fail-closed opaque ACE (INDETERMINATE).
            resolved = None
            try:
                resolved = _resolve_entry(toks, defs, seq, current_acl, stripped)
            except (IndexError, ValueError, ipaddress.AddressValueError):
                resolved = None
            if resolved is not None:
                races, rnotes = resolved
                seq += len(races)
                entries.extend(races)
                notes.extend(rnotes)
                continue
            notes.append(f"unmodeled (object-group): {stripped}")
            seq += 1
            entries.append(_opaque_ace(action, seq, current_acl, stripped))
            continue
        try:
            aces, enotes = _parse_entry(toks, seq, current_acl, stripped)
        except (IndexError, ValueError, ipaddress.AddressValueError):
            # Recognized as an ACE but unparseable — fail closed rather than drop,
            # so an unreadable permit can't be silently treated as isolated.
            notes.append(f"unparsed (kept fail-closed): {stripped}")
            seq += 1
            entries.append(_opaque_ace(action, seq, current_acl, stripped))
            continue
        seq += len(aces)
        entries.extend(aces)
        notes.extend(enotes)
    return entries, notes


def _parse_entry(toks: List[str], seq: int, acl: str, raw: str):
    """Parse one ACE line into a LIST of ACEs (a multi-port `eq` expands to the
    exact union of per-port rules). ACEs are numbered seq+1, seq+2, ...; the
    caller advances its counter by len(result)."""
    action = toks[0].lower()
    proto = toks[1].lower()
    ported = proto in ("tcp", "udp")
    i = 2
    extra_sp = extra_dp = 0
    src, i, imp_s = _parse_addr(toks, i)
    if ported:
        src_ports, i, imp_sp, extra_sp = _parse_port_op(toks, i)
    else:
        src_ports, imp_sp = [ANY_PORTS], False
    dst, i, imp_d = _parse_addr(toks, i)
    if ported:
        dst_ports, i, imp_dp, extra_dp = _parse_port_op(toks, i)
    else:
        dst_ports, imp_dp = [ANY_PORTS], False
    rest = toks[i:]
    stateful = any(t.lower() == "established" for t in rest)
    icmp_type = None
    if proto == "icmp":
        for t in rest:
            if t.lower() not in _TRAILING_NONTYPE:
                icmp_type = t
                break
    imprecise = imp_s or imp_d or imp_sp or imp_dp
    notes: List[str] = []
    if imp_s or imp_d:
        notes.append(f"imprecise mask (treated conservatively): {raw}")
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
                            stateful=stateful, imprecise=imprecise, raw=raw, acl=acl))
    return aces, notes
