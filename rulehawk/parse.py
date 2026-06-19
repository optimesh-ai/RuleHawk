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
from typing import List, Tuple

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


def _parse_port_op(tokens: List[str], i: int) -> Tuple[PortRange, int, bool, int]:
    """Parse an optional port operator; return (range, next_i, imprecise, dropped).

    `dropped` is the count of trailing port tokens NOT modeled. IOS allows a
    multi-port `eq a b c`; the model holds a single range, so only the first
    port is analyzed and the rest are reported via a parse note — never silently
    dropped (that would hide e.g. an exposed RDP port)."""
    if i >= len(tokens):
        return ANY_PORTS, i, False, 0
    op = tokens[i]
    if op == "eq":
        p = _port_num(tokens[i + 1])
        j, dropped = i + 2, 0
        while j < len(tokens) and _is_port_token(tokens[j]):  # extra eq ports
            j += 1
            dropped += 1
        return (PortRange(p, p) if p >= 0 else ANY_PORTS), j, p < 0, dropped
    if op == "range":
        lo, hi = _port_num(tokens[i + 1]), _port_num(tokens[i + 2])
        if lo < 0 or hi < 0:
            return ANY_PORTS, i + 3, True, 0
        return PortRange(min(lo, hi), max(lo, hi)), i + 3, False, 0
    if op == "gt":
        p = _port_num(tokens[i + 1])
        if p < 0 or p >= PORT_MAX:
            return ANY_PORTS, i + 2, True, 0
        return PortRange(p + 1, PORT_MAX), i + 2, False, 0
    if op == "lt":
        p = _port_num(tokens[i + 1])
        if p <= PORT_MIN:
            return ANY_PORTS, i + 2, True, 0
        return PortRange(PORT_MIN, p - 1), i + 2, False, 0
    if op == "neq":
        # neq's true space is non-contiguous (everything EXCEPT p). We cannot
        # represent that as one range, so over-approximate to ANY and mark the
        # entry imprecise — it must never be used to prove another rule dead.
        return ANY_PORTS, i + 2, True, 0
    return ANY_PORTS, i, False, 0


def _entry_tokens(line: str) -> List[str]:
    s = line.strip()
    s = re.sub(r"^\d+\s+", "", s)                                  # IOS seq num
    # ASA prefix: name, optional `line N` (from `show access-list`), optional `extended`.
    s = re.sub(r"(?i)^access-list\s+\S+\s+(?:line\s+\d+\s+)?(?:extended\s+)?", "", s)
    return s.split()


def parse_acls(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse all ACLs in `text`; return (entries, notes).

    `notes` records lines recognized as ACEs but not fully modeled — surfaced,
    never silently dropped.
    """
    entries: List[ACE] = []
    notes: List[str] = []
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
        if re.search(r"(?i)object-group|addrgroup|portgroup", stripped):
            notes.append(f"unmodeled (object-group): {stripped}")
            continue
        toks = _entry_tokens(raw.strip())
        if not toks or toks[0].lower() not in _ACTIONS:
            if "remark" not in stripped.lower():
                notes.append(f"unparsed: {stripped}")
            continue
        try:
            ace, enotes = _parse_entry(toks, seq + 1, current_acl, stripped)
        except (IndexError, ValueError, ipaddress.AddressValueError):
            notes.append(f"unparsed: {stripped}")
            continue
        seq += 1
        entries.append(ace)
        notes.extend(enotes)
    return entries, notes


def _parse_entry(toks: List[str], seq: int, acl: str, raw: str):
    action = toks[0].lower()
    proto = toks[1].lower()
    ported = proto in ("tcp", "udp")
    i = 2
    drop_sp = drop_dp = 0
    src, i, imp_s = _parse_addr(toks, i)
    if ported:
        src_port, i, imp_sp, drop_sp = _parse_port_op(toks, i)
    else:
        src_port, imp_sp = ANY_PORTS, False
    dst, i, imp_d = _parse_addr(toks, i)
    if ported:
        dst_port, i, imp_dp, drop_dp = _parse_port_op(toks, i)
    else:
        dst_port, imp_dp = ANY_PORTS, False
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
    if drop_sp or drop_dp:
        notes.append("multi-port `eq` only partly modeled (first port analyzed; "
                     f"remaining port(s) ignored — verify them manually): {raw}")
    ace = ACE(seq=seq, action=action, proto=proto, src=src, dst=dst,
              src_port=src_port, dst_port=dst_port, icmp_type=icmp_type,
              stateful=stateful, imprecise=imprecise, raw=raw, acl=acl)
    return ace, notes
