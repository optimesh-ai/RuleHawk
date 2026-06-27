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
