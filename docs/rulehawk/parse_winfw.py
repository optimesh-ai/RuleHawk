"""Parse Windows Defender Firewall (WFAS) rules into RuleHawk ``ACE``s.

TARGET FORMAT — the text of ``netsh advfirewall firewall show rule name=all``:
one block per rule, blocks separated by blank lines, each block a set of
``FieldName:  value`` lines (multi-value ``LocalIP``/``RemoteIP`` appear either
comma-separated or one value per indented continuation line)::

    Rule Name:                            Allow SQL from CORP
    ----------------------------------------------------------------------
    Enabled:                              Yes
    Direction:                            In
    Profiles:                             Domain,Private
    LocalIP:                              Any
    RemoteIP:                             10.20.0.0/16
    Protocol:                             TCP
    LocalPort:                            1433
    RemotePort:                           Any
    Action:                               Allow

WINDOWS FIREWALL SEMANTICS — modeled SOUNDLY (this is the subtle part).

BLOCK-PRECEDENCE (why this frontend reorders). WFAS evaluation is NOT the plain
first-match the RuleHawk engine assumes: for a given packet an explicit **Block**
rule generally WINS over any **Allow** rule ("block takes precedence"), and only
if nothing matches does the per-profile default apply (inbound = block,
outbound = allow). To render that in a first-match engine SOUNDLY, WITHIN A
DIRECTION we emit every **Block** rule FIRST (as ``deny`` ACEs), THEN every
**Allow** rule (as ``permit``), THEN the direction default (inbound -> a trailing
``deny ip any any``; outbound -> a trailing ``permit ip any any``). Ordering the
blocks first means any packet a block matches hits the ``deny`` before it can
reach an ``allow`` — exactly WFAS's block-precedence. This is a CONSERVATIVE
model: it can only make the modeled result MORE restrictive than the device in
the rare cases where WFAS would have allowed (e.g. a more-specific allow beating
a broad block is not something WFAS does — block still wins — so we never make it
LESS restrictive). It therefore never falsely PERMITS: an inter-zone
``must_not_reach`` can never FALSE-PASS because we dropped a block, and a
``must_reach`` connectivity check fails closed rather than over-claiming.

DIRECTION -> HOST-HOOK ORIENTATION (transit=False).
  * ``Direction: In`` (inbound): the host is the packet DESTINATION.
    ``LocalIP`` -> dst (``Any`` = the host itself = ANY, a superset), ``RemoteIP``
    -> src. ``acl = "Inbound"``.
  * ``Direction: Out`` (outbound): the host is the packet SOURCE.
    ``LocalIP`` -> src, ``RemoteIP`` -> dst. ``acl = "Outbound"``.
  Both directions are HOST hooks (like the iptables INPUT/OUTPUT chains), NOT the
  transit/forwarding path — a forwarded inter-zone packet never traverses them.
  So every emitted ACE is flagged ``transit=False``: it is excluded from the
  inter-zone segmentation witness search (its default-deny must never shadow a
  real forwarding permit) but stays available for hygiene analysis.

PORT MAPPING. ``dst_port`` is always the port on the DESTINATION side of the
flow. Inbound (host = dst): ``dst_port = LocalPort`` (the service the host
offers), ``src_port = RemotePort``. Outbound (host = src): ``dst_port =
RemotePort``, ``src_port = LocalPort``. Ports apply only to TCP/UDP. ``Any`` ->
ANY_PORTS; ``80,443`` -> the exact union of per-port ACEs; ``5000-5100`` -> one
range. A dynamic/named port that does not resolve to a numeric range (``RPC``,
``RPC-EPMap``, ``IPHTTPS``, ``Teredo``, ``Edge Traversal``) really spans a wide,
unknown range, so the whole port dimension is WIDENED to ANY + ``imprecise`` +
note — never a subset (the RuleHawk superset contract).

ADDRESSES. ``Any`` -> 0.0.0.0/0 (and ::/0 as the family demands); a CIDR / bare
IP -> that network; ``10.0.0.0-10.0.0.255`` -> the exact set of covering CIDRs.
Keyword scopes that are not a concrete CIDR (``LocalSubnet``, ``DNS``, ``DHCP``,
``WINS``, ``Intranet``, ``DefaultGateway``, ``Internet``, ...) are WIDENED to ANY
+ ``imprecise`` + note. Expansion is capped (~256); an over-cap side widens to
ANY + ``imprecise``.

OTHER FIELDS. ``Enabled: No`` -> the rule is disabled on the device; it is
skipped (no ACE) + note (exact, like ASA ``inactive``). ``Protocol: ICMPv4`` ->
``icmp``; ``ICMPv6`` -> ``icmpv6`` (an ICMP ``Type:Code`` is modeled as
``icmp_type`` when present, else all types). L3/L4-orthogonal NARROWING scopes we
do not model (``Program``, ``Service``, ``InterfaceType``, IPsec ``Security``)
mark the ACE ``imprecise`` so a narrowed deny can never prove isolation the
device does not enforce.

Malformed / partial blocks degrade with a note, never crash: a block missing
``Action`` or ``Direction`` is skipped with a note.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet
from .parse import _canon_icmp_type, _port_num  # reuse IANA service + icmp maps

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")
_MAX_EXPAND = 256

# IANA protocol numbers netsh may render in the Protocol slot. Folding a numeric
# proto to its name lets a numeric-proto rule compare against a named policy
# assertion; TCP/UDP in particular must fold so their port dimension applies.
_PROTO_NUM = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "47": "gre",
              "50": "esp", "51": "ah", "58": "icmpv6", "89": "ospf",
              "103": "pim", "112": "vrrp", "132": "sctp"}

# A field line begins at column 0 with `Name:` (names may contain spaces, e.g.
# "Rule Name", "Edge traversal"); its value is the remainder (a value may itself
# contain colons — IPv6 literals, Type:Code — so only the FIRST colon splits).
_FIELD_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9 /_.-]*?)\s*:\s*(?P<val>.*?)\s*$")
# Fields whose values legitimately repeat / continue across lines.
_MULTI = frozenset({"localip", "remoteip", "localport", "remoteport"})
# `LOW-HIGH` numeric port range.
_PORT_RANGE_RE = re.compile(r"^(\d+)\s*-\s*(\d+)$")

# detect() markers.
_NETSH_RE = re.compile(r"(?i)netsh\s+advfirewall")
_RULE_NAME_RE = re.compile(r"(?im)^\s*Rule Name\s*:")
_DIRECTION_RE = re.compile(r"(?im)^\s*Direction\s*:")
_ACTION_RE = re.compile(r"(?im)^\s*Action\s*:")


def detect(text: str) -> bool:
    """True when `text` looks like ``netsh advfirewall ... show rule`` output.

    Requires the three structural markers ``Rule Name:``, ``Direction:`` and
    ``Action:`` (line-anchored, case-insensitive) together, OR the literal
    ``netsh advfirewall`` command string. No other vendor frontend (Cisco IOS/ASA,
    Junos, PAN-OS, iptables) emits that trio of colon-terminated field labels, so
    this never collides with them.
    """
    if _NETSH_RE.search(text):
        return True
    return bool(_RULE_NAME_RE.search(text)
                and _DIRECTION_RE.search(text)
                and _ACTION_RE.search(text))


def _host_net(addr: str) -> _IPNet:
    return ipaddress.ip_network(addr + ("/128" if ":" in addr else "/32"),
                                strict=False)


def _norm_proto(v: str) -> str:
    v = v.strip().lower()
    if v in ("", "any"):
        return "ip"
    if v == "tcp":
        return "tcp"
    if v == "udp":
        return "udp"
    if v in ("icmpv4", "icmp"):
        return "icmp"
    if v == "icmpv6":
        return "icmpv6"
    return _PROTO_NUM.get(v, v)             # numeric/other -> name or opaque-exact


def _iter_blocks(text: str) -> List[Dict[str, object]]:
    """Split netsh show-rule output into per-rule field dictionaries.

    A new block starts at each column-0 ``Rule Name:`` line. Column-0 ``Name:``
    lines set fields; indented lines continue the previous field's value (netsh
    lists multiple LocalIP/RemoteIP one per continuation line); the ``-----``
    separator and any other non-field line is skipped. ``_line`` records the
    1-based source line of the block's ``Rule Name`` for CI annotation.
    """
    blocks: List[Dict[str, object]] = []
    cur: Optional[Dict[str, object]] = None
    cur_field: Optional[str] = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw.strip() == "":
            cur_field = None
            continue
        if raw[:1].isspace():                       # continuation of cur_field
            if cur is not None and cur_field is not None:
                v = raw.strip()
                if v:
                    prev = cur.get(cur_field)
                    cur[cur_field] = (str(prev) + "," + v) if prev else v
            continue
        m = _FIELD_RE.match(raw)
        if not m:                                    # `-----` separator / prose
            cur_field = None
            continue
        nm = m.group("name").strip().lower()
        val = m.group("val").strip()
        if nm == "rule name":
            if cur is not None:
                blocks.append(cur)
            cur = {"_line": lineno}
        elif cur is None:                            # orphan fields before a name
            cur = {"_line": lineno}
        if nm in _MULTI and cur.get(nm):
            cur[nm] = str(cur[nm]) + ("," + val if val else "")
        else:
            cur[nm] = val
        cur_field = nm
    if cur is not None:
        blocks.append(cur)
    return blocks


def _parse_side(raw_val: Optional[str], notes: List[str], name: str,
                field: str) -> Tuple[List[_IPNet], bool, bool]:
    """Parse a LocalIP/RemoteIP value into (concrete_nets, has_any, imprecise).

    ``Any`` / an absent field -> has_any. A CIDR / bare IP -> a concrete net; a
    ``A-B`` range -> the exact covering CIDRs. A keyword scope (LocalSubnet, DNS,
    ...) or an unparseable token is not a concrete rectangle: the WHOLE side is
    WIDENED to ANY + imprecise (a superset — never a subset), so it can never
    prove another rule dead or false-PASS a leak.
    """
    if raw_val is None:
        return [], True, False
    val = raw_val.strip()
    if val == "":
        return [], True, False
    concrete: List[_IPNet] = []
    has_any = False
    imprecise = False
    for part in val.split(","):
        p = part.strip()
        if not p:
            continue
        if p.lower() == "any":
            has_any = True
            continue
        if "-" in p:                                  # try an address range A-B
            a, _, b = p.partition("-")
            try:
                lo = ipaddress.ip_address(a.strip())
                hi = ipaddress.ip_address(b.strip())
                if lo.version == hi.version:
                    if int(lo) > int(hi):
                        lo, hi = hi, lo
                    concrete.extend(ipaddress.summarize_address_range(lo, hi))
                    continue
            except (ValueError, TypeError):
                pass                                  # not an IP range -> keyword
        try:
            if "/" in p:
                concrete.append(ipaddress.ip_network(p, strict=False))
            else:
                concrete.append(_host_net(p))
            continue
        except (ValueError, TypeError):
            pass
        imprecise = True                              # keyword scope / unparseable
        notes.append(f"WinFW {field} '{p}' in rule '{name}' is a keyword scope / "
                     f"unresolvable address — widened to ANY (imprecise; verify "
                     f"manually).")
    if imprecise:
        # The whole side widens to ANY: ANY subsumes any concrete members too.
        return [], True, True
    if len(concrete) > _MAX_EXPAND:
        notes.append(f"WinFW {field} in rule '{name}' expands to {len(concrete)} "
                     f"nets (> cap {_MAX_EXPAND}) — widened to ANY (imprecise).")
        return [], True, True
    return concrete, has_any, imprecise


def _parse_ports(raw_val: Optional[str], notes: List[str], name: str,
                 field: str) -> Tuple[List[PortRange], bool]:
    """Parse a LocalPort/RemotePort value into (ranges, imprecise).

    ``Any`` / absent -> ANY_PORTS. ``80,443`` -> the exact union of per-port
    ranges; ``5000-5100`` -> one range; a service name -> its IANA port. A
    dynamic/named port that does not resolve (``RPC``, ``RPC-EPMap``, ...) widens
    the ENTIRE dimension to ANY + imprecise (dynamic RPC is a wide, unknown range;
    keeping only the resolvable parts would be an unsound subset).
    """
    if raw_val is None:
        return [ANY_PORTS], False
    val = raw_val.strip()
    if val == "" or val.lower() == "any":
        return [ANY_PORTS], False
    ranges: List[PortRange] = []
    widen = False
    for part in val.split(","):
        p = part.strip()
        if not p:
            continue
        if p.lower() == "any":
            return [ANY_PORTS], False
        m = _PORT_RANGE_RE.match(p)
        if m:
            lo = max(PORT_MIN, min(PORT_MAX, int(m.group(1))))
            hi = max(PORT_MIN, min(PORT_MAX, int(m.group(2))))
            ranges.append(PortRange(min(lo, hi), max(lo, hi)))
            continue
        n = _port_num(p)
        if n >= 0:
            ranges.append(PortRange(n, n))
            continue
        widen = True
        notes.append(f"WinFW {field} '{p}' in rule '{name}' is a dynamic/named "
                     f"port (RPC/RPC-EPMap/IPHTTPS/Teredo/etc.) not resolvable to "
                     f"a numeric range — widened to ANY ports (imprecise; verify "
                     f"manually).")
    if widen or not ranges:
        return [ANY_PORTS], True
    return ranges, False


def _raw(acl: str, action: str, name: str, proto: str, s: _IPNet, d: _IPNet,
         sp: PortRange, dp: PortRange, ported: bool) -> str:
    parts = [f"{acl}:", action, f"'{name}'", "|", proto, str(s), "->", str(d)]
    if ported and not sp.is_any():
        parts.append(f"sport {sp}")
    if ported and not dp.is_any():
        parts.append(f"dport {dp}")
    return " ".join(parts)


def _block_to_aces(fields: Dict[str, object], notes: List[str]) -> List[ACE]:
    """Turn one parsed rule block into ACEs (all ``transit=False``, ``seq=0`` —
    the caller renumbers per direction after block-first ordering)."""
    name = str(fields.get("rule name", "")).strip() or "(unnamed)"
    line = int(fields.get("_line", 0) or 0)

    if str(fields.get("enabled") or "").strip().lower() == "no":
        notes.append(f"WinFW rule '{name}': disabled (Enabled: No) — skipped, not "
                     f"enforced on the device (exact).")
        return []

    direction = str(fields.get("direction") or "").strip().lower()
    if direction not in ("in", "out"):
        notes.append(f"WinFW rule '{name}': missing/unknown Direction "
                     f"({fields.get('direction')!r}) — skipped (no first-match "
                     f"context to place it in).")
        return []
    action_raw = str(fields.get("action") or "").strip().lower()
    if action_raw not in ("allow", "block"):
        notes.append(f"WinFW rule '{name}': missing/unknown Action "
                     f"({fields.get('action')!r}) — skipped.")
        return []

    acl = "Inbound" if direction == "in" else "Outbound"
    action = "permit" if action_raw == "allow" else "deny"

    proto = _norm_proto(str(fields.get("protocol") or ""))
    ported = proto in ("tcp", "udp")

    # L3/L4-orthogonal narrowing scopes we do not model -> imprecise (fail closed:
    # a narrowed deny must never prove isolation the device does not enforce).
    narrow_imprecise = False
    for f in ("program", "service", "interfacetype"):
        v = str(fields.get(f) or "").strip()
        if v and v.lower() != "any":
            narrow_imprecise = True
            notes.append(f"WinFW rule '{name}': {f} scope '{v}' not modeled "
                         f"(L3/L4 over-approximation) — marked imprecise, verify "
                         f"manually.")
    sec = str(fields.get("security") or "").strip()
    if sec and sec.lower() not in ("notrequired",):
        narrow_imprecise = True
        notes.append(f"WinFW rule '{name}': IPsec Security '{sec}' not modeled — "
                     f"marked imprecise, verify manually.")

    # Addresses: LocalIP/RemoteIP -> src/dst by direction (see module docstring).
    local_c, local_any, local_imp = _parse_side(
        _opt(fields, "localip"), notes, name, "LocalIP")
    remote_c, remote_any, remote_imp = _parse_side(
        _opt(fields, "remoteip"), notes, name, "RemoteIP")
    if direction == "in":                             # host = destination
        src_c, src_any, src_imp = remote_c, remote_any, remote_imp
        dst_c, dst_any, dst_imp = local_c, local_any, local_imp
    else:                                             # host = source
        src_c, src_any, src_imp = local_c, local_any, local_imp
        dst_c, dst_any, dst_imp = remote_c, remote_any, remote_imp

    # Ports: dst_port is the DESTINATION-side port (LocalPort inbound, RemotePort
    # outbound); src_port symmetric.
    if ported:
        local_ports, lp_imp = _parse_ports(
            _opt(fields, "localport"), notes, name, "LocalPort")
        remote_ports, rp_imp = _parse_ports(
            _opt(fields, "remoteport"), notes, name, "RemotePort")
        if direction == "in":
            dst_ports, dp_imp = local_ports, lp_imp
            src_ports, sp_imp = remote_ports, rp_imp
        else:
            dst_ports, dp_imp = remote_ports, rp_imp
            src_ports, sp_imp = local_ports, lp_imp
    else:
        src_ports = dst_ports = [ANY_PORTS]
        sp_imp = dp_imp = False

    icmp_type: Optional[str] = None
    if proto in ("icmp", "icmpv6"):
        tval = str(fields.get("type") or "").strip()
        if tval and tval.lower() != "any":
            icmp_type = _canon_icmp_type(tval.replace(":", "/"))

    base_imprecise = (narrow_imprecise or src_imp or dst_imp or sp_imp or dp_imp)

    # Address families the rule can match (a WinFW rule with Any addresses matches
    # BOTH v4 and v6, so emit an ACE per family — a sound superset).
    families = set()
    if proto == "icmpv6":
        families = {6}
    elif proto == "icmp":
        families = {4}
    else:
        for netw in src_c + dst_c:
            families.add(netw.version)
        if not families:
            families = {4, 6}

    def side_nets(concrete: List[_IPNet], has_any: bool, fam: int) -> List[_IPNet]:
        if has_any:                                   # ANY subsumes any concrete
            return [_ANY6 if fam == 6 else _ANY4]
        return [n for n in concrete if n.version == fam]

    combos: List[Tuple[_IPNet, _IPNet]] = []
    for fam in sorted(families):
        s_nets = side_nets(src_c, src_any, fam)
        d_nets = side_nets(dst_c, dst_any, fam)
        if not s_nets or not d_nets:                  # no packet in this family
            continue
        for s in s_nets:
            for d in d_nets:
                combos.append((s, d))
    if not combos:
        notes.append(f"WinFW rule '{name}': no matching src/dst address family "
                     f"combination — no ACE emitted (verify manually).")
        return []

    total = len(combos) * len(src_ports) * len(dst_ports)
    if total > _MAX_EXPAND:
        notes.append(f"WinFW rule '{name}': expansion {total} exceeds cap "
                     f"{_MAX_EXPAND} — widened to ANY src/dst/ports (imprecise).")
        out: List[ACE] = []
        for fam in sorted(families):
            net = _ANY6 if fam == 6 else _ANY4
            out.append(ACE(seq=0, action=action, proto=proto, src=net, dst=net,
                           icmp_type=icmp_type, imprecise=True,
                           raw=f"{acl}: {action} '{name}' (over-cap; widened)",
                           acl=acl, line=line, transit=False))
        return out

    out = []
    for (s, d) in combos:
        for sp in src_ports:
            for dp in dst_ports:
                out.append(ACE(
                    seq=0, action=action, proto=proto, src=s, dst=d,
                    src_port=sp, dst_port=dp, icmp_type=icmp_type,
                    stateful=False, imprecise=base_imprecise,
                    raw=_raw(acl, action, name, proto, s, d, sp, dp, ported),
                    acl=acl, line=line, transit=False))
    return out


def _opt(fields: Dict[str, object], key: str) -> Optional[str]:
    v = fields.get(key)
    return None if v is None else str(v)


def _default_aces(acl: str) -> List[ACE]:
    """The per-profile direction default as the trailing rule(s): inbound ->
    ``deny ip any any`` (blocked by default), outbound -> ``permit ip any any``
    (allowed by default). Emitted for both families (v4 + v6)."""
    act = "deny" if acl == "Inbound" else "permit"
    desc = ("per-profile default: inbound is blocked"
            if acl == "Inbound" else "per-profile default: outbound is allowed")
    out: List[ACE] = []
    for net in (_ANY4, _ANY6):
        out.append(ACE(seq=0, action=act, proto="ip", src=net, dst=net,
                       raw=f"{acl}: default policy — {desc}", acl=acl,
                       line=0, transit=False))
    return out


def parse_winfw(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse ``netsh advfirewall firewall show rule name=all`` output.

    Returns the same ``(List[ACE], notes)`` IR as the other frontends, so
    ``analyze`` / ``check_segmentation`` consume it unchanged. Rules are grouped
    into two first-match contexts (``acl`` = ``Inbound`` / ``Outbound``); within
    each, Block rules are ordered before Allow rules (block-precedence) and the
    direction default is appended as the trailing rule. See the module docstring.
    """
    notes: List[str] = []
    buckets: Dict[str, Dict[str, List[ACE]]] = {
        "Inbound": {"deny": [], "permit": []},
        "Outbound": {"deny": [], "permit": []},
    }
    for blk in _iter_blocks(text):
        try:
            aces = _block_to_aces(blk, notes)
        except Exception as exc:                       # never crash on bad input
            notes.append(f"WinFW rule '{blk.get('rule name', '?')}': parse error "
                         f"({exc!r}) — skipped (verify manually).")
            continue
        for a in aces:
            buckets[a.acl][a.action].append(a)

    entries: List[ACE] = []
    for acl in ("Inbound", "Outbound"):
        denies = buckets[acl]["deny"]
        permits = buckets[acl]["permit"]
        if not denies and not permits:
            continue
        # Block-first: every deny, then every permit, then the direction default.
        ordered = list(denies) + list(permits) + _default_aces(acl)
        seq = 0
        for a in ordered:
            seq += 1
            entries.append(dataclasses.replace(a, seq=seq))

    if entries:
        notes.append(
            "WinFW modeling: within each direction Block rules are ordered BEFORE "
            "Allow rules (WFAS block-precedence — a matching Block wins over any "
            "Allow), followed by the per-profile default (inbound=block -> trailing "
            "deny; outbound=allow -> trailing permit). Inbound/Outbound are HOST "
            "hooks (transit=False): excluded from the inter-zone segmentation "
            "witness search (they never carry forwarded traffic) but retained for "
            "hygiene analysis. The model is over-restrictive-only, hence sound.")
    else:
        notes.append("no WinFW (netsh advfirewall) firewall rules found.")
    return entries, notes
