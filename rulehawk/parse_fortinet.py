"""Parse Fortinet FortiGate (FortiOS) firewall policy config into RuleHawk `ACE`s.

Why FortiGate is a worthwhile frontend: it is one of the highest-unit-volume
firewalls in the enterprise/SMB market, and its `config firewall policy` block is
exactly the shape the downstream engine (`analyze.py`, `segcheck.py`,
`model.ACE`) already reasons about — a SINGLE, GLOBALLY ORDERED, first-match list
of permit/deny rules over an (proto, src-net, dst-net, src-port, dst-port) space.
FortiGate evaluates policies top-to-bottom in `edit <N>` order, first match wins,
with an IMPLICIT deny-all at the bottom. So this module only adds a new
*frontend* emitting the same `(List[ACE], notes)` IR; the whole existing analysis
is reused unchanged.

THE SOUNDNESS LINE (the RH-3 lesson, applied to FortiOS). RuleHawk models the
L3/L4 packet space only. Any construct that NARROWS a policy in a dimension we
don't model over-approximates the rule's space, so the widened rule is marked
`imprecise` and SURFACED as a parse note — never used to prove another rule dead
(`covers()` refuses it) and yielding an honest segmentation "indeterminate"
rather than a possibly-wrong verdict. Concretely:

  * A SPECIFIC `srcintf`/`dstintf` interface constrains which traffic hits the
    policy, exactly like a PAN-OS `from`/`to` zone — modeled as an
    over-approximation (full L3/L4 space kept) + `imprecise` (mirrors
    parse_panos, which does the same for a specific zone). `set srcintf "any"`
    (or an omitted intf) is EXACT. This is the reason RuleHawk's FortiGate
    segmentation checks are most decisive on any-interface policies, just as
    PAN-OS is most decisive on any-zone rules.
  * `set schedule` other than `always`, and identity narrowing (`set users` /
    `set groups` / `set fsso-groups`) genuinely restrict the match -> imprecise.
  * `set srcaddr-negate enable` / `set dstaddr-negate enable`: the rule matches
    the COMPLEMENT of the listed set, which is NOT one rectangle. We widen that
    dimension to ANY (ANY ⊇ complement restores the superset invariant) and set
    imprecise — NEVER keep the negated value (that would under-approximate and
    let segcheck FALSE-PASS a probe outside the listed set).
  * `set nat enable` and UTM profiles (av/webfilter/ips/application-list) do NOT
    change the L3/L4 match space (they inspect/rewrite already-forwarded
    traffic) — surfaced as a note only, never imprecise.

ADDRESS / SERVICE / GROUP resolution (the objgroup/Junos union pattern):
  * `config firewall address` objects reduce to exact CIDRs: `set subnet A.B.C.D
    MASK` (netmask form) or `.../len`; `set type iprange` + start/end-ip
    summarize to the EXACT covering CIDR set; IPv6 `set subnet <v6>/len` /
    `set ip6 ...`. The built-in object `all` = 0.0.0.0/0. `set type fqdn` /
    `geography` / `wildcard` / dynamic objects have no fixed L3 space and are
    UNRESOLVABLE.
  * `config firewall addrgrp` groups union their members (nested groups allowed).
  * `config firewall service custom`: tcp/udp/sctp-portrange (`dst[:src]`, a
    space list expands to the exact union), `protocol-number N`, `protocol
    ICMP`/`icmptype N`. `ALL` = any proto/port; `ALL_TCP`/`ALL_UDP`/`ALL_ICMP` =
    that proto, any port. Common predefined names (HTTP=80, HTTPS=443, ...)
    resolve to their exact (proto, port). `config firewall service group` unions.
  * SOUNDNESS: an UNRESOLVABLE name, an undefined reference, a cycle, or an empty
    group WIDENS that whole dimension (src / dst / service) to ANY + imprecise +
    a note — NEVER a subset. So resolution can only turn an INDETERMINATE into a
    precise verdict, never manufacture a false PASS.

CONTEXT / DEFAULT-DENY: every FortiGate policy lives in ONE global ordered
first-match list, so all ACEs share `acl="firewall-policy"`. A trailing
`deny ip any any` (the FortiGate implicit deny-all) is appended so segcheck can
never FALSE-PASS a leak by running off the end of the ruleset. `set status
disable` disables a policy on the device (empty match space) — skipped entirely
(exact, like Cisco `inactive`).

Robustness: malformed / truncated blocks, unbalanced edit/next/end, undefined
references, and empty policies all DEGRADE with a note and never crash — the
scan and each policy expansion are wrapped fail-closed.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet
from .parse import _port_num  # reuse the Cisco/IANA service-name -> port map

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")

_ACL = "firewall-policy"   # every FortiGate policy is one global first-match list

# IP protocol numbers FortiGate uses in `set protocol-number N` / a custom
# service `set protocol IP`. Folded to the same names the other frontends emit so
# a numeric proto matches a named-proto assertion.
_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
              "51": "ah", "58": "icmpv6", "89": "ospf", "132": "sctp",
              "4": "ipip", "41": "ipv6"}

# Address object `set type` values that have NO fixed L3 space -> unresolvable
# (the referencing dimension widens to ANY + imprecise).
_UNRESOLVABLE_ADDR_TYPES = frozenset({
    "fqdn", "wildcard-fqdn", "geography", "geographic", "dynamic",
    "mac", "wildcard", "interface-subnet", "device", "mac-address"})

# Well-known FortiGate predefined services -> exact (proto, port) list. Only
# consulted for a name that is neither a custom service nor a service group.
# Anything not here is UNRESOLVABLE (widen to ANY + imprecise) — never guessed.
_PREDEFINED_PORTS: Dict[str, List[Tuple[str, int]]] = {
    "HTTP": [("tcp", 80)], "HTTPS": [("tcp", 443)],
    "SSH": [("tcp", 22)], "TELNET": [("tcp", 23)],
    "FTP": [("tcp", 21)], "FTP_GET": [("tcp", 21)], "FTP_PUT": [("tcp", 21)],
    "SMTP": [("tcp", 25)], "SMTPS": [("tcp", 465)],
    "POP3": [("tcp", 110)], "POP3S": [("tcp", 995)],
    "IMAP": [("tcp", 143)], "IMAPS": [("tcp", 993)],
    "DNS": [("tcp", 53), ("udp", 53)],
    "NTP": [("udp", 123)],
    "SNMP": [("udp", 161), ("udp", 162)],
    "DHCP": [("udp", 67), ("udp", 68)],
    "TFTP": [("udp", 69)],
    "SMB": [("tcp", 445)], "SAMBA": [("tcp", 139)],
    "RDP": [("tcp", 3389)],
    "LDAP": [("tcp", 389)], "LDAPS": [("tcp", 636)],
    "SYSLOG": [("udp", 514)],
    "MYSQL": [("tcp", 3306)], "POSTGRES": [("tcp", 5432)],
    "MS-SQL": [("tcp", 1433)],
    "REDIS": [("tcp", 6379)], "MONGODB": [("tcp", 27017)],
    "KERBEROS": [("tcp", 88), ("udp", 88)],
    "WINS": [("tcp", 1512), ("udp", 1512)],
    "RADIUS": [("udp", 1812), ("udp", 1813)],
    "SIP": [("tcp", 5060), ("udp", 5060)],
    "VNC": [("tcp", 5900)],
}
# Predefined ICMP-based services -> (proto, icmp_type).
_PREDEFINED_ICMP: Dict[str, Tuple[str, Optional[str]]] = {
    "PING": ("icmp", "echo"), "ALL_ICMP": ("icmp", None),
    "PING6": ("icmpv6", "echo"), "ALL_ICMP6": ("icmpv6", None),
    "TRACEROUTE": ("icmp", None),
}

# A resolved service combination: (proto, src_port, dst_port, icmp_type).
_Combo = Tuple[str, PortRange, PortRange, Optional[str]]
_ANY_SVC: _Combo = ("ip", ANY_PORTS, ANY_PORTS, None)

_MAX_EXPAND = 256   # cross-product cap; beyond it widen to any/any + imprecise


def detect(text: str) -> bool:
    """Heuristic: does `text` look like a FortiOS `show`/config dump?

    Fires on a line-anchored `config firewall policy` (the decisive marker), or on
    the combination of FortiOS address-table markers (`config firewall address` +
    a quoted `edit "..."` + `set subnet`). Cisco ACLs, Junos filters, PAN-OS
    set-policies, iptables rules and JSON have none of these tokens, so they are
    never misrouted here.
    """
    if re.search(r"(?im)^\s*config\s+firewall\s+policy6?\b", text):
        return True
    if (re.search(r"(?im)^\s*config\s+firewall\s+address6?\b", text)
            and re.search(r'(?im)^\s*edit\s+"', text)
            and re.search(r"(?im)^\s*set\s+subnet\b", text)):
        return True
    return False


def _tokenize(line: str) -> List[str]:
    """Split a FortiOS statement, honoring double-quoted values. shlex handles the
    quoting; an unbalanced quote falls back to a plain split (never crash)."""
    import shlex
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        return line.split()


def _kind_of(rest: List[str]) -> str:
    r = [t.lower() for t in rest]
    if r[:2] in (["firewall", "policy"], ["firewall", "policy6"]):
        return "policy"
    if r[:2] in (["firewall", "address"], ["firewall", "address6"]):
        return "address"
    if r[:2] in (["firewall", "addrgrp"], ["firewall", "addrgrp6"]):
        return "addrgrp"
    if r[:3] == ["firewall", "service", "custom"]:
        return "svc_custom"
    if r[:3] == ["firewall", "service", "group"]:
        return "svc_group"
    return "other"


def _first(vals: Optional[List[str]]) -> Optional[str]:
    return vals[0] if vals else None


def _net_from_subnet(vals: List[str]) -> Optional[List[_IPNet]]:
    """`set subnet` operand -> [net]. Handles `A.B.C.D MASK` (netmask form),
    `A.B.C.D/len`, a bare address (== /32 or /128), and IPv6. Any unparsable form
    returns None (the caller fails closed / widens)."""
    try:
        if not vals:
            return None
        if len(vals) >= 2 and "/" not in vals[0]:
            # addr + netmask (ipaddress accepts a dotted netmask after '/').
            return [ipaddress.ip_network(f"{vals[0]}/{vals[1]}", strict=False)]
        tok = vals[0]
        if "/" not in tok:
            tok = tok + ("/128" if ":" in tok else "/32")
        return [ipaddress.ip_network(tok, strict=False)]
    except (ValueError, IndexError):
        return None


def _resolve_addr_obj(obj: Dict[str, List[str]]) -> Optional[List[_IPNet]]:
    """Resolve one `config firewall address` edit to exact nets, or None if it has
    no fixed L3 space (fqdn/geography/wildcard/dynamic/unparsable)."""
    typ = (_first(obj.get("type")) or "").lower()
    if typ in _UNRESOLVABLE_ADDR_TYPES:
        return None
    if typ == "iprange" or ("start-ip" in obj and "end-ip" in obj):
        s, e = _first(obj.get("start-ip")), _first(obj.get("end-ip"))
        if not s or not e:
            return None
        try:
            lo, hi = ipaddress.ip_address(s), ipaddress.ip_address(e)
            if lo.version != hi.version or int(lo) > int(hi):
                return None
            return list(ipaddress.summarize_address_range(lo, hi))
        except (ValueError, TypeError):
            return None
    if "subnet" in obj:
        return _net_from_subnet(obj["subnet"])
    if "ip6" in obj:
        try:
            return [ipaddress.ip_network(_first(obj["ip6"]), strict=False)]
        except (ValueError, TypeError):
            return None
    # fqdn / country / wildcard set WITHOUT an explicit `set type` -> no L3 space.
    if any(k in obj for k in ("fqdn", "wildcard-fqdn", "country", "wildcard",
                              "sdn", "fsso-group")):
        return None
    return None


def parse_fortinet(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse FortiOS firewall config in `text`; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation` consume
    the result unchanged. Every policy is one global ordered first-match context
    (`acl="firewall-policy"`); a trailing implicit `deny ip any any` is appended.
    """
    notes: List[str] = []
    addresses: Dict[str, Dict[str, List[str]]] = {}
    addrgrps: Dict[str, Dict[str, List[str]]] = {}
    svc_custom: Dict[str, Dict[str, List[str]]] = {}
    svc_groups: Dict[str, Dict[str, List[str]]] = {}
    policies: List[Tuple[str, Dict[str, List[str]], int]] = []

    # ── Scan the config/edit/next/end structure into the collections above. A
    # stack of frames tolerates nested `config` blocks and unbalanced markers.
    frames: List[dict] = []

    def commit(fr: dict) -> None:
        name, edit, kind = fr.get("name"), fr.get("edit"), fr["kind"]
        if name is None or edit is None:
            return
        if kind == "address":
            addresses[name] = edit
        elif kind == "addrgrp":
            addrgrps[name] = edit
        elif kind == "svc_custom":
            svc_custom[name] = edit
        elif kind == "svc_group":
            svc_groups[name] = edit
        elif kind == "policy":
            policies.append((name, edit, fr.get("line", 0)))

    try:
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            toks = _tokenize(line)
            if not toks:
                continue
            head = toks[0].lower()
            if head == "config":
                frames.append({"kind": _kind_of(toks[1:]), "name": None,
                               "edit": None, "line": lineno})
                continue
            if head == "end":
                if frames:
                    frames.pop()
                continue
            if not frames:
                continue
            fr = frames[-1]
            if head == "edit":
                fr["name"] = toks[1] if len(toks) > 1 else ""
                fr["edit"] = {}
                fr["line"] = lineno
                continue
            if head == "next":
                commit(fr)
                fr["name"], fr["edit"] = None, None
                continue
            if head in ("set", "unset") and fr.get("edit") is not None:
                if len(toks) >= 2:
                    fr["edit"][toks[1].lower()] = toks[2:] if head == "set" else []
                continue
    except Exception as exc:                 # never crash on a malformed dump
        notes.append(f"fortinet: error scanning config ({exc!r}) — parsed what "
                     f"was readable, fail-closed on the rest")

    # ── Resolvers (closures over the collected definitions). ------------------
    def resolve_name(name: str, seen: frozenset) -> Optional[List[_IPNet]]:
        """A src/dst address name -> exact nets, or None (unresolvable -> widen)."""
        if name == "all":
            return [_ANY4]
        if name in addresses:
            return _resolve_addr_obj(addresses[name])
        if name in addrgrps:
            key = ("grp", name)
            if key in seen:
                return None                  # cycle -> fail closed
            members = addrgrps[name].get("member") or []
            if not members:
                return None                  # empty group -> fail closed
            out: List[_IPNet] = []
            for m in members:
                sub = resolve_name(m, seen | {key})
                if sub is None:
                    return None              # any bad member widens the whole dim
                out.extend(sub)
            return out or None
        return None                          # undefined -> fail closed

    def resolve_addr_list(names: List[str]) -> Tuple[List[_IPNet], bool]:
        """Resolve a policy srcaddr/dstaddr list. Returns (nets, exact). On any
        unresolvable member the WHOLE dimension widens to ANY (superset)."""
        if not names:
            return [_ANY4], False
        out: List[_IPNet] = []
        for name in names:
            nets = resolve_name(name, frozenset())
            if nets is None:
                return [_ANY4], False
            out.extend(nets)
        return (out, True) if out else ([_ANY4], False)

    def parse_range(spec: str) -> Optional[PortRange]:
        spec = spec.strip()
        if not spec:
            return None
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            ln, hn = _port_num(lo.strip()), _port_num(hi.strip())
            if ln < 0 or hn < 0:
                return None
            return PortRange(min(ln, hn), max(ln, hn))
        p = _port_num(spec)
        return PortRange(p, p) if p >= 0 else None

    def parse_portrange(proto: str, specs: List[str]) -> Optional[List[_Combo]]:
        """A tcp/udp/sctp-portrange value list -> combos. Each spec is
        `dst[:src]`, each side `lo[-hi]`. Any unparsable spec -> None (widen)."""
        combos: List[_Combo] = []
        for spec in specs:
            dpart, _, spart = spec.partition(":")
            dpr = parse_range(dpart)
            if dpr is None:
                return None
            spr = ANY_PORTS
            if spart:
                got = parse_range(spart)
                if got is None:
                    return None
                spr = got
            combos.append((proto, spr, dpr, None))
        return combos or None

    def resolve_service(name: str, seen: frozenset) -> Optional[List[_Combo]]:
        """A service name -> combos, or None if unresolvable (widen + imprecise)."""
        up = name.upper()
        if up == "ALL":
            return [_ANY_SVC]
        if up in ("ALL_TCP", "ALL_UDP", "ALL_SCTP"):
            return [(up.split("_")[1].lower(), ANY_PORTS, ANY_PORTS, None)]
        if name in svc_custom:
            return _resolve_custom_svc(svc_custom[name])
        if name in svc_groups:
            key = ("svcgrp", name)
            if key in seen:
                return None
            members = svc_groups[name].get("member") or []
            if not members:
                return None
            out: List[_Combo] = []
            for m in members:
                sub = resolve_service(m, seen | {key})
                if sub is None:
                    return None
                out.extend(sub)
            return out or None
        if up in _PREDEFINED_ICMP:
            proto, itype = _PREDEFINED_ICMP[up]
            return [(proto, ANY_PORTS, ANY_PORTS, itype)]
        if up in _PREDEFINED_PORTS:
            return [(proto, ANY_PORTS, PortRange(port, port), None)
                    for proto, port in _PREDEFINED_PORTS[up]]
        return None                          # unknown predefined -> fail closed

    def _resolve_custom_svc(obj: Dict[str, List[str]]) -> Optional[List[_Combo]]:
        combos: List[_Combo] = []
        for key, proto in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"),
                           ("sctp-portrange", "sctp")):
            if key in obj:
                got = parse_portrange(proto, obj[key])
                if got is None:
                    return None
                combos.extend(got)
        protocol = (_first(obj.get("protocol")) or "").upper()
        if protocol in ("ICMP", "ICMP6"):
            proto = "icmp" if protocol == "ICMP" else "icmpv6"
            itype = _first(obj.get("icmptype"))
            combos.append((proto, ANY_PORTS, ANY_PORTS, itype))
        elif protocol == "IP" or ("protocol-number" in obj and not combos):
            num = _first(obj.get("protocol-number"))
            proto = _PROTO_NUM.get(str(num)) if num is not None else None
            if proto is None:
                return None                  # unknown IP proto number -> widen
            combos.append((proto, ANY_PORTS, ANY_PORTS, None))
        return combos or None

    def resolve_service_list(names: List[str]) -> Tuple[List[_Combo], bool]:
        if not names:
            return [_ANY_SVC], True          # no service set == FortiGate "ALL"
        combos: List[_Combo] = []
        for name in names:
            got = resolve_service(name, frozenset())
            if got is None:
                return [_ANY_SVC], False     # widen service dim + imprecise
            combos.extend(got)
        return (combos, True) if combos else ([_ANY_SVC], False)

    # ── Expand each enabled policy (in edit order) into ACEs. -----------------
    entries: List[ACE] = []
    seq = 0

    def enable(vals: Optional[List[str]]) -> bool:
        return (_first(vals) or "").lower() != "disable"

    def flag_on(vals: Optional[List[str]]) -> bool:
        return (_first(vals) or "").lower() == "enable"

    for pname, pol, pline in policies:
        try:
            if not enable(pol.get("status")):
                notes.append(f"fortinet policy {pname} is disabled "
                             f"(set status disable) — skipped (not enforced)")
                continue

            action = "permit" if (_first(pol.get("action")) or "").lower() == \
                "accept" else "deny"
            imprecise = False

            # Interfaces: a SPECIFIC srcintf/dstintf narrows the match (like a
            # PAN-OS from/to zone) — over-approximate + imprecise. "any" is exact.
            for ik in ("srcintf", "dstintf"):
                iv = pol.get(ik) or []
                if any(v.lower() != "any" for v in iv):
                    imprecise = True
                    notes.append(f"fortinet policy {pname}: specific {ik} "
                                 f"{[v for v in iv if v.lower() != 'any']} not "
                                 f"modeled (L3/L4 over-approximation — marked "
                                 f"imprecise, used conservatively)")

            sched = (_first(pol.get("schedule")) or "always").lower()
            if sched != "always":
                imprecise = True
                notes.append(f"fortinet policy {pname}: schedule '{sched}' "
                             f"restricts WHEN the rule matches — not modeled "
                             f"(marked imprecise, verify manually)")

            for idk in ("users", "groups", "fsso-groups"):
                if pol.get(idk):
                    imprecise = True
                    notes.append(f"fortinet policy {pname}: identity match "
                                 f"`set {idk}` narrows the match — not modeled "
                                 f"(marked imprecise, verify manually)")
                    break

            if flag_on(pol.get("nat")):
                notes.append(f"fortinet policy {pname}: `set nat enable` — source "
                             f"NAT is not modeled (filter-space only; the L3/L4 "
                             f"match space is unchanged)")

            srcs, src_ok = resolve_addr_list(pol.get("srcaddr") or [])
            dsts, dst_ok = resolve_addr_list(pol.get("dstaddr") or [])
            combos, svc_ok = resolve_service_list(pol.get("service") or [])
            if not src_ok:
                imprecise = True
                notes.append(f"fortinet policy {pname}: srcaddr "
                             f"{pol.get('srcaddr')} has an unresolvable/undefined "
                             f"member — src widened to ANY (marked imprecise)")
            if not dst_ok:
                imprecise = True
                notes.append(f"fortinet policy {pname}: dstaddr "
                             f"{pol.get('dstaddr')} has an unresolvable/undefined "
                             f"member — dst widened to ANY (marked imprecise)")
            if not svc_ok:
                imprecise = True
                notes.append(f"fortinet policy {pname}: service "
                             f"{pol.get('service')} unresolvable — widened to ANY "
                             f"proto/port (marked imprecise)")

            # Negated addresses match the COMPLEMENT — not one rectangle. Widen
            # that dimension to ANY (superset) + imprecise; never keep the value.
            if flag_on(pol.get("srcaddr-negate")):
                srcs, imprecise = [_ANY4], True
                notes.append(f"fortinet policy {pname}: srcaddr-negate enable — "
                             f"matches the complement of the listed set; widened "
                             f"to ANY (marked imprecise)")
            if flag_on(pol.get("dstaddr-negate")):
                dsts, imprecise = [_ANY4], True
                notes.append(f"fortinet policy {pname}: dstaddr-negate enable — "
                             f"matches the complement of the listed set; widened "
                             f"to ANY (marked imprecise)")

            if len(srcs) * len(dsts) * len(combos) > _MAX_EXPAND:
                notes.append(f"fortinet policy {pname} expands to >"
                             f"{_MAX_EXPAND} ACEs; widened to a single any/any "
                             f"ACE (superset) and marked imprecise — verify")
                srcs, dsts, combos, imprecise = [_ANY4], [_ANY4], [_ANY_SVC], True

            for s in srcs:
                for d in dsts:
                    for proto, spr, dpr, itype in combos:
                        seq += 1
                        entries.append(ACE(
                            seq=seq, action=action, proto=proto, src=s, dst=d,
                            src_port=spr, dst_port=dpr, icmp_type=itype,
                            stateful=False, imprecise=imprecise,
                            raw=(f"policy {pname}: {action} {proto} {s} -> {d}"
                                 + (f" dport {dpr}" if not dpr.is_any() else "")
                                 + (f" type {itype}" if itype else "")),
                            acl=_ACL, line=pline, transit=True))
        except Exception as exc:
            # A policy we cannot expand fails CLOSED: one opaque any/any imprecise
            # ACE preserving its action, so it becomes segmentation-INDETERMINATE
            # for any flow it touches (never a silent hole / false PASS).
            seq += 1
            act = "permit" if (_first(pol.get("action")) or "").lower() == \
                "accept" else "deny"
            entries.append(ACE(seq=seq, action=act, proto="ip", src=_ANY4,
                               dst=_ANY4, imprecise=True,
                               raw=f"policy {pname}: unparsed ({exc!r}) — "
                                   f"fail-closed", acl=_ACL, line=pline,
                               transit=True))
            notes.append(f"fortinet policy {pname}: expansion error ({exc!r}) — "
                         f"kept as an opaque imprecise ACE (fail-closed)")

    # ── Trailing implicit deny-all (the FortiGate default). Without it segcheck
    # could FALSE-PASS a leak that simply runs off the end of the policy list.
    seq += 1
    entries.append(ACE(seq=seq, action="deny", proto="ip", src=_ANY4, dst=_ANY4,
                       raw="firewall-policy: implicit default deny-all",
                       acl=_ACL, line=0, transit=True))

    if not policies:
        notes.append("fortinet: no `config firewall policy` entries found — only "
                     "the implicit default deny-all is modeled")
    notes.append(f"fortinet: {len(policies)} policy edit(s) modeled as one global "
                 f"first-match context; trailing implicit deny-all appended")
    return entries, notes
