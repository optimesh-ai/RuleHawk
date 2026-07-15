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
  * `set srcaddr-negate enable` / `set dstaddr-negate enable` / `set
    service-negate enable`: the rule matches the COMPLEMENT of the listed set,
    which is NOT one rectangle. We widen that dimension to ANY (ANY ⊇ complement
    restores the superset invariant) and set imprecise — NEVER keep the negated
    value (that would under-approximate and let segcheck FALSE-PASS a probe
    outside the listed set).
  * `set action` maps to permit/deny by SEMANTICS, not a two-way accept/else
    split: `accept` -> permit; `deny`/`drop` (and an omitted action, whose
    FortiGate default is deny) -> deny; every FORWARDING action
    (`ipsec`/`ssl-vpn`/`redirect`/`tunnel`, and any unrecognized action) ->
    permit + imprecise, because those actions FORWARD matched traffic (into a
    tunnel / to a portal) rather than drop it. Modeling a forward as a `deny`
    would both FALSE-PASS a must_not_reach (the flow really is forwarded) and
    kill a later live permit as "dead"; the safe over-approximation is a permit
    whose exact post-tunnel path/NAT we cannot model -> imprecise.
  * `set nat enable` and UTM profiles (av/webfilter/ips/application-list) do NOT
    change the L3/L4 match space (they inspect/rewrite already-forwarded
    traffic) — surfaced as a note only, never imprecise.

IPv4 AND IPv6 (the family-threading lesson): FortiOS filters both families. A
`config firewall policy6` block is v6-only; a unified `config firewall policy`
block can carry v4 (`srcaddr`/`dstaddr`) AND v6 (`srcaddr6`/`dstaddr6`) address
refs at once. The built-in `all` object resolves to `0.0.0.0/0` in a v4 context
and `::/0` in a v6 context, so the parser threads the policy FAMILY through
resolution, reads the v6 address fields, and appends a v6 implicit deny-all
alongside the v4 one. Modeling a v6 policy as v4-only would leave every v6 flow
untouched by any ACE -> a segmentation FALSE-PASS (the flow runs off the end of
a v4-only ruleset and reads as isolated).

ADDRESS / SERVICE / GROUP resolution (the objgroup/Junos union pattern):
  * `config firewall address` objects reduce to exact CIDRs: `set subnet A.B.C.D
    MASK` (netmask form) or `.../len`; `set type iprange` + start/end-ip
    summarize to the EXACT covering CIDR set; IPv6 `set subnet <v6>/len` /
    `set ip6 ...`. The built-in object `all` = 0.0.0.0/0 (v4) or ::/0 (v6).
    `set type fqdn` / `geography` / `wildcard` / dynamic objects have no fixed L3
    space and are UNRESOLVABLE.
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

CONTEXT / VDOMs / DEFAULT-DENY: a plain (non-VDOM) FortiGate config is ONE global
ordered first-match list, so its ACEs share `acl="firewall-policy"`. Under
`config vdom` each VDOM is an INDEPENDENT routing domain with its OWN first-match
policy list and its OWN (same-named!) address/service objects — merging them
would let a deny in one VDOM subtract before a permit in another (false-PASS) and
declare the other VDOM's live permit dead. So VDOM policies are scoped to
`acl="firewall-policy:<vdom>"`, the object tables are keyed per VDOM, and a
trailing implicit `deny ip any any` (v4 AND v6) is appended PER context so
segcheck can never FALSE-PASS a leak by running off the end. `set status
disable` disables a policy on the device (empty match space) — skipped entirely
(exact, like Cisco `inactive`).

Robustness: malformed / truncated blocks, unbalanced edit/next/end, undefined
references, and empty policies all DEGRADE with a note and never crash — the
scan and each policy expansion are wrapped fail-closed. An `edit` left open by a
missing `next` is committed implicitly (on the next `edit`, on `end`, and at EOF)
so a pending rule is never silently dropped — a dropped PERMIT masked by a
following deny would be a segmentation FALSE-PASS.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet
from .parse import _port_num  # reuse the Cisco/IANA service-name -> port map

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")

_ACL = "firewall-policy"   # base name; VDOM policies use "firewall-policy:<vdom>"

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
    if r[:2] == ["firewall", "policy"]:
        return "policy"
    if r[:2] == ["firewall", "policy6"]:
        return "policy6"          # v6-only policy table (family threaded through)
    if r[:2] in (["firewall", "address"], ["firewall", "address6"]):
        return "address"
    if r[:2] in (["firewall", "addrgrp"], ["firewall", "addrgrp6"]):
        return "addrgrp"
    if r[:3] == ["firewall", "service", "custom"]:
        return "svc_custom"
    if r[:3] == ["firewall", "service", "group"]:
        return "svc_group"
    if r[:1] == ["vdom"]:
        return "vdom"             # `config vdom` — an independent routing domain
    return "other"


def _action_of(raw: Optional[str]) -> Tuple[str, bool]:
    """Map a `set action` value to (rulehawk-action, is_forwarding).

    accept -> ("permit", False); deny/drop or an OMITTED action (FortiGate's
    default is deny) -> ("deny", False). Every FORWARDING action
    (ipsec/ssl-vpn/redirect/tunnel) and any UNRECOGNIZED action -> ("permit",
    True): those FORWARD matched traffic, so the safe over-approximation is a
    permit whose exact forwarded path we can't model (caller sets imprecise).
    Choosing permit (never deny) for the unknown case guarantees we never falsely
    prove isolation and never kill a live rule as dead."""
    a = (raw or "").lower()
    if a == "accept":
        return "permit", False
    if a in ("deny", "drop", ""):
        return "deny", False
    return "permit", True


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


# Object-table key: (vdom, name). vdom is None for a plain (non-VDOM) config, so
# same-named objects in different VDOMs never collide in the flat dicts.
_ObjKey = Tuple[Optional[str], str]


def parse_fortinet(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse FortiOS firewall config in `text`; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation` consume
    the result unchanged. Each VDOM is one ordered first-match context
    (`acl="firewall-policy:<vdom>"`, or `"firewall-policy"` with no VDOM); a
    trailing implicit `deny ip any any` (v4 and v6) is appended per context.
    """
    notes: List[str] = []
    addresses: Dict[_ObjKey, Dict[str, List[str]]] = {}
    addrgrps: Dict[_ObjKey, Dict[str, List[str]]] = {}
    svc_custom: Dict[_ObjKey, Dict[str, List[str]]] = {}
    svc_groups: Dict[_ObjKey, Dict[str, List[str]]] = {}
    # policy tuple: (name, edit, line, vdom, block_kind) where block_kind is
    # "policy" (v4/unified) or "policy6" (v6-only).
    policies: List[Tuple[str, Dict[str, List[str]], int, Optional[str], str]] = []

    # ── Scan the config/edit/next/end structure into the collections above. A
    # stack of frames tolerates nested `config` blocks and unbalanced markers.
    frames: List[dict] = []

    def _current_vdom() -> Optional[str]:
        """The innermost enclosing `config vdom` edit name (None if not in one)."""
        v: Optional[str] = None
        for f in frames:
            if f["kind"] == "vdom" and f.get("name"):
                v = f["name"]
        return v

    def commit(fr: dict) -> bool:
        """Store a completed edit into its per-VDOM table. Returns True iff it
        stored something (a `vdom`/`other`/empty frame stores nothing)."""
        name, edit, kind = fr.get("name"), fr.get("edit"), fr["kind"]
        if name is None or edit is None:
            return False
        vdom = _current_vdom()
        if kind == "address":
            addresses[(vdom, name)] = edit
        elif kind == "addrgrp":
            addrgrps[(vdom, name)] = edit
        elif kind == "svc_custom":
            svc_custom[(vdom, name)] = edit
        elif kind == "svc_group":
            svc_groups[(vdom, name)] = edit
        elif kind in ("policy", "policy6"):
            policies.append((name, edit, fr.get("line", 0), vdom, kind))
        else:
            return False
        return True

    def _pending(fr: dict) -> bool:
        return fr.get("edit") is not None and fr.get("name") is not None

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
                    top = frames[-1]
                    # `end` while an edit is still open (no closing `next`) must
                    # not drop that edit — commit it first.
                    if _pending(top) and commit(top):
                        notes.append(f"fortinet: `config {top['kind']}` ended "
                                     f"with `edit {top['name']}` still open (no "
                                     f"`next`) — committed implicitly (edit/next "
                                     f"imbalance repaired)")
                    frames.pop()
                continue
            if not frames:
                continue
            fr = frames[-1]
            if head == "edit":
                # A new `edit` while the previous one is still open (missing
                # `next`) implicitly closes it — commit so no rule is dropped.
                if _pending(fr) and commit(fr):
                    notes.append(f"fortinet: `edit {fr['name']}` in `config "
                                 f"{fr['kind']}` was not closed by `next` before "
                                 f"the next edit — committed implicitly "
                                 f"(edit/next imbalance repaired)")
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
        # EOF with edits still open (truncated dump / missing `next`+`end`):
        # commit whatever is pending so a trailing rule is never lost.
        for fr in frames:
            if _pending(fr) and commit(fr):
                notes.append(f"fortinet: `config {fr['kind']}` reached EOF with "
                             f"`edit {fr['name']}` still open — committed "
                             f"implicitly (edit/next imbalance repaired)")
    except Exception as exc:                 # never crash on a malformed dump
        notes.append(f"fortinet: error scanning config ({exc!r}) — parsed what "
                     f"was readable, fail-closed on the rest")

    def _any_of(family: int) -> _IPNet:
        return _ANY6 if family == 6 else _ANY4

    # ── Resolvers (closures over the collected definitions). ------------------
    def resolve_name(name: str, seen: frozenset, vdom: Optional[str],
                     family: int) -> Optional[List[_IPNet]]:
        """A src/dst address name -> exact nets, or None (unresolvable -> widen).
        `family` (4/6) resolves the built-in `all` to the right wildcard; object
        lookups are scoped to `vdom`."""
        if name == "all":
            return [_any_of(family)]
        if (vdom, name) in addresses:
            return _resolve_addr_obj(addresses[(vdom, name)])
        if (vdom, name) in addrgrps:
            key = ("grp", vdom, name)
            if key in seen:
                return None                  # cycle -> fail closed
            members = addrgrps[(vdom, name)].get("member") or []
            if not members:
                return None                  # empty group -> fail closed
            out: List[_IPNet] = []
            for m in members:
                sub = resolve_name(m, seen | {key}, vdom, family)
                if sub is None:
                    return None              # any bad member widens the whole dim
                out.extend(sub)
            return out or None
        return None                          # undefined -> fail closed

    def resolve_addr_list(names: List[str], vdom: Optional[str],
                          family: int) -> Tuple[List[_IPNet], bool]:
        """Resolve a policy srcaddr/dstaddr list. Returns (nets, exact). On any
        unresolvable member the WHOLE dimension widens to ANY (superset)."""
        any_net = _any_of(family)
        if not names:
            return [any_net], False
        out: List[_IPNet] = []
        for name in names:
            nets = resolve_name(name, frozenset(), vdom, family)
            if nets is None:
                return [any_net], False
            out.extend(nets)
        return (out, True) if out else ([any_net], False)

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

    def resolve_service(name: str, seen: frozenset,
                        vdom: Optional[str]) -> Optional[List[_Combo]]:
        """A service name -> combos, or None if unresolvable (widen + imprecise).
        Custom services and service groups are scoped to `vdom`."""
        up = name.upper()
        if up == "ALL":
            return [_ANY_SVC]
        if up in ("ALL_TCP", "ALL_UDP", "ALL_SCTP"):
            return [(up.split("_")[1].lower(), ANY_PORTS, ANY_PORTS, None)]
        if (vdom, name) in svc_custom:
            return _resolve_custom_svc(svc_custom[(vdom, name)])
        if (vdom, name) in svc_groups:
            key = ("svcgrp", vdom, name)
            if key in seen:
                return None
            members = svc_groups[(vdom, name)].get("member") or []
            if not members:
                return None
            out: List[_Combo] = []
            for m in members:
                sub = resolve_service(m, seen | {key}, vdom)
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

    def resolve_service_list(names: List[str],
                             vdom: Optional[str]) -> Tuple[List[_Combo], bool]:
        if not names:
            return [_ANY_SVC], True          # no service set == FortiGate "ALL"
        combos: List[_Combo] = []
        for name in names:
            got = resolve_service(name, frozenset(), vdom)
            if got is None:
                return [_ANY_SVC], False     # widen service dim + imprecise
            combos.extend(got)
        return (combos, True) if combos else ([_ANY_SVC], False)

    # ── Expand each enabled policy (in edit order) into ACEs. -----------------
    entries: List[ACE] = []
    seq = 0
    contexts: set = set()   # distinct acl (first-match) contexts seen

    def enable(vals: Optional[List[str]]) -> bool:
        return (_first(vals) or "").lower() != "disable"

    def flag_on(vals: Optional[List[str]]) -> bool:
        return (_first(vals) or "").lower() == "enable"

    for pname, pol, pline, pvdom, block in policies:
        acl = _ACL if pvdom is None else f"{_ACL}:{pvdom}"
        contexts.add(acl)
        # Which address families this policy emits. `policy6` is v6-only; a
        # unified `policy` carries v4 (srcaddr/dstaddr) and, when present, v6
        # (srcaddr6/dstaddr6) — emit an ACE set for each.
        if block == "policy6":
            fams: List[Tuple[int, str, str]] = [(6, "srcaddr", "dstaddr")]
        else:
            fams = []
            has6 = bool(pol.get("srcaddr6") or pol.get("dstaddr6"))
            has4 = bool(pol.get("srcaddr") or pol.get("dstaddr"))
            if has4 or not has6:            # default to v4 when no addr field set
                fams.append((4, "srcaddr", "dstaddr"))
            if has6:
                fams.append((6, "srcaddr6", "dstaddr6"))
        try:
            if not enable(pol.get("status")):
                notes.append(f"fortinet policy {pname} is disabled "
                             f"(set status disable) — skipped (not enforced)")
                continue

            action, forwarding = _action_of(_first(pol.get("action")))
            base_imprecise = False

            if forwarding:
                base_imprecise = True
                notes.append(f"fortinet policy {pname}: action "
                             f"'{(_first(pol.get('action')) or '').lower()}' "
                             f"FORWARDS matched traffic (tunnel/portal/redirect) "
                             f"— modeled as an over-approximating PERMIT + "
                             f"imprecise (never a deny); the exact forwarded "
                             f"path/NAT is unmodeled")

            # Interfaces: a SPECIFIC srcintf/dstintf narrows the match (like a
            # PAN-OS from/to zone) — over-approximate + imprecise. "any" is exact.
            for ik in ("srcintf", "dstintf"):
                iv = pol.get(ik) or []
                if any(v.lower() != "any" for v in iv):
                    base_imprecise = True
                    notes.append(f"fortinet policy {pname}: specific {ik} "
                                 f"{[v for v in iv if v.lower() != 'any']} not "
                                 f"modeled (L3/L4 over-approximation — marked "
                                 f"imprecise, used conservatively)")

            sched = (_first(pol.get("schedule")) or "always").lower()
            if sched != "always":
                base_imprecise = True
                notes.append(f"fortinet policy {pname}: schedule '{sched}' "
                             f"restricts WHEN the rule matches — not modeled "
                             f"(marked imprecise, verify manually)")

            for idk in ("users", "groups", "fsso-groups"):
                if pol.get(idk):
                    base_imprecise = True
                    notes.append(f"fortinet policy {pname}: identity match "
                                 f"`set {idk}` narrows the match — not modeled "
                                 f"(marked imprecise, verify manually)")
                    break

            if flag_on(pol.get("nat")):
                notes.append(f"fortinet policy {pname}: `set nat enable` — source "
                             f"NAT is not modeled (filter-space only; the L3/L4 "
                             f"match space is unchanged)")

            combos, svc_ok = resolve_service_list(pol.get("service") or [], pvdom)
            if not svc_ok:
                base_imprecise = True
                notes.append(f"fortinet policy {pname}: service "
                             f"{pol.get('service')} unresolvable — widened to ANY "
                             f"proto/port (marked imprecise)")

            # Negated service matches the COMPLEMENT of the service set — not one
            # rectangle. Widen the whole service dimension to ANY proto/port
            # (superset) + imprecise; never keep the listed set (that would
            # under-approximate and let segcheck FALSE-PASS a probe outside it).
            if flag_on(pol.get("service-negate")):
                combos, base_imprecise = [_ANY_SVC], True
                notes.append(f"fortinet policy {pname}: service-negate enable — "
                             f"matches the complement of the listed services; "
                             f"widened to ANY proto/port (marked imprecise)")

            for family, sf, df in fams:
                any_net = _any_of(family)
                imprecise = base_imprecise
                cbs = combos

                srcs, src_ok = resolve_addr_list(pol.get(sf) or [], pvdom, family)
                dsts, dst_ok = resolve_addr_list(pol.get(df) or [], pvdom, family)
                if not src_ok:
                    imprecise = True
                    notes.append(f"fortinet policy {pname}: {sf} "
                                 f"{pol.get(sf)} has an unresolvable/undefined "
                                 f"member — src widened to ANY (marked imprecise)")
                if not dst_ok:
                    imprecise = True
                    notes.append(f"fortinet policy {pname}: {df} "
                                 f"{pol.get(df)} has an unresolvable/undefined "
                                 f"member — dst widened to ANY (marked imprecise)")

                # Negated addresses match the COMPLEMENT — not one rectangle.
                # Widen that dimension to ANY (superset) + imprecise.
                if flag_on(pol.get("srcaddr-negate")):
                    srcs, imprecise = [any_net], True
                    notes.append(f"fortinet policy {pname}: srcaddr-negate enable "
                                 f"— matches the complement of the listed set; "
                                 f"widened to ANY (marked imprecise)")
                if flag_on(pol.get("dstaddr-negate")):
                    dsts, imprecise = [any_net], True
                    notes.append(f"fortinet policy {pname}: dstaddr-negate enable "
                                 f"— matches the complement of the listed set; "
                                 f"widened to ANY (marked imprecise)")

                if len(srcs) * len(dsts) * len(cbs) > _MAX_EXPAND:
                    notes.append(f"fortinet policy {pname} expands to >"
                                 f"{_MAX_EXPAND} ACEs; widened to a single "
                                 f"any/any ACE (superset) and marked imprecise "
                                 f"— verify")
                    srcs, dsts, cbs, imprecise = [any_net], [any_net], \
                        [_ANY_SVC], True

                for s in srcs:
                    for d in dsts:
                        for proto, spr, dpr, itype in cbs:
                            seq += 1
                            entries.append(ACE(
                                seq=seq, action=action, proto=proto, src=s, dst=d,
                                src_port=spr, dst_port=dpr, icmp_type=itype,
                                stateful=False, imprecise=imprecise,
                                raw=(f"policy {pname}: {action} {proto} {s} -> {d}"
                                     + (f" dport {dpr}" if not dpr.is_any() else "")
                                     + (f" type {itype}" if itype else "")),
                                acl=acl, line=pline, transit=True))
        except Exception as exc:
            # A policy we cannot expand fails CLOSED: one opaque any/any imprecise
            # ACE per family (preserving its action), so it becomes
            # segmentation-INDETERMINATE for any flow it touches (never a silent
            # hole / false PASS).
            act, _fwd = _action_of(_first(pol.get("action")))
            for family, _sf, _df in (fams or [(4, "srcaddr", "dstaddr")]):
                any_net = _any_of(family)
                seq += 1
                entries.append(ACE(seq=seq, action=act, proto="ip", src=any_net,
                                   dst=any_net, imprecise=True,
                                   raw=f"policy {pname}: unparsed ({exc!r}) — "
                                       f"fail-closed", acl=acl, line=pline,
                                   transit=True))
            notes.append(f"fortinet policy {pname}: expansion error ({exc!r}) — "
                         f"kept as an opaque imprecise ACE (fail-closed)")

    # ── Trailing implicit deny-all (the FortiGate default) PER context, for BOTH
    # families. Without it segcheck could FALSE-PASS a leak that simply runs off
    # the end of a policy list. A v6-only deny would leave v4 flows uncovered and
    # vice-versa, so each context gets both. The plain "firewall-policy" context
    # (if any) is appended LAST so its v4 deny is the final ACE (stable for
    # callers that inspect the tail).
    ctx_list = sorted(c for c in contexts if c != _ACL)
    if _ACL in contexts or not contexts:
        ctx_list.append(_ACL)
    for acl in ctx_list:
        seq += 1
        entries.append(ACE(seq=seq, action="deny", proto="ip", src=_ANY6,
                           dst=_ANY6,
                           raw=f"{acl}: implicit default deny-all (IPv6)",
                           acl=acl, line=0, transit=True))
        seq += 1
        entries.append(ACE(seq=seq, action="deny", proto="ip", src=_ANY4,
                           dst=_ANY4,
                           raw=f"{acl}: implicit default deny-all",
                           acl=acl, line=0, transit=True))

    if not policies:
        notes.append("fortinet: no `config firewall policy` entries found — only "
                     "the implicit default deny-all is modeled")
    notes.append(f"fortinet: {len(policies)} policy edit(s) across "
                 f"{len(ctx_list)} first-match context(s) "
                 f"{sorted(ctx_list)}; trailing implicit deny-all (v4+v6) "
                 f"appended per context")
    return entries, notes
