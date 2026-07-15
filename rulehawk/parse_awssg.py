"""Parse AWS EC2 Security Groups (and Control Tower multi-account bundles) into
RuleHawk `ACE`s.

WHY THIS MAPS SOUNDLY ONTO A FIRST-MATCH MODEL. A Security Group is not an
ordered ACL: it is STATEFUL, ALLOW-ONLY, and ORDER-INDEPENDENT. A flow is
allowed iff SOME rule matches it, otherwise it is implicitly denied; there are no
deny rules and no ordering among the permits. That still reduces exactly onto
RuleHawk's ordered first-match engine: emit every SG rule as a `permit` (their
order is irrelevant because none of them conflict — they only ever ADD reachable
space) followed by ONE trailing `deny ip any any`, the implicit default-deny.
Because a packet is evaluated against the SGs attached to ITS OWN instance,
independently of every other group, each Security Group is its OWN first-match
context (`acl` = a readable "name (sg-id)" label). So the existing analysis /
segmentation engine (`analyze.py`, `segcheck.py`) consumes the result unchanged.

THE dst=ANY (INGRESS) OVER-APPROXIMATION — SOUND, and honestly one-directional.
An ingress rule says "allow FROM <source-CIDR> TO the instances carrying this
SG on <ports>". The SOURCE is a concrete `CidrIp`/`CidrIpv6` (modeled EXACTLY);
only the DESTINATION — the set of instances that carry this SG — is unknown, so
it is widened to ANY (`0.0.0.0/0` / `::/0`). ANY is a strict SUPERSET of the
true destination, so per the model.py PARSER CONTRACT this widens (never
narrows) and stays sound. The consequence for a `must_not_reach SRC -> DST`
assertion: because the asserted DST zone is always a subset of ANY, an ingress
permit whose exact source overlaps the SRC zone yields a CONCRETE violation
witness. This can OVER-report — we do not know whether any instance carrying the
SG actually sits in the DST zone — but over-reporting is the SAFE direction: it
can raise a false alarm, NEVER a false PASS (a false PASS would require
NARROWING the space, which we never do). Ingress rules are therefore NOT marked
imprecise: they produce concrete, actionable verdicts.

THE src=ANY (EGRESS) WIDENING — marked imprecise (fail-closed). An egress rule
says "allow FROM the instances carrying this SG TO <dest-CIDR>". Here the DEST is
exact but the SOURCE (the instances) is unknown and widened to ANY. A
`must_not_reach` assertion constrains the SOURCE zone, which we would be matching
against a widened ANY — a vacuous match that cannot confirm the rule's true
source lies in the asserted zone. To avoid asserting a concrete violation we
cannot substantiate, egress rules are marked `imprecise`: `segcheck` degrades
them to an honest "indeterminate / review manually" rather than a possibly-wrong
concrete verdict, and `covers()` never lets one prove another rule dead. This is
the sound fail-closed direction (never a false PASS); auditing egress precisely
needs the instance inventory, which the SG export does not carry.

SG-TO-SG REFERENCES and MANAGED PREFIX LISTS (`UserIdGroupPairs`,
`PrefixListIds`). The peer is another SG's live membership or a managed prefix
list — not a CIDR we can resolve from this document. Dropping such a rule could
false-PASS a genuinely reachable flow, so it is NEVER dropped: it is emitted as
a permit with the unresolved dimension widened to ANY (both address families)
and `imprecise=True` plus a surfaced note. In `segcheck` an imprecise permit
that touches the forbidden space yields indeterminate (never a PASS).

PROTOCOLS / PORTS. `IpProtocol` "-1" -> "ip" (all protocols); "tcp"/"udp"/
"icmp"/"icmpv6" pass through; a numeric string ("47") folds via a small IANA
table. For ported protocols `FromPort`/`ToPort` -> one `PortRange` (absent =>
all ports). For ICMP, `FromPort` is the ICMP TYPE (modeled as `icmp_type`;
-1/absent = all types) and `ToPort` is the code.

CONTROL TOWER / MULTI-ACCOUNT. Three input shapes are accepted: the canonical
`aws ec2 describe-security-groups` object `{"SecurityGroups": [...]}`, a bare
top-level JSON ARRAY of SecurityGroup objects (how Control Tower / multi-account
exports frequently concatenate), and a single SecurityGroup object. Every group
— across every account and region — becomes its own independent first-match
context, so one account's catch-all can never shadow another's.

ROBUSTNESS. Invalid JSON makes `detect` return False (the input falls through to
other frontends) and `parse_awssg` return ([], [note]); it never raises. Empty
groups, missing keys and unusual protocol/port values degrade with notes.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PORT_MAX, PORT_MIN, PortRange, _IPNet

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")

# Keys that identify a describe-security-groups object / a bare SG object. These
# are exactly the markers the Umbrella CDFW frontend refuses, so the two JSON
# frontends never both claim the same document.
_SG_GROUP_KEYS = ("GroupId", "IpPermissions", "IpPermissionsEgress")

# Protocols we attach a port range to (the same set covers() compares ports on).
# AWS uses tcp/udp in practice; sctp included for completeness.
_PORTED = frozenset({"tcp", "udp", "sctp"})

# Numeric IpProtocol -> name. Deliberately excludes anything that collides with
# model._WILDCARD_PROTO ({ip, any, ipv4, ipv6}): a numeric proto (e.g. 41,
# IPv6-encap) must stay a SPECIFIC protocol, never fold to a wildcard that would
# unsoundly "match everything".
_PROTO_NUM = {
    "1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
    "51": "ah", "58": "icmpv6", "89": "ospf", "103": "pim", "112": "vrrp",
    "132": "sctp",
}


# ── detection ────────────────────────────────────────────────────────────────

def _is_group(obj: object) -> bool:
    """True iff `obj` is a dict carrying at least one SG-specific key."""
    return isinstance(obj, dict) and any(k in obj for k in _SG_GROUP_KEYS)


def _looks_like_sg(doc: object) -> bool:
    if isinstance(doc, dict):
        if isinstance(doc.get("SecurityGroups"), list):
            return True                     # the key itself is SG-specific
        return _is_group(doc)               # a single SecurityGroup object
    if isinstance(doc, list):
        return any(_is_group(g) for g in doc)
    return False


def detect(text: str) -> bool:
    """Heuristic: does `text` look like `aws ec2 describe-security-groups` output?

    Strict: the text must be valid JSON AND either carry a top-level
    ``SecurityGroups`` list, or be a list/object whose item(s) carry the
    SG-specific keys (``GroupId`` / ``IpPermissions`` / ``IpPermissionsEgress``).
    Arbitrary JSON, the Umbrella CDFW export (distinct ``rules``/source/dest
    keys, no SG markers) and Cisco/Junos/PAN-OS text configs are all rejected.
    """
    if not isinstance(text, str):
        return False
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return False                        # not JSON object/array — skip fast
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return False
    return _looks_like_sg(doc)


# ── small tolerant helpers ───────────────────────────────────────────────────

def _norm_proto(p: object) -> str:
    """Fold an `IpProtocol` value to a RuleHawk proto token."""
    if p is None:
        return "ip"
    s = str(p).strip().lower()
    if s in ("-1", "", "all"):
        return "ip"
    if s in ("ipv6-icmp", "icmpv6"):
        return "icmpv6"
    return _PROTO_NUM.get(s, s)


def _port_range(from_p: object, to_p: object) -> PortRange:
    """FromPort/ToPort -> one PortRange, widening any missing/negative bound to
    the full range (superset). AWS gives a single contiguous range per rule."""
    lo = from_p if isinstance(from_p, int) and from_p >= 0 else PORT_MIN
    hi = to_p if isinstance(to_p, int) and to_p >= 0 else PORT_MAX
    lo = max(PORT_MIN, min(PORT_MAX, lo))
    hi = max(PORT_MIN, min(PORT_MAX, hi))
    if lo > hi:
        lo, hi = hi, lo
    return PortRange(lo, hi)


def _icmp_type(from_p: object) -> Optional[str]:
    """For ICMP, FromPort carries the ICMP TYPE. -1 / absent = every type."""
    if isinstance(from_p, int) and from_p >= 0:
        return str(from_p)
    return None


def _parse_net(cidr: object) -> Optional[_IPNet]:
    if not isinstance(cidr, str):
        return None
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except (ValueError, TypeError):
        return None


def _acl_label(g: dict, seen: Dict[str, int]) -> str:
    """A readable, UNIQUE first-match context label for the group. GroupId is
    globally unique, so "name (sg-id)" never collides; groups lacking an id get a
    disambiguating suffix so two same-named groups stay independent contexts."""
    gid = g.get("GroupId")
    gname = g.get("GroupName")
    if gname and gid:
        base = f"{gname} ({gid})"
    elif gid:
        base = str(gid)
    elif gname:
        base = str(gname)
    else:
        base = "security-group"
    n = seen.get(base, 0)
    seen[base] = n + 1
    return base if n == 0 else f"{base} #{n + 1}"


def _group_line(text: str, g: dict) -> int:
    """Best-effort 1-based source line of the group (advisory only; 0 = unknown)."""
    key = g.get("GroupId") or g.get("GroupName")
    if not isinstance(key, str) or not key:
        return 0
    idx = text.find(key)
    if idx < 0:
        return 0
    return text.count("\n", 0, idx) + 1


def _raw(acl: str, direction: str, proto: str, src: _IPNet, dst: _IPNet,
         dport: PortRange, itype: Optional[str], imprecise: bool) -> str:
    parts = [f"{acl}:", direction, "permit", proto, str(src), "->", str(dst)]
    if not dport.is_any():
        parts.append(f"dport {dport}")
    if itype is not None:
        parts.append(f"icmp-type {itype}")
    if imprecise:
        parts.append("(over-approximated to ANY — imprecise)")
    return " ".join(parts)


# ── endpoint (CIDR / SG-ref / prefix-list) expansion ─────────────────────────

def _endpoints(perm: dict, direction: str, acl: str,
               notes: List[str]) -> List[Tuple[Optional[_IPNet], bool]]:
    """The CONCRETE side of a permission (sources for ingress, dests for egress).

    Returns (net_or_None, imprecise) tuples. `net` is an exact CIDR network;
    None means "the peer is a security-group / prefix-list / unparseable CIDR —
    widen to ANY in BOTH address families and flag imprecise". A rule is NEVER
    dropped for an unresolved peer (dropping a permit could false-PASS a real
    reachable flow); it is over-approximated instead."""
    out: List[Tuple[Optional[_IPNet], bool]] = []

    for r in perm.get("IpRanges") or []:
        if not isinstance(r, dict):
            continue
        net = _parse_net(r.get("CidrIp"))
        if net is None:
            notes.append(f"security group {acl}: unparseable CidrIp "
                         f"{r.get('CidrIp')!r} in a {direction} rule — "
                         f"over-approximated to ANY (imprecise; rule not dropped).")
            out.append((None, True))
        else:
            out.append((net, False))

    for r in perm.get("Ipv6Ranges") or []:
        if not isinstance(r, dict):
            continue
        net = _parse_net(r.get("CidrIpv6"))
        if net is None:
            notes.append(f"security group {acl}: unparseable CidrIpv6 "
                         f"{r.get('CidrIpv6')!r} in a {direction} rule — "
                         f"over-approximated to ANY (imprecise; rule not dropped).")
            out.append((None, True))
        else:
            out.append((net, False))

    for pair in perm.get("UserIdGroupPairs") or []:
        ref = "?"
        if isinstance(pair, dict):
            ref = pair.get("GroupId") or pair.get("GroupName") or "?"
        notes.append(f"security group {acl}: {direction} rule references security "
                     f"group {ref} — SG membership is not modeled, "
                     f"over-approximated to ANY (imprecise; rule NOT dropped).")
        out.append((None, True))

    for pl in perm.get("PrefixListIds") or []:
        plid = pl.get("PrefixListId") if isinstance(pl, dict) else pl
        notes.append(f"security group {acl}: {direction} rule references managed "
                     f"prefix list {plid} — membership is not modeled, "
                     f"over-approximated to ANY (imprecise; rule NOT dropped).")
        out.append((None, True))

    return out


def _emit_perm(perm: object, direction: str, acl: str, line: int,
               notes: List[str], aces: List[ACE], seq: int) -> int:
    """Expand one IpPermission(Egress) entry into permit ACEs, appended to `aces`.
    Returns the updated running `seq` for the context."""
    if not isinstance(perm, dict):
        notes.append(f"security group {acl}: skipped a non-object {direction} "
                     f"permission entry.")
        return seq

    proto = _norm_proto(perm.get("IpProtocol"))
    from_p = perm.get("FromPort")
    to_p = perm.get("ToPort")
    dport = _port_range(from_p, to_p) if proto in _PORTED else ANY_PORTS
    itype = _icmp_type(from_p) if proto in ("icmp", "icmpv6") else None

    endpoints = _endpoints(perm, direction, acl, notes)
    if not endpoints:
        notes.append(f"security group {acl}: a {direction} permission has no "
                     f"source/destination selectors (IpRanges / Ipv6Ranges / "
                     f"UserIdGroupPairs / PrefixListIds) — nothing to model.")
        return seq

    for net, ep_imprecise in endpoints:
        fams = [net.version] if net is not None else [4, 6]
        for fam in fams:
            any_net = _ANY6 if fam == 6 else _ANY4
            concrete = net if (net is not None and net.version == fam) else any_net
            if direction == "ingress":
                # Source is exact (the CidrIp); destination (the instances) is
                # the ANY superset. Imprecise only when the peer is unresolved.
                src, dst, imprecise = concrete, any_net, ep_imprecise
            else:
                # Egress: destination exact, SOURCE (the instances) widened to
                # ANY -> imprecise (fail-closed; see module docstring).
                src, dst, imprecise = any_net, concrete, True
            seq += 1
            aces.append(ACE(
                seq=seq, action="permit", proto=proto, src=src, dst=dst,
                src_port=ANY_PORTS, dst_port=dport, icmp_type=itype,
                imprecise=imprecise,
                raw=_raw(acl, direction, proto, src, dst, dport, itype, imprecise),
                acl=acl, line=line, transit=True))
    return seq


def _parse_group(g: dict, text: str, notes: List[str],
                 seen: Dict[str, int]) -> List[ACE]:
    acl = _acl_label(g, seen)
    line = _group_line(text, g)
    aces: List[ACE] = []
    seq = 0

    ingress = g.get("IpPermissions")
    if ingress is not None and not isinstance(ingress, list):
        notes.append(f"security group {acl}: 'IpPermissions' is not a list — "
                     f"ingress ignored.")
        ingress = None
    for perm in ingress or []:
        seq = _emit_perm(perm, "ingress", acl, line, notes, aces, seq)

    egress = g.get("IpPermissionsEgress")
    if egress is None:
        notes.append(f"security group {acl}: no 'IpPermissionsEgress' field — "
                     f"egress not modeled. AWS's default egress is allow-all; if "
                     f"this export omitted egress, those flows are UNMODELED "
                     f"(paste full describe-security-groups output to audit egress).")
    elif not isinstance(egress, list):
        notes.append(f"security group {acl}: 'IpPermissionsEgress' is not a list "
                     f"— egress ignored.")
    else:
        for perm in egress:
            seq = _emit_perm(perm, "egress", acl, line, notes, aces, seq)

    # The implicit default-deny (SG allow-only). Emitted in BOTH families so a v6
    # flow is denied by default too, never silently unhandled.
    for any_net in (_ANY4, _ANY6):
        seq += 1
        aces.append(ACE(
            seq=seq, action="deny", proto="ip", src=any_net, dst=any_net,
            raw=f"{acl}: implicit default-deny (Security Groups are allow-only)",
            acl=acl, line=line, transit=True))
    return aces


def _extract_groups(doc: object, notes: List[str]) -> List[object]:
    if isinstance(doc, dict):
        sg = doc.get("SecurityGroups")
        if isinstance(sg, list):
            return list(sg)
        if sg is not None:
            notes.append("'SecurityGroups' is present but is not a list — ignored.")
        if _is_group(doc):
            return [doc]
        notes.append("JSON object is neither a describe-security-groups output "
                     "nor a single security-group object — no groups found.")
        return []
    if isinstance(doc, list):
        return list(doc)
    notes.append("top-level JSON is neither an object nor an array — no security "
                 "groups found.")
    return []


def parse_awssg(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse AWS Security Groups in `text`; return (entries, notes).

    Same contract as `parse.parse_acls`, so `analyze`/`check_segmentation`
    consume the result unchanged. Each Security Group is an independent
    first-match context; its ingress + egress rules become permits followed by an
    implicit default-deny. Never raises: invalid input returns ([], [note]).
    """
    notes: List[str] = []
    if not isinstance(text, str):
        return [], ["AWS security-group input is not text — nothing parsed."]
    try:
        doc = json.loads(text)
    except (ValueError, TypeError) as exc:
        return [], [f"AWS security-group input is not valid JSON ({exc}) — "
                    f"nothing parsed."]

    groups = _extract_groups(doc, notes)
    entries: List[ACE] = []
    seen: Dict[str, int] = {}
    n_groups = 0
    for g in groups:
        if not isinstance(g, dict):
            notes.append("skipped a non-object entry in the security-group list.")
            continue
        if not _is_group(g):
            notes.append("skipped an object with no GroupId / IpPermissions / "
                         "IpPermissionsEgress — not a security group.")
            continue
        n_groups += 1
        entries.extend(_parse_group(g, text, notes, seen))

    if entries:
        notes.append(
            "AWS Security Groups are stateful, allow-only, order-independent: each "
            "rule is modeled as a permit and each group gets one implicit "
            "default-deny. Ingress destinations (the SG's instances) are "
            "over-approximated to ANY — SOUND for must_not_reach (may over-report, "
            "never a false PASS). Egress sources (the instances) are unknown and "
            "marked imprecise (segcheck yields indeterminate, never a false PASS).")
    if n_groups > 1:
        notes.append(f"parsed {n_groups} security groups as {n_groups} independent "
                     f"first-match contexts (multi-account / Control Tower bundles "
                     f"are handled per group).")
    if not entries:
        notes.append("no AWS security-group rules were modeled from this input.")
    return entries, notes
