"""Parse AWS EC2 Security Groups (`aws ec2 describe-security-groups`) into `ACE`s.

WHY SECURITY GROUPS FIT model.ACE (correcting an earlier judgment). An older note
in parse_panos.py said Security Groups "don't fit `model.ACE` without a different
analyzer" because they are allow-only and order-independent. That is right about
*shadowing* and wrong about everything else:

  * An allow-only, order-independent ruleset is EXACTLY equivalent to an ordered
    list of `permit`s terminated by the implicit default-deny the engine already
    assumes. First-match over a permit-only list == the union of those permits.
    So `segcheck` — the compliance value — is exact here, not approximate.
  * Least-privilege analysis is the single most valuable thing to run on a
    Security Group: `0.0.0.0/0` on 22/3389/445/3306 is the archetypal cloud
    exposure, and `permit-any-any`/`dangerous-exposure` catch it unchanged.
  * Redundancy analysis stays meaningful: an SG rule wholly covered by another
    is genuinely deletable.

What genuinely does NOT apply is intent-inversion (`deny`-dead / `permit`-dead):
with no deny rules, no rule can invert another's intent. Producing nothing there
is the correct answer, not a gap.

THE SOUNDNESS LINE. Two SG constructs cannot be resolved from the export alone:

  * `UserIdGroupPairs` — "allow from anything in sg-xxxx". The member instances'
    addresses are not in this document.
  * `PrefixListIds` — a managed/customer prefix list, resolved by AWS elsewhere.

Neither may be dropped (that would UNDER-approximate the permitted space and
could turn a real leak into a PASS) and neither may be guessed. Following the
PAN-OS partial-precision pattern, a permission mixing resolved CIDRs with
unresolvable references expands into EXACT ACEs for the CIDRs (which can prove a
CRITICAL) plus ONE trailing opaque any-source `imprecise` ACE covering the
unresolved remainder — which keeps that remainder INDETERMINATE forever: never a
PASS, never a false CRITICAL. Every unresolved reference is also surfaced as a
parse note.

DIRECTION. Ingress and egress are separate first-match contexts, emitted as
separate ACLs (`sg-xxxx/ingress`, `sg-xxxx/egress`) exactly like iptables chains.
In AWS a flow needs the source's EGRESS *and* the destination's INGRESS to allow
it, so a segmentation violation found in only one of them means "a ruleset on the
path permits the forbidden flow" — RuleHawk's documented, deliberately
over-reporting claim, not an end-to-end reachability proof. Erring toward
over-reporting is the fail-closed direction.

STATEFULNESS is a property of the *return* path, not of the rule: an ingress rule
still matches new inbound flows exactly. So rules are NOT marked `stateful`
(that flag means `established`, i.e. matches only return traffic). The practical
consequence — that no explicit return rule is needed — is surfaced as a note on
`must_reach`-style questions rather than modeled.

Scope: the JSON emitted by `aws ec2 describe-security-groups` (the
`{"SecurityGroups": [...]}` envelope, or a bare list of group objects). Network
ACLs (`describe-network-acls`) are ordered and DO have denies — a separate
frontend, not this one.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PortRange
from .parse import _PROTO_NUM, _canon_icmp_type

# `-1` in the IpProtocol slot means EVERY protocol (and forbids ports).
_ALL_PROTOS = "-1"

_V4_ANY = ipaddress.ip_network("0.0.0.0/0")
_V6_ANY = ipaddress.ip_network("::/0")


def detect(text: str) -> bool:
    """True for `aws ec2 describe-security-groups` JSON.

    Deliberately narrow: it must parse as JSON AND carry the Security-Group
    shape. A Network ACL export is ordered and has denies, so it must NOT be
    routed here and silently read as allow-only.
    """
    head = text.lstrip()[:1]
    if head not in ("{", "["):
        return False
    try:
        doc = json.loads(text)
    except ValueError:
        return False
    groups = _groups_of(doc)
    if groups is None:
        return False
    return any(("IpPermissions" in g or "IpPermissionsEgress" in g)
               and ("GroupId" in g or "GroupName" in g)
               for g in groups if isinstance(g, dict))


def _groups_of(doc: Any) -> Optional[List[dict]]:
    """The group list, from either the CLI envelope or a bare array."""
    if isinstance(doc, dict):
        groups = doc.get("SecurityGroups")
        return groups if isinstance(groups, list) else None
    if isinstance(doc, list):
        return doc
    return None


def _line_index(text: str) -> Dict[str, int]:
    """Best-effort 1-based source line for each `"GroupId": "sg-…"` occurrence,
    so the CI gate can annotate the group in a PR diff. A JSON document has no
    per-rule lines to recover after json.loads, and a wrong line is worse than
    none — so findings anchor to their GROUP, and 0 when even that is unknown."""
    out: Dict[str, int] = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(r'"GroupId"\s*:\s*"([^"]+)"', line)
        if m and m.group(1) not in out:
            out[m.group(1)] = i
    return out


def _proto_of(perm: dict) -> Tuple[str, bool]:
    """(canonical protocol, is_wildcard). Numeric IANA values are folded to
    names by the same map the Cisco frontend uses, so `"6"` and `"tcp"` are one
    protocol to a policy assertion."""
    raw = perm.get("IpProtocol", _ALL_PROTOS)
    tok = str(raw).lower().strip()
    if tok in (_ALL_PROTOS, "", "all", "-1"):
        return "ip", True
    return _PROTO_NUM.get(tok, tok), False


def _ports_of(perm: dict, proto: str) -> Tuple[PortRange, Optional[str], List[str]]:
    """(dst port range, icmp type, notes).

    AWS overloads FromPort/ToPort for ICMP: FromPort is the ICMP *type* and
    ToPort the *code*, NOT ports. Reading them as ports would model a nonsense
    space (e.g. "tcp/8" for an echo rule), so they are routed to `icmp_type`.
    """
    notes: List[str] = []
    frm, to = perm.get("FromPort"), perm.get("ToPort")
    if proto in ("icmp", "icmpv6"):
        # -1 (or absent) = every type/code.
        if frm is None or int(frm) < 0:
            return ANY_PORTS, None, notes
        icmp_type = _canon_icmp_type(str(int(frm)))
        if to is not None and int(to) >= 0 and int(to) != int(frm):
            notes.append(
                f"ICMP code range {frm}-{to} is not modeled (RuleHawk reasons "
                f"about ICMP type only); the type is matched exactly")
        return ANY_PORTS, icmp_type, notes
    if frm is None and to is None:
        return ANY_PORTS, None, notes
    try:
        lo = int(frm) if frm is not None else 0
        hi = int(to) if to is not None else 65535
    except (TypeError, ValueError):
        notes.append(f"unparseable port range {frm!r}-{to!r} — widened to ANY")
        return ANY_PORTS, None, notes
    if lo < 0 or hi < 0:                     # -1 with a real protocol = all ports
        return ANY_PORTS, None, notes
    if lo > hi:
        notes.append(f"inverted port range {lo}-{hi} — widened to ANY")
        return ANY_PORTS, None, notes
    return PortRange(max(0, lo), min(65535, hi)), None, notes


def _cidrs_of(perm: dict) -> Tuple[List[ipaddress._BaseNetwork], List[str], List[str]]:
    """(resolved networks, unresolved-reference labels, notes)."""
    nets, unresolved, notes = [], [], []
    for entry in perm.get("IpRanges") or []:
        raw = (entry or {}).get("CidrIp")
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            notes.append(f"unparseable CidrIp {raw!r} — treated as unresolved")
            unresolved.append(f"CidrIp {raw}")
    for entry in perm.get("Ipv6Ranges") or []:
        raw = (entry or {}).get("CidrIpv6")
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            notes.append(f"unparseable CidrIpv6 {raw!r} — treated as unresolved")
            unresolved.append(f"CidrIpv6 {raw}")
    # Not resolvable from this document — must stay opaque, never dropped.
    for entry in perm.get("UserIdGroupPairs") or []:
        gid = (entry or {}).get("GroupId") or (entry or {}).get("GroupName") or "?"
        unresolved.append(f"security-group {gid}")
    for entry in perm.get("PrefixListIds") or []:
        pid = (entry or {}).get("PrefixListId") or "?"
        unresolved.append(f"prefix-list {pid}")
    return nets, unresolved, notes


def _raw_text(group_id: str, direction: str, proto: str, pr: PortRange,
              src: str) -> str:
    port = ""
    if pr != ANY_PORTS:
        port = f" port {pr.lo}" + ("" if pr.lo == pr.hi else f"-{pr.hi}")
    return f"{group_id} {direction} allow {proto} from {src}{port}"


def parse_awssg(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse `describe-security-groups` JSON -> (ACEs, notes)."""
    notes: List[str] = []
    try:
        doc = json.loads(text)
    except ValueError as e:
        return [], [f"not valid JSON: {e}"]
    groups = _groups_of(doc)
    if groups is None:
        return [], ["no SecurityGroups array found in the JSON document"]

    lines = _line_index(text)
    aces: List[ACE] = []
    for group in groups:
        if not isinstance(group, dict):
            notes.append(f"skipped a non-object entry in SecurityGroups: {group!r}")
            continue
        gid = group.get("GroupId") or group.get("GroupName") or "sg-?"
        gline = lines.get(gid, 0)
        for key, direction in (("IpPermissions", "ingress"),
                               ("IpPermissionsEgress", "egress")):
            acl = f"{gid}/{direction}"
            seq = 0
            for perm in (group.get(key) or []):
                if not isinstance(perm, dict):
                    notes.append(f"{acl}: skipped a non-object rule: {perm!r}")
                    continue
                proto, wildcard = _proto_of(perm)
                pr, icmp_type, pnotes = _ports_of(perm, proto)
                notes += [f"{acl}: {n}" for n in pnotes]
                nets, unresolved, cnotes = _cidrs_of(perm)
                notes += [f"{acl}: {n}" for n in cnotes]

                # The zone-facing side is the SOURCE for ingress and the
                # DESTINATION for egress; the other side is the instances the
                # group is attached to, whose addresses this document does not
                # contain — so it stays ANY (a superset, never a subset).
                for net in nets:
                    seq += 1
                    other = _V6_ANY if net.version == 6 else _V4_ANY
                    src, dst = (net, other) if direction == "ingress" else (other, net)
                    aces.append(ACE(
                        seq=seq, action="permit", proto=proto, src=src, dst=dst,
                        dst_port=pr, icmp_type=icmp_type,
                        raw=_raw_text(gid, direction, proto, pr, str(net)),
                        acl=acl, line=gline))
                if unresolved:
                    # ONE opaque catch-all for everything we could not resolve.
                    # Marked imprecise: it can never prove another rule dead and
                    # never certifies isolation — the remainder stays
                    # INDETERMINATE rather than silently PASSing.
                    seq += 1
                    label = ", ".join(sorted(set(unresolved)))
                    notes.append(
                        f"{acl}: unresolved source(s) [{label}] cannot be mapped "
                        f"to addresses from this export — modeled as an opaque "
                        f"any/any rule (review manually; never reported as "
                        f"isolated)")
                    aces.append(ACE(
                        seq=seq, action="permit", proto=proto,
                        src=_V4_ANY, dst=_V4_ANY, dst_port=pr,
                        icmp_type=icmp_type, imprecise=True,
                        raw=_raw_text(gid, direction, proto, pr, label),
                        acl=acl, line=gline))
                if not nets and not unresolved:
                    notes.append(f"{acl}: a rule names no source or destination "
                                 f"({perm!r}) — nothing to model")
    if not aces and not notes:
        notes.append("no security-group rules found in the document")
    return aces, notes
