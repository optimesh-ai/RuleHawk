"""Rule-space analysis: the product's core value.

Per ACL (entries in match order):
  * SHADOWED / DEAD       — a rule an earlier EXACT rule fully covers, so it can
                            never match. Split by intent:
       - intent-inversion-permit-dead (earlier deny kills a later permit) ->
         silent CONNECTIVITY loss (high).
       - intent-inversion-deny-dead   (earlier permit kills a later deny)  ->
         silent SECURITY hole (critical).
       - redundant                    (same action) -> safe to delete (low).
  * OVERLY-PERMISSIVE     — permit ip any any (critical) and broad any (high).
  * DANGEROUS-EXPOSURE    — a permit exposing a sensitive service to `any` src.
Only EXACT earlier rules can prove a later rule dead (see model.covers): an
`imprecise` (neq / bad mask) or `stateful` (established) rule never covers,
so we never recommend deleting a load-bearing rule.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional, Tuple

from .model import (ACE, _WILDCARD_PROTO, _compatible_coverer, covered_dimensions,
                    covers, _union_covers)

# Max compatible earlier rules considered when testing cumulative coverage. Beyond
# this we under-report (stay fast/sound) rather than risk slowdown — documented.
_UNION_K = 64

_SEV_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

# Sensitive services that should not be reachable from `any`. SSH is separated:
# bastion/management SSH-from-any is common, so it's MEDIUM, not HIGH like telnet.
_DANGEROUS_PORTS = {
    21: "ftp", 23: "telnet", 135: "msrpc", 137: "netbios", 138: "netbios",
    139: "netbios", 445: "smb", 512: "rexec", 513: "rlogin", 514: "rsh",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5601: "kibana", 5900: "vnc", 5985: "winrm", 5986: "winrm-https",
    6379: "redis", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    2049: "nfs", 2375: "docker", 2379: "etcd", 389: "ldap",
}
_SSH_PORT = 22  # reported at MEDIUM


@dataclasses.dataclass
class Finding:
    rule_id: str
    kind: str
    severity: str
    message: str
    rule: str
    cited: str = ""
    fix: str = ""
    witness: str = ""   # segmentation: the concrete packet, e.g. "10.20.0.1 -> 10.10.0.1:445 (tcp)"
    line: int = 0       # 1-based source-file line of the offending rule (0 = unknown).


def _id(a: ACE) -> str:
    return f"{a.acl}:{a.seq}"


def _minimize(target, spanners, attr) -> List[ACE]:
    """Greedily drop coverers whose removal still leaves `target` covered, so the
    citation is the smallest provably-sufficient set (explainability)."""
    result = list(spanners)
    for a in list(result):
        trial = [x for x in result if x is not a]
        if trial and _union_covers(target, [getattr(x, attr) for x in trial]):
            result = trial
    return result


def _union_shadow(b: ACE, earlier: List[ACE]) -> Optional[Tuple[str, str, List[ACE]]]:
    """If b's IP space is fully covered by the UNION of compatible earlier exact
    rules, return (kind, severity, cited_rules). Else None.

    Sound (never over-claims) and conservative: only single-dimension unions —
    coverers that each span all of b.dst whose srcs union to b.src (Case A), or
    the symmetric Case B. Reached only when no SINGLE rule already covers b, so a
    genuine union needs >=2 rules."""
    coverers = [a for a in earlier if _compatible_coverer(a, b)]
    if len(coverers) < 2:
        return None
    if len(coverers) > _UNION_K:                       # keep the broadest
        coverers = sorted(coverers,
                          key=lambda a: a.src.num_addresses + a.dst.num_addresses,
                          reverse=True)[:_UNION_K]
    dims = [(a, covered_dimensions(a, b)) for a in coverers]
    dst_spanners = [a for a, (cs, cd) in dims if cd]   # each spans all of b.dst
    src_spanners = [a for a, (cs, cd) in dims if cs]   # each spans all of b.src

    chosen = None
    if len(dst_spanners) >= 2 and _union_covers(b.src, [a.src for a in dst_spanners]):
        chosen = _minimize(b.src, dst_spanners, "src")
    elif len(src_spanners) >= 2 and _union_covers(b.dst, [a.dst for a in src_spanners]):
        chosen = _minimize(b.dst, src_spanners, "dst")
    if not chosen or len(chosen) < 2:
        return None

    if {a.action for a in chosen} == {b.action}:
        return ("union-redundant", "low", chosen)
    if b.action == "deny":
        return ("union-shadowed-deny-dead", "critical", chosen)
    return ("union-shadowed-permit-dead", "high", chosen)


_UNION_MSG = {
    "union-shadowed-deny-dead": (
        "This deny NEVER takes effect — earlier rules {seqs} cumulatively "
        "already allow the same traffic. The traffic you meant to block is ALLOWED.",
        "make the deny match only traffic not already permitted, or move it above rules {seqs}"),
    "union-shadowed-permit-dead": (
        "This permit NEVER takes effect — earlier rules {seqs} cumulatively "
        "already drop the same traffic. Likely a silent connectivity loss.",
        "move rule {seq} above rules {seqs}, or narrow them"),
    "union-redundant": (
        "Rule is redundant — its traffic is already fully handled by earlier "
        "rules {seqs}; safe to remove.",
        "remove rule {seq}"),
}


def _analyze_one_acl(aces: List[ACE]) -> List[Finding]:
    findings: List[Finding] = []
    for i, b in enumerate(aces):
        # Shadowing: the first EXACT earlier rule whose space covers b kills b.
        shadowed = False
        for a in aces[:i]:
            if not covers(a, b):       # covers() already excludes imprecise/stateful a
                continue
            if a.action == b.action:
                findings.append(Finding(
                    _id(b), "redundant", "low",
                    f"Rule is redundant — fully covered by an earlier "
                    f"{a.action} (rule {a.seq}); safe to remove.",
                    b.raw, a.raw, fix=f"remove rule {b.seq}",
                    line=b.line))
            elif b.action == "permit":
                findings.append(Finding(
                    _id(b), "intent-inversion-permit-dead", "high",
                    f"This permit NEVER takes effect — an earlier deny "
                    f"(rule {a.seq}) already drops the same traffic. "
                    f"Likely a silent connectivity loss.",
                    b.raw, a.raw,
                    fix=f"move rule {b.seq} above rule {a.seq}, or narrow rule {a.seq}",
                    line=b.line))
            else:
                findings.append(Finding(
                    _id(b), "intent-inversion-deny-dead", "critical",
                    f"This deny NEVER takes effect — an earlier permit "
                    f"(rule {a.seq}) already allows the same traffic. The "
                    f"traffic you meant to block is ALLOWED.",
                    b.raw, a.raw, fix=f"move rule {b.seq} above rule {a.seq}",
                    line=b.line))
            shadowed = True
            break

        # No single rule covers b — is it dead under the UNION of earlier rules?
        if not shadowed:
            u = _union_shadow(b, aces[:i])
            if u:
                kind, sev, chosen = u
                seqs = ", ".join(str(a.seq) for a in sorted(chosen, key=lambda x: x.seq))
                msg, fix = _UNION_MSG[kind]
                findings.append(Finding(
                    _id(b), kind, sev,
                    msg.format(seqs=seqs, seq=b.seq), b.raw,
                    cited=f"rules {seqs} (cumulative)",
                    fix=fix.format(seqs=seqs, seq=b.seq),
                    line=b.line))

        if b.action != "permit" or b.stateful:
            # `established` permits are return-traffic — not an over-permission.
            continue
        # Only a rule whose space is EXACT can be called over-permissive — an
        # over-approximated (imprecise) address must never drive an any/any verdict.
        if b.src_any and b.dst_any and not b.imprecise:
            if b.proto in _WILDCARD_PROTO:
                findings.append(Finding(
                    _id(b), "permit-any-any", "critical",
                    f"permit {b.proto} any any — allows ALL traffic; defeats the ACL.",
                    b.raw, fix="replace with least-privilege permits + a default deny",
                    line=b.line))
            else:
                findings.append(Finding(
                    _id(b), "broad-any-any", "high",
                    f"permit {b.proto} any any — very broad; allows all {b.proto} "
                    f"between any hosts.", b.raw,
                    fix="scope the source and/or destination",
                    line=b.line))
        # Dangerous services exposed to any source (skip imprecise port spaces).
        if b.src_any and b.proto in ("tcp", "udp") and not b.imprecise:
            hits = sorted({name for port, name in _DANGEROUS_PORTS.items()
                           if b.dst_port.contains(port)})
            if b.dst_port.contains(_SSH_PORT):
                findings.append(Finding(
                    _id(b), "ssh-exposure", "medium",
                    "SSH (port 22) is permitted from ANY source — fine for a "
                    "bastion, risky otherwise; confirm it's intended.",
                    b.raw, fix="restrict the source for SSH if not a jump host",
                    line=b.line))
            if hits:
                findings.append(Finding(
                    _id(b), "dangerous-exposure", "high",
                    f"Sensitive service(s) permitted from ANY source: "
                    f"{', '.join(hits)}.", b.raw,
                    fix="restrict the source, or remove if unused",
                    line=b.line))
    return findings


def analyze(aces: List[ACE]) -> List[Finding]:
    by_acl: Dict[str, List[ACE]] = {}
    for a in aces:
        by_acl.setdefault(a.acl, []).append(a)
    out: List[Finding] = []
    for acl_aces in by_acl.values():
        out.extend(_analyze_one_acl(sorted(acl_aces, key=lambda x: x.seq)))
    return out


def score(findings: List[Finding]) -> int:
    """0 (worst) .. 100 (clean)."""
    return max(0, 100 - sum(_SEV_WEIGHT.get(f.severity, 0) for f in findings))
