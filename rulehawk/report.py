"""Render analysis findings as a human report (text) or machine report (JSON)."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .analyze import Finding, score

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Cap text output so a pathological config can't print thousands of lines, but
# NEVER silently drop: when we elide, we say how many remain and where to see
# them in full. Real ASA configs routinely carry hundreds of object-group lines,
# so the old hard `[:20]` truncation hid most of them (the JSON path was always
# complete) — a soundness regression for the "surface, never drop" promise.
_NOTES_CAP = 200

# Canonical human-readable list of every vendor format RuleHawk can parse.
# Kept in one place so the zero-rules error message and docs stay in sync.
_SUPPORTED_VENDORS = (
    "Cisco IOS/ASA, NX-OS, Arista EOS, Juniper Junos, Palo Alto PAN-OS, "
    "Fortinet FortiGate, iptables, Windows Firewall, AWS Security Groups, "
    "Cisco Umbrella CDFW, Infoblox/BIND DNS ACLs, Microsoft DNS"
)


def _note_lines(notes: List[str]) -> List[str]:
    out = [f"   ! {n}" for n in notes[:_NOTES_CAP]]
    extra = len(notes) - _NOTES_CAP
    if extra > 0:
        out.append(f"   ... and {extra} more not shown — re-run with --json "
                   f"for the complete list.")
    return out


def to_json(findings: List[Finding], notes: List[str], n_rules: int,
            vendor: Optional[str] = None) -> str:
    return json.dumps({
        # Additive field: machine-readable vendor label (ios-asa | junos | panos |
        # iptables | nxos | eos). "ios-asa" is also the default/fallback.
        "vendor": vendor or "ios-asa",
        # No parseable rules => not "clean", just nothing analyzed. Don't hand
        # the user a false 100/100 bill of health on input we couldn't read.
        "score": (score(findings) if n_rules else None),
        "status": ("ok" if n_rules else "no_rules_parsed"),
        "rules_analyzed": n_rules,
        "findings_total": len(findings),
        "findings_by_severity": _counts(findings),
        "findings": [
            {"rule_id": f.rule_id, "kind": f.kind, "severity": f.severity,
             "message": f.message, "rule": f.rule, "cited": f.cited, "fix": f.fix,
             "witness": f.witness, "line": f.line}
            for f in _sorted(findings)
        ],
        "parse_notes": notes,
    }, indent=2)


def to_text(findings: List[Finding], notes: List[str], n_rules: int,
            vendor: Optional[str] = None) -> str:
    _vendor = vendor or "ios-asa"
    if not n_rules:
        # Soundness: zero rules is NOT a clean bill of health. Make the
        # distinction explicit so the user cannot confuse "nothing parsed"
        # with "audited and found clean". Exit code 2 mirrors gate.py's
        # parse_failures path.
        out = ["=" * 64,
               " RuleHawk audit — NO ACL RULES PARSED",
               "=" * 64,
               "",
               " No ACL/firewall rules found — nothing was audited.",
               " This is NOT a clean result."]
        if _vendor == "ios-asa":
            # "ios-asa" is the fallback: no vendor was positively detected.
            out += [
                f" Detected: none of {_SUPPORTED_VENDORS}.",
                " Check you pasted the config itself, not a description or JSON export.",
            ]
        else:
            # A vendor WAS detected but the config had no parseable rules.
            out += [
                f" Detected format: {_vendor} — but no ACL/firewall rules were parsed.",
                f" Supported: {_SUPPORTED_VENDORS}.",
            ]
        if notes:
            out.append("")
            out.append(f" Parse notes ({len(notes)}):")
            out += _note_lines(notes)
        return "\n".join(out)
    sc = score(findings)
    counts = _counts(findings)
    lines: List[str] = []
    lines.append("=" * 64)
    lines.append(f" RuleHawk audit — {n_rules} rules analyzed")
    lines.append(f" Hygiene score: {sc}/100   "
                 + "  ".join(f"{k}:{counts[k]}" for k in
                             ("critical", "high", "medium", "low")))
    lines.append("=" * 64)
    if not findings:
        # Explicit: distinguish "0 findings with N rules analyzed" from "nothing
        # parsed". The header already carries the rule count; this line names the
        # vendor so the operator knows what format was actually audited.
        lines.append(
            f"\n  0 findings — {n_rules} rules analyzed ({_vendor}): policy is clean."
        )
    for f in _sorted(findings):
        lines.append("")
        lines.append(f"[{f.severity.upper():8}] {f.kind}  ({f.rule_id})")
        lines.append(f"   rule : {f.rule}")
        if f.line:
            lines.append(f"   line : {f.line}")
        if f.cited:
            lines.append(f"   cause: {f.cited}")
        if f.witness:
            # Segmentation: the concrete provable packet (e.g.
            # "10.20.0.1 -> 10.10.0.1:445 (tcp)") — the machine-checkable
            # artifact an auditor pastes into a ticket or packet-tracer.
            # Every other surface (JSON, SARIF, step summary, PR comment)
            # already shows it; the CLI text report must too.
            lines.append(f"   pkt  : {f.witness}")
        lines.append(f"   why  : {f.message}")
        if f.fix:
            lines.append(f"   fix  : {f.fix}")
    # Cleanup plan: the safe-to-delete (redundant) rules, collected. Both
    # redundancy kinds belong here — "redundant" (covered by ONE earlier
    # same-action rule) and "union-redundant" (covered by the UNION of several
    # earlier same-action rules); the union message literally says "safe to
    # remove", so omitting it would make the copy-into-ticket section
    # under-report what the engine already proved deletable.
    dead = [f for f in findings if f.kind in ("redundant", "union-redundant")]
    if dead:
        lines.append("")
        lines.append("-" * 64)
        lines.append(f" Cleanup plan: {len(dead)} redundant rule(s) safe to remove:")
        for f in dead:
            # Include the config file line when known so the operator can apply
            # the deletion without grepping the config by hand.
            loc = f" (line {f.line})" if f.line else ""
            lines.append(f"   - {f.rule_id}{loc}: {f.rule}")
    if notes:
        lines.append("")
        lines.append(f" Parse notes ({len(notes)} line(s) — resolved expansions "
                     f"and lines not fully modeled):")
        lines += _note_lines(notes)
    return "\n".join(lines)


def _sorted(findings: List[Finding]) -> List[Finding]:
    # Numeric-aware within a severity: `EDGE:10` sorts after `EDGE:2`.
    def key(f: Finding):
        acl, _, seq = f.rule_id.rpartition(":")
        if seq.isdigit():
            return (_ORDER.get(f.severity, 9), acl, int(seq))
        return (_ORDER.get(f.severity, 9), f.rule_id, 0)
    return sorted(findings, key=key)


def _counts(findings: List[Finding]) -> Dict[str, int]:
    c = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c
