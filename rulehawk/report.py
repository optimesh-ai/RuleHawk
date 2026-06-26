"""Render analysis findings as a human report (text) or machine report (JSON)."""

from __future__ import annotations

import json
from typing import Dict, List

from .analyze import Finding, score

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Cap text output so a pathological config can't print thousands of lines, but
# NEVER silently drop: when we elide, we say how many remain and where to see
# them in full. Real ASA configs routinely carry hundreds of object-group lines,
# so the old hard `[:20]` truncation hid most of them (the JSON path was always
# complete) — a soundness regression for the "surface, never drop" promise.
_NOTES_CAP = 200


def _note_lines(notes: List[str]) -> List[str]:
    out = [f"   ! {n}" for n in notes[:_NOTES_CAP]]
    extra = len(notes) - _NOTES_CAP
    if extra > 0:
        out.append(f"   ... and {extra} more not shown — re-run with --json "
                   f"for the complete list.")
    return out


def to_json(findings: List[Finding], notes: List[str], n_rules: int) -> str:
    return json.dumps({
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
             "witness": f.witness}
            for f in _sorted(findings)
        ],
        "parse_notes": notes,
    }, indent=2)


def to_text(findings: List[Finding], notes: List[str], n_rules: int) -> str:
    if not n_rules:
        out = ["=" * 64,
               " RuleHawk audit — NO ACL RULES PARSED",
               "=" * 64,
               "",
               " Nothing was analyzed (this is NOT a clean bill of health).",
               " Check the input is a Cisco IOS extended ACL, ASA access-list,"
               " or Juniper Junos firewall filter."]
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
        lines.append("\n  No issues found. ✅")
    for f in _sorted(findings):
        lines.append("")
        lines.append(f"[{f.severity.upper():8}] {f.kind}  ({f.rule_id})")
        lines.append(f"   rule : {f.rule}")
        if f.cited:
            lines.append(f"   cause: {f.cited}")
        lines.append(f"   why  : {f.message}")
        if f.fix:
            lines.append(f"   fix  : {f.fix}")
    # Cleanup plan: the safe-to-delete (redundant) rules, collected.
    dead = [f for f in findings if f.kind == "redundant"]
    if dead:
        lines.append("")
        lines.append("-" * 64)
        lines.append(f" Cleanup plan: {len(dead)} redundant rule(s) safe to remove:")
        for f in dead:
            lines.append(f"   - {f.rule_id}: {f.rule}")
    if notes:
        lines.append("")
        lines.append(f" Parse notes ({len(notes)} line(s) not fully modeled):")
        lines += _note_lines(notes)
    return "\n".join(lines)


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (_ORDER.get(f.severity, 9), f.rule_id))


def _counts(findings: List[Finding]) -> Dict[str, int]:
    c = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c
