"""Verification boundary: where RuleHawk's rule-layer audit stops.

RuleHawk reasons about ACL/filter semantics only: which packets a ruleset
permits or denies, first-match. It does not model routing, NAT, or topology,
and it does not compare forwarding behaviour before and after a change. So it
can prove "this ruleset permits that packet"; it cannot prove the packet is
delivered on your network, or what a rule change breaks elsewhere. Those need
a forwarding model, which is what Hammerhead does.

Two tiers, deliberately quiet:

- Every report states the scope as a fact: rule layer only, routing/NAT/
  topology not evaluated. No product pointer.
- Only a finding whose real-world answer depends on forwarding adds a single
  "next step" pointing at Hammerhead: a live segmentation violation (is the
  witness delivered? what does tightening the rule break?) or a broken
  must_reach flow (what does the fix break?).

Deliberately NOT triggers:

- `*-indeterminate`: segcheck raises these for rule-layer imprecision (an
  unmodeled rule form, or a ruleset too large to search). The next step is
  fixing the rule, which a forwarding model does not do.
- accepted findings: the owner has recorded the risk (riskaccept.py);
  repeating a pointer on every run is noise.
- findings already run through Hammerhead path-grounding (pathground.py,
  confirmed or inconclusive): that user already has Hammerhead.

The JSON report carries only the facts (`to_dict`); the pitch copy lives in
the human-facing surfaces.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

from .analyze import Finding

HAMMERHEAD_URL = "https://optimesh.ai"

NOT_EVALUATED = ("routing", "nat", "topology", "change-impact")

SCOPE_LINE = ("Scope: rule layer only (ACL/filter semantics). Routing, NAT and "
              "topology were not evaluated.")

# Per-kind: what RuleHawk proved, and the forwarding question it leaves open.
_NEXT = {
    "segmentation-violation": (
        "RuleHawk proved the rules permit a flow your policy forbids. Whether "
        "that packet is actually delivered across routing and NAT, and what "
        "tightening the rule breaks elsewhere, needs a forwarding model."
    ),
    "connectivity-broken": (
        "RuleHawk proved the rules block a flow your policy requires. What the "
        "fix opens or breaks on other devices needs a forwarding model."
    ),
}

_HH_TAIL = "Hammerhead verifies that offline, before you push"

# Stamps pathground.py appends once Hammerhead has seen a witness.
# tests/test_boundary.py runs every Reach verdict through path_ground, so a
# renamed stamp fails there rather than silently re-enabling the pointer.
_PATH_GROUNDED_MARKS = ("[PATH-CONFIRMED]", "[PATH-GROUNDED]",
                        "[PATH-GROUNDING INDETERMINATE]")


def _path_grounded(f: Finding) -> bool:
    return any(m in f.message for m in _PATH_GROUNDED_MARKS)


def triggers(findings: Iterable[Finding]) -> List[str]:
    """Finding kinds (in stable order) whose answer needs a forwarding model."""
    seen = set()
    for f in findings:
        if f.kind in _NEXT and f.accepted is None and not _path_grounded(f):
            seen.add(f.kind)
    return [k for k in _NEXT if k in seen]


def next_step(findings: Iterable[Finding]) -> str:
    """The one-sentence handoff, or "" when nothing crosses the boundary."""
    reasons = triggers(findings)
    if not reasons:
        return ""
    return " ".join(_NEXT[k] for k in reasons)


def to_dict(findings: Iterable[Finding]) -> Dict[str, object]:
    """Machine-readable boundary for the JSON report. Facts only, no copy."""
    reasons = triggers(findings)
    return {
        "scope": "rule-layer",
        "not_evaluated": list(NOT_EVALUATED),
        "needs_path_verification": bool(reasons),
        "triggered_by": reasons,
    }


def text_lines(findings: Iterable[Finding]) -> List[str]:
    findings = list(findings)
    out = _wrap(SCOPE_LINE, 64, indent=" ")
    step = next_step(findings)
    if step:
        out += _wrap(f"Next: {step} {_HH_TAIL}: {HAMMERHEAD_URL}", 64, indent=" ")
    return out


def markdown_lines(findings: Iterable[Finding]) -> List[str]:
    """The CI-gate handoff: one blockquote, or nothing."""
    step = next_step(findings)
    if not step:
        return []
    return [f"> **Next:** {step} [Hammerhead]({HAMMERHEAD_URL}) verifies that "
            "offline, before merge."]


def _wrap(text: str, width: int, indent: str = "") -> List[str]:
    out: List[str] = []
    line = ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(indent + line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        out.append(indent + line)
    return out
