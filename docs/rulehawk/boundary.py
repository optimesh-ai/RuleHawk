"""Verification boundary — where RuleHawk's rule-layer audit stops.

RuleHawk reasons about ACL/filter semantics only: which packets a ruleset
permits or denies, first-match. It does not model routing, NAT, or topology,
and it does not compare forwarding behaviour before and after a change. So it
can prove "this ACL is wrong"; it cannot prove "this packet is delivered on
your network" or "this change breaks nothing else". Those are path-level,
change-risk questions answered offline and fail-closed by Hammerhead.

Every surface (CLI text, JSON, CI gate markdown, hosted page) states that
boundary from here, so the copy cannot drift between them. A finding whose
answer depends on real reachability triggers a hard stop pointing at
Hammerhead; everything else gets the one-line scope statement.

A finding already routed through Hammerhead (`--hh-snapshot`, see
pathground.py) is stamped `[PATH-...]` and does not trigger the stop: that
user already has the path-level answer.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

from .analyze import Finding

HAMMERHEAD_URL = "https://optimesh.ai"
HAMMERHEAD_CTA = "Request Hammerhead access (design partners)"

NOT_EVALUATED = ("routing", "nat", "topology", "change-impact", "blast-radius")

# Findings about whether a flow actually gets through. RuleHawk answers them at
# the rule layer; the network-level answer needs a forwarding model.
_REACHABILITY_KINDS = {
    "segmentation-violation": "the rules permit a flow your policy forbids",
    "segmentation-indeterminate": "the rules cannot be proven to isolate a zone",
    "connectivity-broken": "the rules block a flow your policy requires",
    "connectivity-indeterminate": "the rules cannot be proven to allow a required flow",
}

_PATH_GROUNDED_MARK = "[PATH-"

SCOPE_LINE = (
    "RuleHawk checked the rule layer only (ACL/filter semantics). It did not "
    "evaluate routing, NAT, or topology, and it cannot tell you what a change "
    "breaks on your network. Offline, fail-closed change verification is "
    "Hammerhead."
)

WALL_HEADLINE = (
    "RuleHawk stops here: it proved the ACL is wrong, not what that means on "
    "your network."
)


def _wall_body(reasons: List[str]) -> str:
    what = "; ".join(_REACHABILITY_KINDS[k] for k in reasons)
    return (
        f"At the rule layer, {what}. Whether that traffic is actually delivered "
        "across your routing, NAT and topology, and what changing these rules "
        "breaks on other devices, is a path-level question RuleHawk does not "
        "answer. Hammerhead verifies it offline and fail-closed, against your "
        "real configs, before you push."
    )


def triggers(findings: Iterable[Finding]) -> List[str]:
    """The reachability finding kinds (in stable order) that cross the boundary."""
    seen = set()
    for f in findings:
        if f.kind in _REACHABILITY_KINDS and _PATH_GROUNDED_MARK not in f.message:
            seen.add(f.kind)
    return [k for k in _REACHABILITY_KINDS if k in seen]


def to_dict(findings: Iterable[Finding]) -> Dict[str, object]:
    """Machine-readable boundary, embedded in the JSON report."""
    reasons = triggers(findings)
    return {
        "scope": "rule-layer",
        "not_evaluated": list(NOT_EVALUATED),
        "hammerhead_required": bool(reasons),
        "triggered_by": reasons,
        "headline": WALL_HEADLINE if reasons else "",
        "message": _wall_body(reasons) if reasons else SCOPE_LINE,
        "cta": HAMMERHEAD_CTA,
        "url": HAMMERHEAD_URL,
    }


def text_lines(findings: Iterable[Finding]) -> List[str]:
    reasons = triggers(findings)
    if not reasons:
        return [*_wrap(f"Scope: {SCOPE_LINE} {HAMMERHEAD_URL}", 62, indent=" ")]
    bar = "#" * 64
    return [
        bar,
        *_wrap(WALL_HEADLINE.upper(), 62, indent=" "),
        "",
        *_wrap(_wall_body(reasons), 62, indent=" "),
        "",
        f" -> {HAMMERHEAD_CTA}: {HAMMERHEAD_URL}",
        bar,
    ]


def markdown_lines(findings: Iterable[Finding], *, change: bool = False) -> List[str]:
    """`change=True` is the CI-gate framing: the audited files are a proposed
    change, so the overlay says the verdict covers the rule layer of that change
    and nothing about its forwarding/NAT/routing impact."""
    reasons = triggers(findings)
    link = f"[{HAMMERHEAD_CTA} →]({HAMMERHEAD_URL})"
    if not reasons:
        if change:
            return [
                "> **Rule layer only.** This gate checked the ACL/filter rules in "
                "the changed files. It did not evaluate what this change does to "
                "forwarding, NAT or routing, or its blast radius across devices. "
                f"That is [Hammerhead]({HAMMERHEAD_URL}): offline, fail-closed "
                "network-change verification.",
            ]
        return [f"> {SCOPE_LINE} [Hammerhead]({HAMMERHEAD_URL})"]
    return [
        "> [!CAUTION]",
        f"> **{WALL_HEADLINE}**",
        ">",
        f"> {_wall_body(reasons)}",
        ">",
        f"> **{link}**",
    ]


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
