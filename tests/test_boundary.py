"""The verification boundary: RuleHawk audits the rule layer, then stops.

A reachability finding (segmentation violation, broken or indeterminate
must_reach/must_not_reach) must end in an explicit Hammerhead stop on every
surface: CLI text, JSON, CI gate markdown and console, and the hosted page.
Hygiene-only results carry a one-line scope statement instead. A finding that
Hammerhead has already path-grounded does not trigger the stop.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import boundary, gate  # noqa: E402
from rulehawk.analyze import Finding, analyze  # noqa: E402
from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.pathground import Reach, path_ground  # noqa: E402
from rulehawk.report import to_json, to_text  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_LEAK = """ip access-list extended EDGE
 permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445
 deny ip any any
"""
_HYGIENE_ONLY = """ip access-list extended EDGE
 permit tcp any any eq 3389
 deny ip any any
"""
_POLICY = {"zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
           "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                               "ports": [445]}]}


def _findings(cfg: str, policy=None):
    aces, notes = parse_acls(cfg)
    fs = analyze(aces)
    if policy:
        fs += check_segmentation(aces, policy)
    return aces, notes, fs


def test_violation_triggers_the_stop():
    _, _, fs = _findings(_LEAK, _POLICY)
    assert boundary.triggers(fs) == ["segmentation-violation"]


def test_hygiene_only_does_not_trigger():
    _, _, fs = _findings(_HYGIENE_ONLY, _POLICY)
    assert fs and boundary.triggers(fs) == []


def test_connectivity_broken_triggers():
    f = Finding("x", "connectivity-broken", "high", "no ruleset permits it", "")
    assert boundary.triggers([f]) == ["connectivity-broken"]


def test_path_grounded_findings_do_not_trigger():
    _, _, fs = _findings(_LEAK, _POLICY)
    confirmed = path_ground(fs, lambda w: Reach.REACHABLE)
    suppressed = path_ground(fs, lambda w: Reach.UNREACHABLE)
    assert boundary.triggers(confirmed) == []
    assert boundary.triggers(suppressed) == []


def test_json_report_carries_the_boundary():
    aces, notes, fs = _findings(_LEAK, _POLICY)
    vb = json.loads(to_json(fs, notes, len(aces)))["verification_boundary"]
    assert vb["scope"] == "rule-layer"
    assert vb["hammerhead_required"] is True
    assert vb["triggered_by"] == ["segmentation-violation"]
    assert vb["url"] == "https://optimesh.ai"
    assert {"routing", "nat", "topology"} <= set(vb["not_evaluated"])

    aces, notes, fs = _findings(_HYGIENE_ONLY)
    vb = json.loads(to_json(fs, notes, len(aces)))["verification_boundary"]
    assert vb["hammerhead_required"] is False and vb["triggered_by"] == []


def test_text_report_walls_after_findings_before_cleanup():
    aces, notes, fs = _findings(_LEAK, _POLICY)
    out = to_text(fs, notes, len(aces))
    assert "RULEHAWK STOPS HERE" in out
    assert "https://optimesh.ai" in out
    assert out.index("segmentation-violation") < out.index("RULEHAWK STOPS HERE")


def test_text_report_scope_line_when_not_walled():
    aces, notes, fs = _findings(_HYGIENE_ONLY)
    out = to_text(fs, notes, len(aces))
    assert "RULEHAWK STOPS HERE" not in out
    assert "rule layer only" in out and "https://optimesh.ai" in out


def _gate(tmp_path, cfg, policy=None):
    p = tmp_path / "edge.acl"
    p.write_text(cfg)
    return gate.run_gate([str(p)], policy, fail_on="high")


def test_gate_markdown_walls_after_witness_table(tmp_path):
    md = gate.to_markdown(_gate(tmp_path, _LEAK, _POLICY))
    assert "> [!CAUTION]" in md
    assert "(https://optimesh.ai)" in md
    wall = md.index("[!CAUTION]")
    assert md.index("### Segmentation violations") < wall < md.index("<details>")
    assert "Rule layer only" not in md


def test_gate_markdown_rule_layer_overlay_without_violation(tmp_path):
    md = gate.to_markdown(_gate(tmp_path, _HYGIENE_ONLY))
    assert "[!CAUTION]" not in md
    assert "**Rule layer only.**" in md
    assert "forwarding, NAT or routing" in md


def test_gate_console_states_scope_and_next_step(tmp_path):
    out = gate.to_console(_gate(tmp_path, _LEAK, _POLICY))
    assert "SCOPE  : rule layer only" in out
    assert "Hammerhead" in out and "https://optimesh.ai" in out
    clean = gate.to_console(_gate(tmp_path, _HYGIENE_ONLY))
    assert "SCOPE  : rule layer only" in clean and "NEXT" not in clean


def test_copy_never_overclaims():
    """RuleHawk must not claim to fix the network or prove blast radius."""
    f = Finding("x", "segmentation-violation", "critical", "leak", "")
    rendered = " ".join([
        boundary.SCOPE_LINE, boundary.WALL_HEADLINE,
        json.dumps(boundary.to_dict([f])),
        "\n".join(boundary.text_lines([f])),
        "\n".join(boundary.markdown_lines([f], change=True)),
    ]).lower()
    for claim in ("fixes your network", "proves the blast radius",
                  "guarantees", "safe to push"):
        assert claim not in rendered


def _index() -> str:
    with open(os.path.join(_ROOT, "docs", "index.html"), encoding="utf-8") as fh:
        return fh.read()


def test_hosted_page_renders_the_wall_before_hygiene_findings():
    html = _index()
    render = html[html.index("function render(d, vendor)"):html.index("function notesHTML")]
    assert "vb.hammerhead_required" in render
    assert render.index("wallHTML(vb)") < render.index("rest.map(findingHTML)")


def test_hosted_page_ctas_point_at_hammerhead_not_github_updates():
    html = _index()
    assert 'const HAMMERHEAD_URL     = "https://optimesh.ai"' in html
    assert "WAITLIST_URL" not in html and "Get updates" not in html
    assert 'data-cta="hammerhead-wall"' in html and 'data-cta="hammerhead"' in html


def test_hosted_entrypoint_emits_the_boundary():
    """The page reads verification_boundary from the engine's JSON, so the
    hosted entrypoint (worker.js ANALYZE_PY) must produce it."""
    from test_hosted_parity import _analyze_py, _read, _run_hosted, _WORKER
    env = _run_hosted(_analyze_py(_read(_WORKER)), _LEAK, json.dumps(_POLICY))
    vb = env["report_json"]["verification_boundary"]
    assert vb["hammerhead_required"] is True
    assert re.match(r"https://optimesh\.ai", vb["url"])
    assert "RULEHAWK STOPS HERE" in env["report_text"]


def test_accepted_violation_still_walls():
    """A risk acceptance owns the risk; it does not answer the path question."""
    _, _, fs = _findings(_LEAK, _POLICY)
    accepted = [dataclasses.replace(f, accepted={"id": "R-1"}) for f in fs]
    assert boundary.triggers(accepted) == ["segmentation-violation"]
