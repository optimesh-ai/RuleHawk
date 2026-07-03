"""The hosted demo's sample flow must showcase the witness-packet story.

Segmentation witness packets are RuleHawk's flagship differentiator, but they
only appear if BOTH textareas are filled. This module guards the first-minute
experience of docs/index.html:

  1. Clicking "Load sample" pre-fills the config AND the segmentation policy and
     opens the (otherwise collapsed) policy panel — so a first-time visitor's
     very first Audit shows the red segmentation verdict with concrete witness
     packets, instead of hiding the feature inside a panel whose own "load
     sample policy" button is only reachable after the panel is already open.
  2. The standalone "load sample policy" button keeps working for users who
     opened the panel themselves.
  3. The shipped SAMPLE_ACL + SAMPLE_POLICY actually reproduce the story in the
     real engine: two CRITICAL segmentation violations with audit-grade
     witnesses (CORP -> PCI on tcp/445, DMZ -> PCI on ip), each carrying the
     offending source line. If someone edits either sample and breaks the demo,
     this fails at build time — the landing page never promises a proof the
     engine won't deliver.

Static assertions read the literal shipped JS (no hardcoded copies of the
samples); engine assertions run the same parse+segcheck pipeline the hosted
tool executes.
"""

from __future__ import annotations

import json
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_INDEX = os.path.join(_ROOT, "docs", "index.html")


def _read_index() -> str:
    with open(_INDEX, encoding="utf-8") as fh:
        return fh.read()


def _js_literal(html: str, name: str) -> str:
    m = re.search(rf"const {name} = `([^`]*)`", html)
    assert m, f"{name} template literal not found in index.html"
    return m.group(1)


def _handler(html: str, elem_id: str) -> str:
    """Extract the body of the `$(\"<id>\").addEventListener(\"click\", ...)`
    arrow handler as shipped."""
    m = re.search(
        rf'\$\("{elem_id}"\)\.addEventListener\("click",\s*\(\)\s*=>\s*(\{{.*?\}}|[^;]*)\);',
        html, re.S)
    assert m, f'click handler for #{elem_id} not found in index.html'
    return m.group(1)


# --------------------------------------------------------------------------- #
# 1. UI wiring: the sample flow assembles the whole demo
# --------------------------------------------------------------------------- #
def test_load_sample_prefills_policy_and_opens_panel():
    body = _handler(_read_index(), "sample")
    assert "SAMPLE_ACL" in body, "sample no longer loads the config"
    assert "SAMPLE_POLICY" in body, (
        "Load sample must also pre-fill the segmentation policy — otherwise the "
        "witness-packet story is undiscoverable from the primary demo flow")
    assert '$("policy").value' in body
    assert re.search(r'\.open\s*=\s*true', body), (
        "Load sample must open the collapsed policy <details> so the user can "
        "see what was loaded")


def test_load_sample_status_mentions_witness_story():
    body = _handler(_read_index(), "sample")
    assert "witness packet" in body, (
        "the sample-loaded status line should tell the user what Audit will prove")


def test_standalone_sample_policy_button_unchanged():
    html = _read_index()
    assert 'id="samplePolicy"' in html
    body = _handler(html, "samplePolicy")
    assert "SAMPLE_POLICY" in body and re.search(r'\.open\s*=\s*true', body)


def test_sample_button_is_outside_collapsed_details():
    """The entry point to the demo must be visible without expanding anything."""
    html = _read_index()
    sample_at = html.index('id="sample"')
    details_at = html.index("<details")
    assert sample_at < details_at, (
        '#sample ("Load sample") must live in the always-visible row, not inside '
        "the collapsed advanced panel")
    # ...while the policy textarea itself stays in the collapsible panel.
    assert details_at < html.index('id="policy"')


# --------------------------------------------------------------------------- #
# 2. engine truth: the shipped samples really produce the witness packets
# --------------------------------------------------------------------------- #
def test_sample_policy_is_valid_json_with_zones_and_assertions():
    policy = json.loads(_js_literal(_read_index(), "SAMPLE_POLICY"))
    assert set(policy["zones"]) >= {"PCI", "CORP"}
    assert policy["must_not_reach"], "sample policy must assert at least one rule"


def test_shipped_samples_reproduce_two_critical_witnesses():
    html = _read_index()
    aces, notes = parse_acls(_js_literal(html, "SAMPLE_ACL"))
    assert not notes, f"sample ACL must be fully modeled (no parse notes): {notes}"
    policy = json.loads(_js_literal(html, "SAMPLE_POLICY"))
    findings = check_segmentation(aces, policy)

    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert len(viol) == 2, (
        f"the demo promises two segmentation violations, engine produced "
        f"{[(f.kind, f.witness) for f in findings]}")
    assert all(f.severity == "critical" for f in viol)

    by_witness = {f.witness: f for f in viol}
    # CORP workstation reaching PCI on SMB — the forwardable screenshot.
    assert "10.20.0.1 -> 10.10.0.1:445 (tcp)" in by_witness
    # DMZ host reaching PCI on any IP protocol.
    assert "203.0.113.1 -> 10.10.0.1 (ip)" in by_witness

    # Audit-grade evidence: every witness is pinned to the offending rule + line.
    for f in viol:
        assert f.rule_id.startswith("EDGE_IN:")
        assert f.line > 0, "witness finding must carry the 1-based source line"

    # Fail-closed honesty: the demo never mixes a false PASS into the story.
    assert not any(f.kind == "segmentation-indeterminate" for f in findings)
