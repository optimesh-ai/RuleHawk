"""The verification boundary: RuleHawk audits the rule layer, says so, and
points at a forwarding model only when a finding actually needs one.

Every surface (CLI text, JSON, CI gate markdown and console, hosted page)
states the rule-layer scope. A live segmentation violation or a broken
must_reach flow adds one "next step" pointing at Hammerhead. Hygiene-only
results, indeterminate findings, accepted risks, and findings Hammerhead has
already path-grounded never mention it.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import boundary, gate  # noqa: E402
from rulehawk.analyze import Finding, analyze  # noqa: E402
from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.pathground import Reach, path_ground  # noqa: E402
from rulehawk.report import to_json, to_text  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HH = boundary.HAMMERHEAD_URL

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


def _accept(fs):
    acc = {"id": "R-1", "reason": "legacy SMB share, migrating Q4",
           "approved_by": "sec-lead@example.com", "expires": "2099-01-01"}
    return [dataclasses.replace(f, accepted=acc) for f in fs]


# --- what triggers the next step --------------------------------------------

def test_violation_triggers():
    _, _, fs = _findings(_LEAK, _POLICY)
    assert boundary.triggers(fs) == ["segmentation-violation"]


def test_connectivity_broken_triggers():
    f = Finding("x", "connectivity-broken", "high", "no ruleset permits it", "")
    assert boundary.triggers([f]) == ["connectivity-broken"]


def test_hygiene_only_does_not_trigger():
    _, _, fs = _findings(_HYGIENE_ONLY, _POLICY)
    assert fs and boundary.triggers(fs) == []


def test_indeterminate_does_not_trigger():
    """Indeterminate means an unmodeled rule form or a ruleset too large to
    search: the fix is at the rule, not in a forwarding model."""
    fs = [Finding("x", k, "medium", "review manually", "")
          for k in ("segmentation-indeterminate", "connectivity-indeterminate")]
    assert boundary.triggers(fs) == []


def test_accepted_findings_do_not_trigger():
    _, _, fs = _findings(_LEAK, _POLICY)
    assert boundary.triggers(_accept(fs)) == []


def test_path_grounded_findings_do_not_trigger():
    """Every Hammerhead verdict (confirmed, suppressed, inconclusive) means the
    user already has Hammerhead. Guards against pathground renaming a stamp."""
    _, _, fs = _findings(_LEAK, _POLICY)
    for verdict in Reach:
        grounded = path_ground(fs, lambda w, v=verdict: v)
        assert boundary.triggers(grounded) == [], verdict


# --- surfaces ---------------------------------------------------------------

def test_json_carries_facts_not_copy():
    aces, notes, fs = _findings(_LEAK, _POLICY)
    vb = json.loads(to_json(fs, notes, len(aces)))["verification_boundary"]
    assert vb == {"scope": "rule-layer",
                  "not_evaluated": ["routing", "nat", "topology", "change-impact"],
                  "needs_path_verification": True,
                  "triggered_by": ["segmentation-violation"]}

    aces, notes, fs = _findings(_HYGIENE_ONLY)
    vb = json.loads(to_json(fs, notes, len(aces)))["verification_boundary"]
    assert vb["needs_path_verification"] is False and vb["triggered_by"] == []


def test_text_report_next_step_after_findings_before_cleanup():
    cfg = _LEAK.replace(" deny ip any any",
                        " permit tcp host 10.20.0.5 host 10.10.0.5 eq 445\n"
                        " deny ip any any")
    aces, notes, fs = _findings(cfg, _POLICY)
    out = to_text(fs, notes, len(aces))
    assert "Scope: rule layer only" in out
    assert "Next: RuleHawk proved" in out and _HH in out
    assert (out.index("segmentation-violation") < out.index("Next:")
            < out.index("Cleanup plan"))


def _gate(tmp_path, cfg, policy=None):
    p = tmp_path / "edge.acl"
    p.write_text(cfg)
    return gate.run_gate([str(p)], policy, fail_on="high")


def test_gate_markdown_next_step_under_witness_table(tmp_path):
    md = gate.to_markdown(_gate(tmp_path, _LEAK, _POLICY))
    assert "Rule-layer audit: routing, NAT and topology are not evaluated." in md
    nxt = md.index("> **Next:**")
    assert md.index("### Segmentation violations") < nxt < md.index("<details>")
    assert f"[Hammerhead]({_HH})" in md
    assert "[!CAUTION]" not in md


def test_gate_console_next_only_when_triggered(tmp_path):
    out = gate.to_console(_gate(tmp_path, _LEAK, _POLICY))
    assert "SCOPE  : rule layer only" in out and "NEXT   :" in out
    clean = gate.to_console(_gate(tmp_path, _HYGIENE_ONLY))
    assert "SCOPE  : rule layer only" in clean and "NEXT" not in clean


def test_no_product_pointer_without_a_trigger(tmp_path):
    """The free tool does not advertise on every run: hygiene-only and
    accepted-risk results never mention Hammerhead on any surface."""
    aces, notes, fs = _findings(_HYGIENE_ONLY)
    _, _, leak = _findings(_LEAK, _POLICY)
    for findings in (fs, _accept(leak)):
        surfaces = [to_text(findings, notes, len(aces)),
                    to_json(findings, notes, len(aces))]
        assert all("Hammerhead" not in s and _HH not in s for s in surfaces)
    g = _gate(tmp_path, _HYGIENE_ONLY)
    assert "Hammerhead" not in gate.to_markdown(g) + gate.to_console(g)


def test_copy_does_not_overclaim():
    """Only claim what was proved; never claim to fix the network or prove
    blast radius."""
    f = [Finding("a", "segmentation-violation", "critical", "leak", ""),
         Finding("b", "connectivity-broken", "high", "blocked", "")]
    rendered = " ".join([boundary.SCOPE_LINE, *boundary.text_lines(f),
                         *boundary.markdown_lines(f)]).lower()
    for claim in ("fixes your network", "proves the blast radius",
                  "guarantee", "safe to push"):
        assert claim not in rendered


# --- hosted page ------------------------------------------------------------

def _index() -> str:
    with open(os.path.join(_ROOT, "docs", "index.html"), encoding="utf-8") as fh:
        return fh.read()


def test_hosted_page_panel_before_hygiene_findings():
    html = _index()
    render = html[html.index("function render(d, vendor)"):html.index("function notesHTML")]
    assert "vb.needs_path_verification" in render
    assert render.index("wallHTML(vb)") < render.index("rest.map(findingHTML)")


def test_hosted_page_panel_copy_covers_every_trigger():
    html = _index()
    copy = html[html.index("const WALL_COPY"):html.index("function wallHTML")]
    for kind in boundary._NEXT:
        assert f'"{kind}"' in copy


def test_hosted_page_ctas():
    html = _index()
    assert f'const HAMMERHEAD_URL     = "{_HH}"' in html
    assert "WAITLIST_URL" not in html and "Get updates" not in html
    for target in ("ci-gate", "hammerhead", "hammerhead-wall"):
        assert f'data-cta="{target}"' in html
    wall = html[html.index("function wallHTML"):html.index("function ctaHTML")]
    assert 'role="alert"' not in wall


def test_hosted_entrypoint_emits_the_boundary():
    """The page reads verification_boundary from the engine's JSON, so the
    hosted entrypoint (worker.js ANALYZE_PY) must produce it."""
    from test_hosted_parity import _analyze_py, _read, _run_hosted, _WORKER
    env = _run_hosted(_analyze_py(_read(_WORKER)), _LEAK, json.dumps(_POLICY))
    vb = env["report_json"]["verification_boundary"]
    assert vb["needs_path_verification"] is True
    assert vb["triggered_by"] == ["segmentation-violation"]
    assert "Next: RuleHawk proved" in env["report_text"]
