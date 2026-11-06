"""Coverage and SARIF all-clear rows (design v2 section 3.1, v4 section 12
slice 2, errata R4-L2).

`coverage.state = complete` and an empty SARIF run are all-clear signals.
Until a file is certified, neither is given:
- the MCP coverage block is `partial` (or `incomplete`), never `complete`;
- every uncertified file gets one `rulehawk/uncertified` SARIF result, at
  level `note` (so a repo that blocks on warnings is not newly blocked;
  blocking stays with exit 3), with a fingerprint of the rule id and the file
  path only, so the alert does not churn between runs.
No file is certified in this release, so both hold on every config in every
dialect.
"""

from __future__ import annotations

import json
import os
import shutil

import pytest

from rulehawk import allclear, gate, mcp_server

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_S = os.path.join(_ROOT, "samples")
CLEAN = os.path.join(_S, "adv_realistic.txt")     # nothing flagged, every line modelled
DIRTY = os.path.join(_S, "ios_acl.txt")           # critical findings
POLICY = os.path.join(_S, "policy.json")
RULE = "rulehawk/uncertified"

_DESIGN = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")

# Every sample config, plus one config per dialect the samples lack.
_DIALECTS = sorted(
    os.path.join(_S, n) for n in os.listdir(_S)
    if n != "policy.json" and not n.startswith(".")
    and os.path.isfile(os.path.join(_S, n))) + [
    os.path.join(_DESIGN, "cfg", "j01_junos_except_inverts_source.conf"),
    os.path.join(_DESIGN, "cfg", "n01_nxos_unlisted_admin_state.cfg"),
    os.path.join(_DESIGN, "cfg", "p01_panos_object_named_like_literal.set"),
]
_EOS = ("! Command: show running-config\n"
        "ip access-list CORP-IN\n"
        "   10 permit tcp 10.0.0.0/8 any eq 22\n"
        "   20 deny ip any any\n")
_VENDORS = {"ios-asa", "junos", "panos", "iptables", "nxos", "eos", "aws-sg"}


def _policy():
    with open(POLICY, encoding="utf-8") as fh:
        return json.load(fh)


def _sarif(paths, pol=None):
    g = gate.run_gate(list(paths), pol, "high")
    return json.loads(gate.to_sarif(g, version="x"))["runs"][0]


def _uncertified(run):
    return [r for r in run["results"] if r["ruleId"] == RULE]


# --------------------------------------------------------------------------- #
# coverage.state
# --------------------------------------------------------------------------- #
def test_complete_is_an_all_clear_through_allclear():
    assert allclear.emit(allclear.COMPLETE) == "partial"
    assert allclear.emit(allclear.COMPLETE, cert=object()) == "partial"


@pytest.mark.parametrize("cfg", [CLEAN, DIRTY])
def test_fully_modelled_file_is_partial_not_complete(cfg):
    r = mcp_server.audit(cfg, POLICY)
    cov = r["coverage"]
    assert cov["files_with_unmodelled_lines"] == 0
    assert cov["state"] == "partial", cov
    assert cov["files_uncertified"] == cov["files_analysed"] == 1
    assert "certified" in cov["explanation"]


def test_no_coverage_block_is_complete_anywhere():
    for cfg in _DIALECTS:
        r = mcp_server.audit(cfg, "")
        assert r["coverage"]["state"] in ("partial", "incomplete"), cfg
        assert r["coverage"]["files_uncertified"] == r["coverage"]["files_analysed"]
        c = mcp_server.compare(cfg, cfg, "")
        for side in ("before", "after"):
            assert c["coverage"][side]["state"] in ("partial", "incomplete"), cfg


def test_unmodelled_lines_keep_their_own_explanation():
    cfg = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants",
                       "design", "cfg", "a02_ios_seq_reorder_permit_first.cfg")
    cov = mcp_server.audit(cfg, "")["coverage"]
    assert cov["files_with_unmodelled_lines"] == 1
    assert cov["state"] == "partial"
    assert "unmodelled_lines" in cov["explanation"]
    assert cov["files_uncertified"] == 1


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", _DIALECTS, ids=os.path.basename)
def test_every_file_in_every_dialect_gets_one_uncertified_note(cfg):
    run = _sarif([cfg])
    res = _uncertified(run)
    assert len(res) == 1, res
    r = res[0]
    assert r["level"] == "note"
    uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == gate._sarif_uri(cfg)
    assert r["partialFingerprints"] == {"ruleHawk/v2": f"{RULE}:{uri}"}
    rule = run["tool"]["driver"]["rules"][r["ruleIndex"]]
    assert rule["id"] == RULE
    assert rule["defaultConfiguration"]["level"] == "note"
    # A note, not a security alert: no security-severity.
    assert "security-severity" not in rule.get("properties", {})


def test_every_dialect_is_covered(tmp_path):
    eos = tmp_path / "arista.cfg"
    eos.write_text(_EOS, encoding="utf-8")
    g = gate.run_gate(_DIALECTS + [str(eos)], None, "high")
    assert {fr.vendor for fr in g.files} == _VENDORS
    run = json.loads(gate.to_sarif(g, version="x"))["runs"][0]
    assert len(_uncertified(run)) == len(g.files)
    cov = mcp_server.audit(str(eos), "")["coverage"]
    assert cov["state"] == "partial" and cov["files_uncertified"] == 1


def test_clean_file_sarif_is_not_empty():
    run = _sarif([CLEAN], _policy())
    assert [(r["ruleId"], r["level"]) for r in run["results"]] == [(RULE, "note")]


def test_findings_are_unchanged_and_the_note_comes_after_them():
    run = _sarif([DIRTY], _policy())
    ids = [r["ruleId"] for r in run["results"]]
    assert ids[-1] == RULE and ids.count(RULE) == 1
    assert len(ids) > 1


def test_one_note_per_file_in_a_multi_file_run(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("hostname r1\n", encoding="utf-8")
    run = _sarif([CLEAN, DIRTY, str(empty)], _policy())
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in _uncertified(run)]
    assert uris == [gate._sarif_uri(p) for p in (CLEAN, DIRTY, str(empty))]
    # The parse failure keeps its own error as well.
    assert "RH-PARSE-000" in {r["ruleId"] for r in run["results"]}
    rules = [x["id"] for x in run["tool"]["driver"]["rules"]]
    assert rules.count(RULE) == 1


def test_fingerprint_is_stable_across_runs_and_line_shifts(tmp_path):
    cfg = tmp_path / "acl.txt"
    shutil.copy(CLEAN, cfg)
    a = _uncertified(_sarif([str(cfg)]))[0]
    b = _uncertified(_sarif([str(cfg)]))[0]
    cfg.write_text("!\n! a comment shifts every line\n!\n"
                   + open(CLEAN, encoding="utf-8").read(), encoding="utf-8")
    c = _uncertified(_sarif([str(cfg)]))[0]
    assert a["partialFingerprints"] == b["partialFingerprints"] == c["partialFingerprints"]
    assert a["message"] == c["message"]


def test_uncertified_message_says_what_it_is():
    msg = _uncertified(_sarif([CLEAN]))[0]["message"]["text"]
    assert "not certified" in msg and "fail-closed stopgap" in msg
    assert "UNKNOWN" in msg
