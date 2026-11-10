"""#42 phase 2: the phase-2 harness (design v2 section 13, v4 section 11).

`scripts/shadow_harness.py` is a developer script. It runs every attack
file (the four EXPECTED tables, with the policy each row names) and the
three controls with RULEHAWK_SHADOW=1 in its own process, and prints the
shadow per-file list for both placement modes: the default blocking
reason and the strict one, the checker's agreement and its answer per
assertion, and the lists of files that would pass in each mode.

It is not shipped (the wheel packages only `rulehawk`), no Action calls
it, and it writes no all-clear word.
"""
from __future__ import annotations

import csv
import os
import re
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_ROOT, "scripts", "shadow_harness.py")
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_COLUMNS = ["file", "policy", "dialects", "grammar", "default", "strict", "would_pass",
            "checker_agrees", "checker", "engine"]


def _run(*args):
    env = {k: v for k, v in os.environ.items() if k != "RULEHAWK_SHADOW"}
    r = subprocess.run([sys.executable, _SCRIPT, *args], capture_output=True, text=True,
                       cwd=_ROOT, env=env)
    return r.returncode, r.stdout, r.stderr


def _expected_rows():
    out = []
    for name in sorted(os.listdir(_D)):
        if name.startswith("EXPECTED") and name.endswith(".tsv"):
            with open(os.path.join(_D, name), encoding="utf-8") as fh:
                out += [(r["file"], r["policy"]) for r in csv.DictReader(fh, delimiter="\t")]
    return out


def _table(out):
    lines = out.split("\n")
    start = lines.index("\t".join(_COLUMNS))
    rows = []
    for ln in lines[start + 1:]:
        if not ln:
            break
        rows.append(dict(zip(_COLUMNS, ln.split("\t"))))
    return rows


def test_the_harness_lists_every_attack_file_and_control_in_both_modes():
    rc, out, err = _run()
    assert rc == 0, err
    rows = _table(out)
    want = {f for f, _ in _expected_rows()} | {
        "controls/k00_base.conf", "controls/p00_base.set", "controls/i00_base.sh"}
    assert {r["file"] for r in rows} == want, sorted(want ^ {r["file"] for r in rows})
    assert len(rows) == len(want)
    for r in rows:
        assert r["default"] and r["strict"], r
        assert r["would_pass"] == "false", r
    by = {r["file"]: r for r in rows}
    k = by["controls/k00_base.conf"]
    assert k["checker_agrees"] == "true" and k["checker"] == "no-witness", k
    assert k["default"] == "file-uncertified", k
    p = by["controls/p00_base.set"]
    # The checker is indeterminate on PAN-OS while panos-any-meaning is
    # pending (review of #60-#62 r2, F60-5, merged from #58).
    assert p["default"] == "checker-disagrees" and p["strict"] == "zone-placement-unpinned", p
    assert p["checker"] == "indeterminate" and p["checker_agrees"] == "false", p


def test_the_harness_prints_the_would_pass_lists_and_counts_for_both_modes():
    rc, out, _ = _run()
    assert rc == 0
    assert "would pass (default placement): 0\n" in out, out
    assert "would pass (strict placement): 0\n" in out, out
    assert "blocking reasons (default placement):" in out
    assert "blocking reasons (strict placement):" in out


def test_the_harness_takes_named_files_and_a_policy():
    pol = os.path.join(_D, "pol", "v4_reach_ip.json")
    rc, out, err = _run("--policy", pol, os.path.join(_D, "controls", "i00_base.sh"))
    assert rc == 0, err
    (r,) = _table(out)
    # The checker is indeterminate on iptables while iptables-script-scope
    # is pending (review of #60-#62, F60-1, merged from #58).
    assert r["checker"] == "indeterminate", r


def _all_clear_hits(out):
    """The all-clear words in `out` (review of #60-#62, F61-1 and r2 R61-1).
    Only the exact reason codes `file-uncertified` and `config-incomplete`
    and the harness's own `would pass (` and `would_pass` are taken out.
    Then, in any case: certified, complete, verified, `"passed": true`, no
    new risk with any separator, and pass, passed, passes or accepted as a
    word (a letter, digit or `_` on either side is part of a name, such as
    `bypass` or `v4_ip_accepted`); and PASS, ACCEPTED and the check marks
    as written."""
    rest = out
    for exact in ("file-uncertified", "config-incomplete", "would pass (", "would_pass"):
        rest = rest.replace(exact, "")
    low = rest.lower()
    hits = [w for w in ("certified", "complete", "verified", '"passed": true') if w in low]
    hits += re.findall(r"(?i)no[-_ ]new[-_ ]risk", rest)
    hits += re.findall(r"(?i)(?<![a-z0-9_])(?:pass(?:ed|es)?|accepted)(?![a-z0-9_])", rest)
    hits += [w for w in ("PASS", "ACCEPTED", "\u2713", "\u2714", "\u2705") if w in rest]
    return hits


def test_the_harness_writes_no_all_clear_word():
    rc, out, _ = _run()
    assert rc == 0
    assert _all_clear_hits(out) == [], _all_clear_hits(out)


@pytest.mark.parametrize("text", [
    "file-certified", "certified-ok", "certified_ok", "fully_certified", "completed",
    "complete-match", "Certified", "CERTIFIED", "Complete", "ACCEPTED", "Verified",
    '"passed": true', '"Passed": True', "\u2713", "\u2714",
])
def test_the_all_clear_scan_catches_every_spelling(text):
    """Review of #60-#62, F61-1: the scan strips only the two exact reason
    codes, then scans case-insensitively."""
    assert _all_clear_hits("x " + text + " y"), text


def test_the_all_clear_scan_ignores_only_the_two_reason_codes():
    assert _all_clear_hits("file-uncertified config-incomplete") == []


@pytest.mark.parametrize("text", [
    "Pass", "Passed", "pass", "passed", "passes", "PASSED", "Accepted", "accepted",
    '"passed":true', "Pass: 0", "result: passed", "no new risk", "No-New-Risk",
    "NO_NEW_RISK", "no_new-risk", "\u2705",
])
def test_the_all_clear_scan_catches_mixed_case_and_compact_spellings(text):
    """Review of #60-#62 r2, R61-1."""
    assert _all_clear_hits("x " + text + " y"), text


@pytest.mark.parametrize("text", [
    "would pass (default placement): 0", "would pass (strict placement): 0", "would_pass",
    "bypass", "v4_ip_accepted", "g01_ios_accepted_violation_gate", "_iptables_nfqueue_bypass",
])
def test_the_all_clear_scan_ignores_the_harness_s_own_names(text):
    assert _all_clear_hits("x " + text + " y") == [], text


def test_the_harness_is_not_shipped_or_wired_into_an_action():
    with open(os.path.join(_ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        text = fh.read()
    assert 'packages = ["rulehawk"]' in text
    assert "shadow_harness" not in text
    for name in ("action.yml", os.path.join("comment", "action.yml")):
        path = os.path.join(_ROOT, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                assert "shadow_harness" not in fh.read(), name
    assert not os.path.exists(os.path.join(_ROOT, "rulehawk", "shadow_harness.py"))
