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
    assert p["default"] == "file-uncertified" and p["strict"] == "zone-placement-unpinned", p


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
    assert r["checker"] == "hole", r


def test_the_harness_writes_no_all_clear_word():
    rc, out, _ = _run()
    assert rc == 0
    for word in ("PASS", "VERIFIED", "NO_NEW_RISK"):
        assert word not in out, word
    # As values, not inside the reason codes `file-uncertified` and
    # `config-incomplete`.
    for word in ("certified", "complete"):
        assert not re.search(r"(?<![-\w])" + word + r"(?![-\w])", out), word


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
