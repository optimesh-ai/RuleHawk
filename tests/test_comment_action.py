"""optimesh-ai/RuleHawk/comment — the job that combines every check of a run.

Wiring checks like tests/test_action.py, plus the shipped steps executed the
way a runner does (see tests/test_sticky_comment_verdict.py for the harness).
"""

from __future__ import annotations

import os
import re

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML not installed")

from rulehawk import gate                                          # noqa: E402
from test_sticky_comment_verdict import (                          # noqa: E402
    _posted_body, _run_comment_script, _run_invocation, needs_node_and_bash)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DIR = os.path.join(_ROOT, "comment")
_MANIFEST = os.path.join(_DIR, "action.yml")
_S = os.path.join(_ROOT, "samples")


def _manifest() -> dict:
    with open(_MANIFEST, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _results(tmp_path, *specs) -> str:
    """Write one result record per (config, label) into a results directory."""
    d = tmp_path / "results"
    d.mkdir(exist_ok=True)
    for i, (config, label) in enumerate(specs):
        gate.main([os.path.join(_S, config), "--policy", os.path.join(_S, "policy.json"),
                   "--label", label, "--result", str(d / f"r{i}.json"), "-q"])
    return str(d)


def _run(tmp_path, results: str, expect: str):
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    return _run_invocation(_manifest(), {"expect": expect, "results": results},
                           str(runner), str(tmp_path), action_path=_DIR)


def test_manifest_wiring():
    a = _manifest()
    assert a["runs"]["using"] == "composite"
    assert a["inputs"]["expect"].get("required") is True, \
        "expect must be required: without it a missing job cannot be noticed"
    used = set(re.findall(r"inputs\.([\w-]+)", yaml.dump(a)))
    assert not used - set(a["inputs"]), used - set(a["inputs"])
    run = "\n".join(s.get("run", "") for s in a["runs"]["steps"])
    written = set(re.findall(r'echo "([a-z_]+)=', run))
    for name, spec in a["outputs"].items():
        key = re.search(r"steps\.[\w-]+\.outputs\.([\w-]+)", spec["value"]).group(1)
        assert key in written, f"output {name} reads {key!r}, which nothing writes"
    assert os.path.exists(os.path.join(_DIR, "sticky.js"))


def test_documented_inputs_match_the_manifest():
    doc = open(os.path.join(_ROOT, "docs", "github-action.md"), encoding="utf-8").read()
    assert "optimesh-ai/RuleHawk/comment" in doc
    for name in _manifest()["inputs"]:
        assert f"`{name}`" in doc, f"comment input {name!r} is undocumented"


@needs_node_and_bash
def test_a_failing_job_and_a_passing_job_combine_to_fail(tmp_path):
    res = _results(tmp_path, ("adv_realistic.txt", "Segmentation"),
                   ("ios_acl.txt", "Egress"))
    run = _run(tmp_path, res, "2")
    combine = run["outputs"]["combine"]
    assert combine["verdict"] == "FAIL"
    enforce = [v for k, v in run["outputs"].items() if k.startswith("_step")]
    assert enforce and enforce[-1]["__rc__"] == 1, "the step must fail on FAIL"
    env = run["comment_step_env"]
    body = _posted_body(_run_comment_script(env["__script__"], env, [], str(tmp_path)))
    head = next(l for l in body.splitlines() if l.startswith("## "))
    assert "FAIL" in head and "✅" not in head
    assert "| Segmentation | ✅ PASS |" in body and "| Egress | ❌ FAIL" in body


@needs_node_and_bash
def test_a_job_that_never_reported_makes_it_unknown(tmp_path):
    res = _results(tmp_path, ("adv_realistic.txt", "One"), ("adv_realistic.txt", "Two"))
    run = _run(tmp_path, res, "3")
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"
    enforce = [v for k, v in run["outputs"].items() if k.startswith("_step")]
    assert enforce[-1]["__rc__"] == 1


@needs_node_and_bash
def test_no_downloaded_results_is_unknown(tmp_path):
    run = _run(tmp_path, str(tmp_path / "nothing-here"), "1")
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"


@needs_node_and_bash
def test_a_bad_expect_value_is_unknown_not_pass(tmp_path):
    res = _results(tmp_path, ("adv_realistic.txt", "One"))
    run = _run(tmp_path, res, "two")
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"
    body = open(run["outputs"]["combine"]["comment"], encoding="utf-8").read()
    assert "UNKNOWN" in body and "✅" not in body


@needs_node_and_bash
def test_every_check_passing_passes(tmp_path):
    res = _results(tmp_path, ("adv_realistic.txt", "One"), ("adv_realistic.txt", "Two"))
    run = _run(tmp_path, res, "2")
    assert run["outputs"]["combine"]["verdict"] == "PASS"
    enforce = [v for k, v in run["outputs"].items() if k.startswith("_step")]
    assert enforce[-1]["__rc__"] == 0
