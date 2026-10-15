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


def _run(tmp_path, results: str, expect: str, jobs: str = ""):
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    return _run_invocation(_manifest(), {"expect": expect, "results": results,
                                         "jobs": jobs},
                           str(runner), str(tmp_path), action_path=_DIR)


def test_manifest_wiring():
    a = _manifest()
    assert a["runs"]["using"] == "composite"
    assert a["inputs"]["expect"].get("required") is True, \
        "expect must be required: without it a missing job cannot be noticed"
    assert a["inputs"]["jobs"].get("required") is True, \
        "jobs must be required: without it a stale re-run PASS cannot be noticed"
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


@needs_node_and_bash
def test_a_gate_job_that_failed_without_a_failing_result_is_unknown(tmp_path):
    import json
    d = tmp_path / "results"
    d.mkdir()
    for job, label in (("egress", "Egress"), ("segmentation", "Segmentation")):
        os.environ["GITHUB_JOB"] = job
        try:
            gate.main([os.path.join(_S, "adv_realistic.txt"), "--policy",
                       os.path.join(_S, "policy.json"), "--label", label,
                       "--result", str(d / f"{job}.json"), "-q"])
        finally:
            os.environ.pop("GITHUB_JOB", None)
    jobs = json.dumps({"egress": {"result": "failure", "outputs": {}},
                       "segmentation": {"result": "success", "outputs": {}}})
    run = _run(tmp_path, str(d), "2", jobs)
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"


def test_a_failed_upload_is_not_hidden_inside_the_gate_action():
    """If sharing the result fails, the job must fail: the combining job then
    sees a failed job with no failing result and says UNKNOWN."""
    with open(os.path.join(_ROOT, "action.yml"), encoding="utf-8") as fh:
        main = yaml.safe_load(fh)
    upload = [s for s in main["runs"]["steps"]
              if "upload-artifact" in str(s.get("uses", ""))]
    assert upload, "the gate action has no result upload step"
    assert not upload[0].get("continue-on-error"), \
        "a failed upload would leave the previous attempt's result standing"


@needs_node_and_bash
def test_a_pass_body_beside_a_failing_exit_is_never_posted(tmp_path):
    """Belt and braces: if combine ever wrote a PASS body yet exited non-zero,
    the posted comment must not read PASS."""
    action = _manifest()
    step = next(s for s in action["runs"]["steps"] if s.get("id") == "combine")
    stub = ("rh_stub() { printf '<!-- rulehawk-gate -->\\n## ✅ RuleHawk firewall gate: PASS\\n'"
            " > \"${BODY}\"; return 1; }\n")
    step["run"] = step["run"].replace("python3 -m rulehawk combine", "rh_stub")
    step["run"] = step["run"].replace("set -u\n", "set -u\n" + stub, 1)
    runner = tmp_path / "runner"
    runner.mkdir()
    run = _run_invocation(action, {"expect": "1", "results": str(tmp_path), "jobs": ""},
                          str(runner), str(tmp_path), action_path=_DIR)
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"
    body = open(run["outputs"]["combine"]["comment"], encoding="utf-8").read()
    assert "✅" not in body and "UNKNOWN" in body


@needs_node_and_bash
def test_a_second_invocation_does_not_overwrite_the_first_comment_file(tmp_path):
    """Two combining steps in one job: each one's comment-file output must
    still hold its own body after the other runs."""
    runner = tmp_path / "runner"
    runner.mkdir()
    fail = _results(tmp_path, ("ios_acl.txt", "Dirty"))
    first = _run_invocation(_manifest(), {"expect": "1", "results": fail, "jobs": ""},
                            str(runner), str(tmp_path), action_path=_DIR)
    (tmp_path / "results").rename(tmp_path / "results-first")
    clean = _results(tmp_path, ("adv_realistic.txt", "Clean"))
    second = _run_invocation(_manifest(), {"expect": "1", "results": clean, "jobs": ""},
                             str(runner), str(tmp_path), action_path=_DIR)
    assert first["outputs"]["combine"]["verdict"] == "FAIL"
    assert second["outputs"]["combine"]["verdict"] == "PASS"
    body = open(first["outputs"]["combine"]["comment"], encoding="utf-8").read()
    assert body.splitlines()[1].startswith("## ❌"), body


@needs_node_and_bash
def test_results_left_by_an_earlier_invocation_are_not_combined_again(tmp_path):
    """If this invocation's download fails, a record an earlier invocation
    downloaded must not stand in for it."""
    runner = tmp_path / "runner"
    runner.mkdir()
    stale = runner / "rulehawk-combine-in"
    stale.mkdir()
    gate.main([os.path.join(_S, "adv_realistic.txt"), "--policy",
               os.path.join(_S, "policy.json"), "--label", "Old",
               "--result", str(stale / "old.json"), "-q"])
    # results '' -> the download step (not executed here: as if it failed).
    run = _run_invocation(_manifest(), {"expect": "1", "results": "", "jobs": ""},
                          str(runner), str(tmp_path), action_path=_DIR)
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"
