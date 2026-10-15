"""`rulehawk combine`: one sticky comment for every check in a run.

The headline is the WORST verdict across the checks: FAIL beats UNKNOWN beats
PASS. A check that was expected but left no readable result is UNKNOWN, so a
crashed, cancelled or skipped job can never read as a pass.
"""

from __future__ import annotations

import json
import os

from rulehawk import combine, gate

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_S = os.path.join(_ROOT, "samples")
_POLICY = os.path.join(_S, "policy.json")
_DIRTY = os.path.join(_S, "ios_acl.txt")      # critical findings -> FAIL
_CLEAN = os.path.join(_S, "adv_realistic.txt")  # passes the policy


def _result(tmp_path, name, config, *, label=None, job="j", attempt="1") -> str:
    out = str(tmp_path / name)
    argv = [config, "--policy", _POLICY, "--result", out, "-q"]
    if label:
        argv += ["--label", label]
    env_before = dict(os.environ)
    os.environ["GITHUB_JOB"] = job
    os.environ["GITHUB_RUN_ATTEMPT"] = attempt
    try:
        gate.main(argv)
    finally:
        os.environ.clear()
        os.environ.update(env_before)
    return out


def _headline(body: str) -> str:
    return next(l for l in body.splitlines() if l.startswith("## "))


def test_gate_writes_a_result_record(tmp_path):
    p = _result(tmp_path, "r.json", _DIRTY)
    rec = json.load(open(p))
    assert rec["schema"] == "rulehawk.result/v1"
    assert rec["passed"] is False and rec["exit_code"] == 1
    assert rec["job"] == "j" and rec["attempt"] == 1
    # Default label names what was checked: the patterns and the policy.
    assert _DIRTY in rec["label"] and _POLICY in rec["label"]
    assert rec["markdown"].startswith("## ❌ RuleHawk firewall gate")


def test_one_result_renders_exactly_the_single_gate_comment(tmp_path):
    """Existing single-check users must see the comment they always saw."""
    p = _result(tmp_path, "r.json", _DIRTY)
    body, verdict = combine.render([p])
    g = gate.run_gate([_DIRTY], json.load(open(_POLICY)), "high", "auto")
    assert body == gate.comment_body(g)
    assert verdict == "FAIL"


def test_a_failing_check_beside_a_passing_one_heads_the_comment_with_fail(tmp_path):
    a = _result(tmp_path, "a.json", _CLEAN, label="segmentation")
    b = _result(tmp_path, "b.json", _DIRTY, label="egress")
    body, verdict = combine.render([a, b])
    assert verdict == "FAIL"
    assert body.startswith(gate._COMMENT_MARKER)
    head = _headline(body)
    assert "❌" in head and "FAIL" in head and "✅" not in head
    # Every check appears in the summary table with its own verdict.
    assert "| segmentation | ✅ PASS |" in body
    assert "| egress | ❌ FAIL" in body
    # The failing check's full report, witness packets included, is on the PR.
    assert "10.20.0.1 -> 10.10.0.1:445" in body


def test_two_passing_checks_pass(tmp_path):
    a = _result(tmp_path, "a.json", _CLEAN, label="one")
    b = _result(tmp_path, "b.json", _CLEAN, label="two")
    body, verdict = combine.render([a, b], expect=2)
    assert verdict == "PASS"
    assert "✅" in _headline(body) and "PASS" in _headline(body)


def test_a_missing_expected_check_is_unknown_never_pass(tmp_path):
    a = _result(tmp_path, "a.json", _CLEAN, label="one")
    b = _result(tmp_path, "b.json", _CLEAN, label="two")
    body, verdict = combine.render([a, b], expect=3)
    assert verdict == "UNKNOWN"
    head = _headline(body)
    assert "UNKNOWN" in head and "✅" not in head
    assert "expected 3" in body and "found 2" in body


def test_fail_outranks_unknown(tmp_path):
    a = _result(tmp_path, "a.json", _DIRTY, label="one")
    body, verdict = combine.render([a], expect=2)
    assert verdict == "FAIL"


def test_an_unreadable_result_is_unknown(tmp_path):
    a = _result(tmp_path, "a.json", _CLEAN, label="one")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    body, verdict = combine.render([a, str(bad)])
    assert verdict == "UNKNOWN"
    assert "bad.json" in body


def test_a_result_with_the_wrong_shape_is_unknown(tmp_path):
    a = _result(tmp_path, "a.json", _CLEAN, label="one")
    odd = tmp_path / "odd.json"
    odd.write_text(json.dumps({"schema": "rulehawk.result/v1", "passed": "yes"}))
    body, verdict = combine.render([a, str(odd)])
    assert verdict == "UNKNOWN"


def test_no_results_at_all_is_unknown(tmp_path):
    body, verdict = combine.render([str(tmp_path)])
    assert verdict == "UNKNOWN"
    assert "✅" not in _headline(body)


def test_a_directory_is_searched_recursively(tmp_path):
    d = tmp_path / "artifacts" / "job-a"
    d.mkdir(parents=True)
    _result(d, "a.json", _DIRTY, label="one")
    body, verdict = combine.render([str(tmp_path / "artifacts")])
    assert verdict == "FAIL"


def test_a_rerun_attempt_replaces_the_same_check_from_an_older_attempt(tmp_path):
    """Re-running a job writes a second result for the same check; only the
    newest attempt of that check counts. Other checks keep theirs."""
    old = _result(tmp_path, "old.json", _DIRTY, label="egress", job="e", attempt="1")
    new = _result(tmp_path, "new.json", _CLEAN, label="egress", job="e", attempt="2")
    seg = _result(tmp_path, "seg.json", _CLEAN, label="seg", job="s", attempt="1")
    body, verdict = combine.render([old, new, seg], expect=2)
    assert verdict == "PASS", body
    assert body.count("| egress |") == 1


def test_the_same_check_twice_in_one_attempt_is_kept_twice(tmp_path):
    """Two results with the same label in the SAME attempt (a matrix, say) are
    different runs, not a retry: both count, so neither can hide the other."""
    a = _result(tmp_path, "a.json", _CLEAN, label="same", job="m")
    b = _result(tmp_path, "b.json", _DIRTY, label="same", job="m")
    body, verdict = combine.render([a, b])
    assert verdict == "FAIL"


def test_an_oversized_comment_keeps_the_verdict_and_every_row(tmp_path):
    """GitHub rejects comments over 65,536 characters; a rejected update would
    leave the previous verdict standing. Trim the detail, never the verdict."""
    paths = []
    for i in range(40):
        paths.append(_result(tmp_path, f"r{i}.json", _DIRTY, label=f"check-{i}"))
    body, verdict = combine.render(paths)
    assert len(body) <= combine.MAX_COMMENT_CHARS
    assert verdict == "FAIL" and "FAIL" in _headline(body)
    for i in range(40):
        assert f"| check-{i} |" in body


def test_cli_exit_codes_and_comment_file(tmp_path):
    a = _result(tmp_path, "a.json", _CLEAN, label="one")
    b = _result(tmp_path, "b.json", _DIRTY, label="two")
    out = tmp_path / "c.md"
    assert combine.main([a, "--comment", str(out), "-q"]) == 0
    assert combine.main([a, b, "--comment", str(out), "-q"]) == 1
    assert out.read_text().startswith(gate._COMMENT_MARKER)
    assert combine.main([a, "--expect", "2", "--comment", str(out), "-q"]) == 2
    assert "UNKNOWN" in out.read_text()
    assert combine.main(["--expect", "x", a]) == 2


def test_cli_is_reachable_as_a_subcommand(tmp_path):
    from rulehawk import cli
    a = _result(tmp_path, "a.json", _DIRTY, label="one")
    assert cli.main(["combine", a, "-q"]) == 1


def _record(tmp_path, name, **over) -> str:
    """A hand-written result record, for the shapes the gate never writes."""
    rec = {"schema": "rulehawk.result/v1", "label": name, "job": "j", "attempt": 1,
           "passed": True, "exit_code": 0, "fail_on": "high", "worst": "none",
           "violations": 0, "parse_failures": 0,
           "markdown": "## ✅ RuleHawk firewall gate\n\n**PASS** — fine."}
    rec.update(over)
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps(rec))
    return str(p)


def test_a_boolean_exit_code_is_not_a_pass(tmp_path):
    p = _record(tmp_path, "boolcode", exit_code=False)
    assert combine.render([p])[1] == "UNKNOWN"


def test_a_pass_claim_with_findings_at_the_threshold_is_not_a_pass(tmp_path):
    p = _record(tmp_path, "liar", violations=3)
    assert combine.render([p])[1] == "UNKNOWN"


def test_a_pass_claim_with_unparsed_files_is_not_a_pass(tmp_path):
    p = _record(tmp_path, "unparsed", parse_failures=1)
    assert combine.render([p])[1] == "UNKNOWN"
    # ...except under the advisory threshold, which never blocks.
    q = _record(tmp_path, "advisory", parse_failures=1, fail_on="none")
    assert combine.render([q])[1] == "PASS"


def test_a_record_missing_its_counts_is_not_a_pass(tmp_path):
    p = _record(tmp_path, "bare")
    rec = json.load(open(p))
    del rec["violations"], rec["parse_failures"], rec["fail_on"]
    open(p, "w").write(json.dumps(rec))
    assert combine.render([p])[1] == "UNKNOWN"


def test_a_report_that_contradicts_its_verdict_is_unknown(tmp_path):
    """A FAIL record carrying a PASS report must not post that report."""
    p = _record(tmp_path, "mixed", passed=False, exit_code=1, violations=1)
    body, verdict = combine.render([p])
    assert verdict == "UNKNOWN"
    assert "✅" not in _headline(body)


def test_a_single_oversized_report_still_fits(tmp_path):
    big = "## ❌ RuleHawk firewall gate\n\n**FAIL** — x.\n\n" + ("- finding\n" * 30000)
    p = _record(tmp_path, "huge", passed=False, exit_code=1, violations=1, markdown=big)
    body, verdict = combine.render([p])
    assert len(body) <= combine.MAX_COMMENT_CHARS
    assert verdict == "FAIL" and "FAIL" in _headline(body)


def test_a_failed_gate_job_whose_results_show_no_failure_is_unknown(tmp_path):
    """Re-run: the job failed again but its new result never uploaded, so only
    the first attempt's PASS is left. The failed job makes that UNKNOWN."""
    old = _result(tmp_path, "old.json", _CLEAN, label="egress", job="egress")
    seg = _result(tmp_path, "seg.json", _CLEAN, label="seg", job="segmentation")
    needs = {"egress": {"result": "failure", "outputs": {}},
             "segmentation": {"result": "success", "outputs": {}}}
    body, verdict = combine.render([old, seg], expect=2, needs=needs)
    assert verdict == "UNKNOWN"
    assert "egress" in body and "failure" in body


def test_a_failed_job_that_reported_its_failure_is_plain_fail(tmp_path):
    bad = _result(tmp_path, "bad.json", _DIRTY, label="egress", job="egress")
    needs = {"egress": {"result": "failure"}}
    body, verdict = combine.render([bad], expect=1, needs=needs)
    assert verdict == "FAIL"
    assert "job egress" not in body


def test_a_failed_job_that_runs_no_rulehawk_check_is_ignored(tmp_path):
    ok = _result(tmp_path, "ok.json", _CLEAN, label="seg", job="segmentation")
    needs = {"segmentation": {"result": "success"}, "lint": {"result": "failure"}}
    assert combine.render([ok], expect=1, needs=needs)[1] == "PASS"


def test_cli_needs(tmp_path):
    old = _result(tmp_path, "old.json", _CLEAN, label="egress", job="egress")
    needs = json.dumps({"egress": {"result": "cancelled"}})
    assert combine.main([old, "--needs", needs, "-q"]) == 2
    assert combine.main([old, "--needs", "[1]", "-q"]) == 2
    assert combine.main([old, "--needs", "{nope", "-q"]) == 2


def test_a_record_without_a_valid_worst_severity_is_not_a_pass(tmp_path):
    p = _record(tmp_path, "noworst")
    rec = json.load(open(p))
    del rec["worst"]
    open(p, "w").write(json.dumps(rec))
    assert combine.render([p])[1] == "UNKNOWN"
    q = _record(tmp_path, "bogus", worst="catastrophic")
    assert combine.render([q])[1] == "UNKNOWN"


def test_a_fail_record_whose_report_says_pass_in_the_verdict_line_is_unknown(tmp_path):
    md = "## ❌ RuleHawk firewall gate\n\n**PASS** — no findings at or above `high`."
    p = _record(tmp_path, "mixed2", passed=False, exit_code=1, violations=1, markdown=md)
    body, verdict = combine.render([p])
    assert verdict == "UNKNOWN"
    assert "**PASS**" not in body


def test_a_check_skipped_on_a_rerun_does_not_keep_its_old_pass(tmp_path):
    """Attempt 1 ran checks A and B (both passed; the job then failed later).
    Attempt 2 ran only A. B's attempt-1 PASS is stale: it must not count."""
    a1 = _result(tmp_path, "a1.json", _CLEAN, label="A", job="j", attempt="1")
    b1 = _result(tmp_path, "b1.json", _CLEAN, label="B", job="j", attempt="1")
    a2 = _result(tmp_path, "a2.json", _CLEAN, label="A", job="j", attempt="2")
    body, verdict = combine.render([a1, b1, a2], expect=2)
    assert verdict == "UNKNOWN", body


def test_rerunning_one_matrix_leg_is_unknown_until_every_leg_reruns(tmp_path):
    """Matrix legs share a job id, so a leg that was not re-run cannot be told
    from a check that was skipped: the older results do not count, and the
    verdict is UNKNOWN (never a stale PASS) until the whole job re-runs."""
    a1 = _result(tmp_path, "a1.json", _CLEAN, label="egress", job="m", attempt="1")
    b1 = _result(tmp_path, "b1.json", _DIRTY, label="egress", job="m", attempt="1")
    a2 = _result(tmp_path, "a2.json", _CLEAN, label="egress", job="m", attempt="2")
    body, verdict = combine.render([a1, b1, a2], expect=2)
    assert verdict == "UNKNOWN", body


def test_a_single_report_at_the_limit_still_fits_once_posted(tmp_path):
    """The posted body ends with a newline; that newline counts."""
    head = "## ❌ RuleHawk firewall gate\n\n**FAIL** — x.\n\n"
    marker = "<!-- rulehawk-gate -->\n"
    pad = combine.GITHUB_COMMENT_LIMIT - combine._length(marker + head)
    p = _record(tmp_path, "edge", passed=False, exit_code=1, violations=1,
                markdown=head + "x" * pad)
    out = tmp_path / "c.md"
    combine.main([p, "--comment", str(out), "-q"])
    assert combine._length(out.read_text(encoding="utf-8")) <= combine.GITHUB_COMMENT_LIMIT


def test_a_single_report_that_fits_github_is_byte_identical(tmp_path):
    """Up to GitHub's limit the one-check comment is exactly the old one."""
    md = "## ❌ RuleHawk firewall gate\n\n**FAIL** — x.\n\n" + "x" * 64000
    p = _record(tmp_path, "fits", passed=False, exit_code=1, violations=1, markdown=md)
    body, verdict = combine.render([p])
    assert body == "<!-- rulehawk-gate -->\n" + md
    assert verdict == "FAIL"


def test_a_record_without_its_attempt_or_job_is_not_counted(tmp_path):
    """The re-run and failed-job rules key on attempt and job; a record that
    leaves either out cannot be placed, so it is UNKNOWN, not defaulted."""
    for field in ("attempt", "job"):
        p = _record(tmp_path, f"no-{field}")
        rec = json.load(open(p))
        del rec[field]
        open(p, "w").write(json.dumps(rec))
        assert combine.render([p])[1] == "UNKNOWN", field


def test_an_unwritable_summary_does_not_split_the_verdict_from_the_comment(tmp_path):
    """The step summary is a convenience. Failing to write it must not turn a
    PASS exit code into UNKNOWN while a PASS comment is posted (or vice versa):
    the exit code and the comment always say the same thing."""
    a = _result(tmp_path, "a.json", _CLEAN, label="one")
    out = tmp_path / "c.md"
    rc = combine.main([a, "--comment", str(out), "--summary", str(tmp_path), "-q"])
    body = out.read_text(encoding="utf-8")
    assert rc == 0 and "✅" in _headline(body)
