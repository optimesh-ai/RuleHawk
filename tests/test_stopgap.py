"""Fail-closed stopgap (0.4.1): PASS / VERIFIED are never emitted.

Until the fail-closed work lands, RuleHawk cannot back a pass on every config
it reads, so every surface reports a would-be pass as UNKNOWN, with reason
code `fail-closed-stopgap` and the message "fail-closed stopgap pending
soundness review". FAIL is unchanged. Exit codes: 1 FAIL, 2 parse failure or
invalid input, 3 UNKNOWN (precedence 2, then 1, then 3); 0 only for the
advisory `--fail-on none`.

One test (or a few) per surface: CLI text / --json / --evidence, gate exit
codes, JSON, markdown, PR comment, console, result record, SARIF, the GitHub
Action, `rulehawk combine` and the combining action, the MCP tools and the
hosted page. Then a token sweep over every output, and the FAIL-unchanged
check against tests/stopgap_fail_golden.json.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

from rulehawk import cli, combine, gate

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_S = os.path.join(_ROOT, "samples")
CLEAN = os.path.join(_S, "adv_realistic.txt")       # no finding at any level
DIRTY = os.path.join(_S, "ios_acl.txt")             # critical findings + violation
POLICY = os.path.join(_S, "policy.json")

CODE = "fail-closed-stopgap"
MESSAGE = "fail-closed stopgap pending soundness review"
REASONS = [{"code": CODE, "message": MESSAGE}]

# A config whose must_reach flow is fully permitted: before the stopgap this
# was `connectivity-ok` (a proof), now it is UNKNOWN like every other pass.
REACH_CFG = """ip access-list extended EDGE
 10 permit tcp 10.20.0.0 0.0.255.255 203.0.113.0 0.0.0.255 eq 443
 20 deny ip any any
"""
REACH_POLICY = {"zones": {"CORP": ["10.20.0.0/16"], "DMZ": ["203.0.113.0/24"]},
                "must_reach": [{"src": "CORP", "dst": "DMZ", "proto": "tcp",
                                "ports": [443]}]}


def _cli(args, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(args)
    return rc, out.getvalue()


@pytest.fixture
def reach(tmp_path):
    cfg = tmp_path / "reach.cfg"
    cfg.write_text(REACH_CFG)
    pol = tmp_path / "reach_policy.json"
    pol.write_text(json.dumps(REACH_POLICY))
    return str(cfg), str(pol)


# --------------------------------------------------------------------------- #
# single-file CLI
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pargs", [[], ["--policy", POLICY]])
def test_cli_clean_text_is_unknown_exit_3(pargs):
    rc, out = _cli([CLEAN] + pargs)
    assert rc == 3
    assert "VERDICT: UNKNOWN" in out
    assert CODE in out and MESSAGE in out
    assert "policy is clean" not in out


@pytest.mark.parametrize("pargs", [[], ["--policy", POLICY]])
def test_cli_clean_json_is_unknown_with_reason(pargs):
    rc, out = _cli([CLEAN, "--json"] + pargs)
    assert rc == 3
    d = json.loads(out)
    assert d["verdict"] == "UNKNOWN"
    assert d["reasons"] == REASONS


def test_cli_policy_assertions_are_unknown_findings_with_reason():
    rc, out = _cli([CLEAN, "--json", "--policy", POLICY])
    d = json.loads(out)
    kinds = [f["kind"] for f in d["findings"]]
    assert "segmentation-ok" not in kinds
    unk = [f for f in d["findings"] if f["kind"] == "segmentation-unknown"]
    assert len(unk) == 2                       # one per must_not_reach assertion
    for f in unk:
        assert f["verdict"] == "UNKNOWN" and f["reasons"] == REASONS
        assert MESSAGE in f["message"]


def test_cli_must_reach_proof_is_unknown(reach):
    cfg, pol = reach
    rc, out = _cli([cfg, "--json", "--policy", pol])
    assert rc == 3
    d = json.loads(out)
    kinds = [f["kind"] for f in d["findings"]]
    assert "connectivity-ok" not in kinds and "connectivity-unknown" in kinds
    f = next(f for f in d["findings"] if f["kind"] == "connectivity-unknown")
    assert f["verdict"] == "UNKNOWN" and f["reasons"] == REASONS
    assert f["witness"]                          # the permitted packet is still shown


def test_cli_fail_and_parse_failure_codes_are_unchanged(tmp_path):
    assert _cli([DIRTY, "--policy", POLICY])[0] == 1
    rc, out = _cli([DIRTY, "--json", "--policy", POLICY])
    assert rc == 1 and json.loads(out)["verdict"] == "FAIL"
    assert json.loads(out)["reasons"] == []
    empty = tmp_path / "empty.txt"
    empty.write_text("hostname r1\n")
    assert _cli([str(empty)])[0] == 2


def test_cli_evidence_claims_are_indeterminate_with_reason():
    rc, out = _cli([CLEAN, "--evidence", "--policy", POLICY])
    assert rc == 3
    art = json.loads(out)
    assert art["result"]["attestations_verified"] == 0
    assert art["attestations"]
    for a in art["attestations"]:
        assert a["status"] == "INDETERMINATE"
        assert a["reasons"] == REASONS
    for c in art["controls"]:
        assert c["status"] != "VERIFIED"


def test_cli_evidence_markdown_names_the_stopgap():
    rc, out = _cli([CLEAN, "--evidence-md", "--policy", POLICY])
    assert rc == 3
    assert "UNKNOWN" in out and CODE in out and MESSAGE in out
    assert "**PASS" not in out


# --------------------------------------------------------------------------- #
# gate: exit codes and every renderer
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fail_on", ["critical", "high", "medium", "low"])
@pytest.mark.parametrize("policy", [None, POLICY])
def test_gate_clean_exits_3_at_every_threshold(fail_on, policy):
    pol = json.load(open(POLICY)) if policy else None
    g = gate.run_gate([CLEAN], pol, fail_on)
    assert g.exit_code() == 3
    assert g.verdict == "UNKNOWN"
    assert g.passed is False


def test_gate_fail_on_none_exits_0_but_reports_unknown():
    g = gate.run_gate([CLEAN], json.load(open(POLICY)), "none")
    assert g.exit_code() == 0
    assert g.verdict == "UNKNOWN" and g.passed is False
    d = json.loads(gate.to_json(g))
    assert d["verdict"] == "UNKNOWN" and d["enforced"] is False
    assert d["reasons"] == REASONS and d["passed"] is False
    md = gate.to_markdown(g)
    assert md.splitlines()[0].startswith("## ❌ ")
    assert "**UNKNOWN (not enforced)**" in md and MESSAGE in md
    assert "VERDICT: UNKNOWN (not enforced" in gate.to_console(g)


def test_gate_exit_precedence_2_then_1_then_3(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("hostname r1\n")
    pol = json.load(open(POLICY))
    assert gate.run_gate([CLEAN, str(empty)], pol, "high").exit_code() == 2
    assert gate.run_gate([CLEAN, DIRTY, str(empty)], pol, "high").exit_code() == 2
    assert gate.run_gate([CLEAN, DIRTY], pol, "high").exit_code() == 1
    assert gate.run_gate([CLEAN], pol, "high").exit_code() == 3


def test_gate_main_returns_3_and_writes_unknown_everywhere(tmp_path, capsys):
    paths = {k: str(tmp_path / k) for k in
             ("out.sarif", "out.json", "comment.md", "summary.md", "result.json",
              "ev.json", "ev.md")}
    rc = gate.main([CLEAN, "--policy", POLICY,
                    "--sarif", paths["out.sarif"], "--json", paths["out.json"],
                    "--comment", paths["comment.md"], "--summary", paths["summary.md"],
                    "--result", paths["result.json"], "--evidence", paths["ev.json"],
                    "--evidence-md", paths["ev.md"]])
    console = capsys.readouterr().out
    assert rc == 3
    assert "VERDICT: UNKNOWN (exit 3" in console and MESSAGE in console
    d = json.load(open(paths["out.json"]))
    assert d["verdict"] == "UNKNOWN" and d["exit_code"] == 3
    assert d["passed"] is False and d["reasons"] == REASONS
    assert d["undecided_assertions"] == 2
    for name in ("comment.md", "summary.md"):
        md = open(paths[name]).read()
        lines = [l for l in md.splitlines() if l.strip() and not l.startswith("<!--")]
        assert lines[0].startswith("## ❌ "), lines[0]
        assert lines[1].startswith("**UNKNOWN**"), lines[1]
        assert CODE in lines[1] and MESSAGE in lines[1]
        assert "✅" not in md
    rec = json.load(open(paths["result.json"]))
    assert rec["exit_code"] == 3 and rec["passed"] is False
    assert rec["verdict"] == "UNKNOWN"
    sarif = json.load(open(paths["out.sarif"]))
    assert sarif["runs"][0]["results"] == []          # nothing failed, no "pass"
    ev = json.load(open(paths["ev.json"]))
    assert {a["status"] for a in ev["attestations"]} == {"INDETERMINATE"}


def test_gate_fail_run_is_unchanged_fail(tmp_path):
    rc = gate.main([DIRTY, "--policy", POLICY, "--json", str(tmp_path / "o.json"), "-q"])
    assert rc == 1
    d = json.load(open(tmp_path / "o.json"))
    assert d["verdict"] == "FAIL" and d["reasons"] == []
    md = gate.to_markdown(gate.run_gate([DIRTY], json.load(open(POLICY)), "high"))
    assert [l for l in md.splitlines() if l.strip()][1].startswith("**FAIL**")


# --------------------------------------------------------------------------- #
# GitHub Action (action.yml)
# --------------------------------------------------------------------------- #
try:
    import yaml
except ImportError:          # the Action checks need PyYAML (CI installs it)
    yaml = None
_BASH = shutil.which("bash")
needs_yaml = pytest.mark.skipif(yaml is None, reason="PyYAML not installed")


def _action(path=os.path.join(_ROOT, "action.yml")) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _step(action: dict, name: str) -> dict:
    return next(s for s in action["runs"]["steps"] if s.get("name") == name)


@needs_yaml
def test_action_declares_verdict_and_exit_code_outputs():
    outs = _action()["outputs"]
    assert "verdict" in outs and "exit-code" in outs
    assert "steps.gate.outputs.verdict" in outs["verdict"]["value"]
    assert "steps.gate.outputs.exit_code" in outs["exit-code"]["value"]
    assert "never" in outs["passed"]["description"].lower()


def _enforce(tmp_path, rc: str, fail_on: str, verdict: str):
    step = _step(_action(), "Enforce gate verdict")
    (tmp_path / "rulehawk.rc").write_text(rc + "\n")
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), RH_FAIL_ON=fail_on,
               RH_WORST="none", RH_VERDICT=verdict)
    return subprocess.run([_BASH, "-c", step["run"]], env=env,
                          capture_output=True, text=True)


@pytest.mark.skipif(not _BASH, reason="needs bash")
@needs_yaml
def test_action_exit_3_fails_the_check_with_a_stopgap_annotation(tmp_path):
    p = _enforce(tmp_path, "3", "high", "UNKNOWN")
    assert p.returncode == 1
    assert "::error title=RuleHawk gate UNKNOWN" in p.stdout
    assert CODE in p.stdout and MESSAGE in p.stdout
    assert "passed" not in p.stdout


@pytest.mark.skipif(not _BASH, reason="needs bash")
@needs_yaml
def test_action_fail_on_none_never_reads_as_passed(tmp_path):
    p = _enforce(tmp_path, "0", "none", "UNKNOWN")
    assert p.returncode == 0
    assert "::warning" in p.stdout and "UNKNOWN" in p.stdout
    assert "gate passed" not in p.stdout


@pytest.mark.skipif(not _BASH, reason="needs bash")
@needs_yaml
def test_action_end_to_end_clean_is_unknown(tmp_path):
    from test_sticky_comment_verdict import _run_invocation
    runner = tmp_path / "runner"
    runner.mkdir()
    run = _run_invocation(_action(), {"configs": CLEAN, "policy": POLICY,
                                      "upload-sarif": "false"},
                          str(runner), _ROOT)
    out = run["outputs"]["gate"]
    assert out["exit_code"] == "3"
    assert out["verdict"] == "UNKNOWN"
    assert out["passed"] == "false"
    enforce = [v for k, v in run["outputs"].items() if k.startswith("_step")]
    assert enforce[-1]["__rc__"] == 1


# --------------------------------------------------------------------------- #
# rulehawk combine + the combining action
# --------------------------------------------------------------------------- #
def _record(tmp_path, name, cfg, fail_on="high", label=None):
    d = tmp_path / "results"
    d.mkdir(exist_ok=True)
    gate.main([cfg, "--policy", POLICY, "--fail-on", fail_on, "--label", label or name,
               "--result", str(d / f"{name}.json"), "-q"])
    return str(d)


def test_combine_reads_exit_3_as_unknown(tmp_path, capsys):
    d = _record(tmp_path, "clean", CLEAN)
    checks = combine.collect([d])
    assert [c.verdict for c in checks] == ["UNKNOWN"]
    assert checks[0].reported
    assert MESSAGE in checks[0].detail
    body = tmp_path / "c.md"
    assert combine.main([d, "--comment", str(body), "-q"]) == 2
    text = body.read_text()
    assert "## ✅" not in text and "UNKNOWN" in text


def test_combine_fail_outranks_unknown(tmp_path):
    _record(tmp_path, "clean", CLEAN)
    d = _record(tmp_path, "dirty", DIRTY)
    assert combine.main([d, "-q"]) == 1


def test_combine_fail_on_none_is_unknown_not_enforced(tmp_path):
    d = _record(tmp_path, "adv", CLEAN, fail_on="none")
    checks = combine.collect([d])
    assert [c.verdict for c in checks] == ["UNKNOWN"] and not checks[0].enforced
    body = tmp_path / "c.md"
    vfile = tmp_path / "v.txt"
    assert combine.main([d, "--comment", str(body), "--verdict", str(vfile), "-q"]) == 0
    assert vfile.read_text().strip() == "UNKNOWN (not enforced)"
    assert "## ✅" not in body.read_text()


@pytest.mark.skipif(not (_BASH and shutil.which("node")), reason="needs node and bash")
@needs_yaml
def test_comment_action_clean_check_is_unknown_and_fails(tmp_path):
    from test_sticky_comment_verdict import _run_invocation
    d = _record(tmp_path, "clean", CLEAN)
    runner = tmp_path / "runner"
    runner.mkdir()
    cdir = os.path.join(_ROOT, "comment")
    run = _run_invocation(_action(os.path.join(cdir, "action.yml")),
                          {"expect": "1", "results": d, "jobs": ""},
                          str(runner), str(tmp_path), action_path=cdir)
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"
    enforce = [v for k, v in run["outputs"].items() if k.startswith("_step")]
    assert enforce[-1]["__rc__"] == 1


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #
def test_mcp_audit_is_unknown_with_reason():
    from rulehawk import mcp_server
    r = mcp_server.audit(CLEAN, POLICY)
    assert r["verdict"] == "UNKNOWN"
    assert r["reasons"] == REASONS and MESSAGE in r["verdict_reason"]
    assert r["segmentation_passed"] == []
    assert len(r["segmentation_unknown"]) == 2
    for u in r["segmentation_unknown"]:
        assert u["reasons"] == REASONS


def test_mcp_audit_without_policy_is_unknown():
    from rulehawk import mcp_server
    assert mcp_server.audit(CLEAN)["verdict"] == "UNKNOWN"


def test_mcp_compare_is_never_an_all_clear():
    from rulehawk import mcp_server
    r = mcp_server.compare(CLEAN, CLEAN, POLICY)
    assert r["verdict"] == "UNKNOWN"
    assert r["reasons"] == REASONS


def test_mcp_fail_is_unchanged():
    from rulehawk import mcp_server
    assert mcp_server.audit(DIRTY, POLICY)["verdict"] == "FAIL"


# --------------------------------------------------------------------------- #
# hosted page (docs/): the in-browser engine copy and its renderer
# --------------------------------------------------------------------------- #
def _hosted(cfg: str, pol: str = "") -> dict:
    from test_hosted_parity import _analyze_py, _read, _run_hosted
    return _run_hosted(_analyze_py(_read(os.path.join(_ROOT, "docs", "worker.js"))),
                       cfg, pol)


def test_hosted_report_is_unknown_with_reason():
    env = _hosted(open(CLEAN).read(), open(POLICY).read())
    rep = env["report_json"]
    assert rep["verdict"] == "UNKNOWN" and rep["reasons"] == REASONS
    assert "VERDICT: UNKNOWN" in env["report_text"]
    assert {a["status"] for a in env["evidence"]["attestations"]} == {"INDETERMINATE"}


def test_hosted_page_renders_unknown_never_a_pass():
    html = open(os.path.join(_ROOT, "docs", "index.html"), encoding="utf-8").read()
    render = html[html.index("function render(d, vendor)"):]
    render = render[:render.index("\n}\n")]
    assert "Segmentation holds" not in render
    assert "No issues found" not in render
    assert '"pass"' not in render
    assert "UNKNOWN" in render and "d.reasons" in render


# --------------------------------------------------------------------------- #
# token sweep: no output path emits PASS / VERIFIED / segmentation-ok /
# "no violation"
# --------------------------------------------------------------------------- #
# Pre-existing negated sentences that name the word only to deny it ("no PASS
# is given", "This is NOT a PASS"). They are removed before the sweep; each is
# an exact phrase, so a new positive PASS anywhere still fails the test.
NEGATIONS = (
)
BANNED = [re.compile(r"\bPASS\b"), re.compile(r"\bVERIFIED\b"),
          re.compile(r"segmentation-ok", re.I), re.compile(r"connectivity-ok", re.I),
          re.compile(r"no violation", re.I), re.compile(r"policy is clean", re.I),
          re.compile("✅")]


def _sweep(label: str, text: str):
    for n in NEGATIONS:
        text = text.replace(n, "")
    for pat in BANNED:
        m = pat.search(text)
        assert not m, (f"{label} emits {m.group(0)!r}: "
                       f"...{text[max(0, m.start() - 80):m.end() + 80]}...")


def _all_outputs(tmp_path, cfg, pol_path, pol_obj):
    pargs = ["--policy", pol_path] if pol_path else []
    out = {}
    for flag in ([], ["--json"], ["--evidence"], ["--evidence-md"]):
        out[f"cli {' '.join(flag) or 'text'}"] = _cli([cfg] + flag + pargs)[1]
    for fail_on in ("high", "none"):
        g = gate.run_gate([cfg], pol_obj, fail_on)
        out[f"gate json {fail_on}"] = gate.to_json(g)
        out[f"gate markdown {fail_on}"] = gate.to_markdown(g)
        out[f"gate comment {fail_on}"] = gate.comment_body(g)
        out[f"gate console {fail_on}"] = gate.to_console(g)
        out[f"gate sarif {fail_on}"] = gate.to_sarif(g, version="x")
        out[f"gate result {fail_on}"] = gate.to_result(g, "lbl")
        rd = tmp_path / f"res-{fail_on}"
        rd.mkdir(exist_ok=True)
        (rd / "r.json").write_text(gate.to_result(g, "lbl"))
        out[f"combine {fail_on}"] = combine.render([str(rd)])[0]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        gate.main([cfg] + pargs + ["--evidence-md", "-", "-q"])
    out["gate evidence-md"] = buf.getvalue()
    from rulehawk import mcp_server
    for fail_on in ("high", "none"):
        out[f"mcp audit {fail_on}"] = json.dumps(
            mcp_server.audit(cfg, pol_path or "", fail_on=fail_on))
        out[f"mcp compare {fail_on}"] = json.dumps(
            mcp_server.compare(cfg, cfg, pol_path or "", fail_on=fail_on))
    out["mcp list"] = json.dumps(mcp_server.list_findings(cfg, pol_path or ""))
    env = _hosted(open(cfg).read(), open(pol_path).read() if pol_path else "")
    out["hosted"] = json.dumps(env)
    return out


def _sweep_configs():
    cfgs = [os.path.join(_S, n) for n in sorted(os.listdir(_S))
            if n != "policy.json"]
    return cfgs


@pytest.mark.parametrize("cfg", _sweep_configs(), ids=os.path.basename)
@pytest.mark.parametrize("with_policy", [False, True], ids=["nopolicy", "policy"])
def test_no_output_path_emits_a_pass_token(tmp_path, cfg, with_policy):
    pol_path = POLICY if with_policy else ""
    pol_obj = json.load(open(POLICY)) if with_policy else None
    for label, text in _all_outputs(tmp_path, cfg, pol_path, pol_obj).items():
        _sweep(f"{os.path.basename(cfg)} [{label}]", text)


def test_no_output_path_emits_a_pass_token_on_a_must_reach_proof(tmp_path, reach):
    cfg, pol = reach
    for label, text in _all_outputs(tmp_path, cfg, pol, REACH_POLICY).items():
        _sweep(f"reach [{label}]", text)


def test_mcp_instructions_and_kind_help_name_no_pass():
    from rulehawk import mcp_server
    _sweep("mcp instructions", mcp_server.INSTRUCTIONS)
    _sweep("mcp supported_inputs", json.dumps(mcp_server.supported_inputs()))
    _sweep("gate kind help", json.dumps(gate._KIND_HELP))


# --------------------------------------------------------------------------- #
# FAIL is unchanged: findings, severities, witnesses, SARIF, failed claims,
# exit 1 / exit 2 — on every sample and fixture
# --------------------------------------------------------------------------- #
def test_fail_is_unchanged_on_every_sample_and_fixture():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from stopgap_fail_baseline import GOLDEN, collect
    golden = json.load(open(GOLDEN, encoding="utf-8"))
    now = collect()
    assert [(r["config"], r["policy"]) for r in now] == \
        [(r["config"], r["policy"]) for r in golden]
    for was, got in zip(golden, now):
        key = (was["config"], was["policy"])
        for field in ("findings", "failed_claims", "sarif_results",
                      "gate_violations"):
            assert got[field] == was[field], (key, field)
        for field in ("cli_exit", "gate_exit_high"):
            # 1 and 2 stay as they were; the only change is 0 -> 3.
            want = 3 if was[field] == 0 else was[field]
            assert got[field] == want, (key, field, was[field], got[field])
