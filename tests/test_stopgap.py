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
import shlex
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
    # Nothing failed and nothing reads as a pass: the only result is the note
    # that the file is not certified (#42 phase 2 slice 2).
    assert [(r["ruleId"], r["level"]) for r in sarif["runs"][0]["results"]] == \
        [("rulehawk/uncertified", "note")]
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
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), RH_FAIL_ON=fail_on,
               RH_WORST="none", RH_VERDICT=verdict, RH_RC=rc)
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
# One use of the action, run step by step (reserve, gate, enforce): the
# per-invocation verdict and the documented FAIL-only recipe.
# --------------------------------------------------------------------------- #
_GH_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_SIM_STEPS = ("Reserve this check's result", "Run RuleHawk gate",
              "Enforce gate verdict")


def _gh_ctx(expr: str, inputs: dict, outs: dict) -> str:
    m = re.fullmatch(r"inputs\.([\w-]+)", expr)
    if m:
        return str(inputs.get(m.group(1), ""))
    m = re.fullmatch(r"steps\.([\w-]+)\.outputs\.([\w-]+)", expr)
    if m:
        return str(outs.get(m.group(1), {}).get(m.group(2), ""))
    return _ROOT if expr == "github.action_path" else ""


def _gh_resolve(value, inputs: dict, outs: dict) -> str:
    return _GH_EXPR.sub(lambda m: _gh_ctx(m.group(1), inputs, outs), str(value))


def _gh_outputs(path: str) -> dict:
    out, lines = {}, open(path, encoding="utf-8").read().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "<<" in line and "=" not in line.split("<<", 1)[0]:
            key, delim = line.split("<<", 1)
            j = lines.index(delim, i + 1)
            out[key] = "\n".join(lines[i + 1:j])
            i = j
        elif "=" in line:
            key, val = line.split("=", 1)
            out[key] = val
        i += 1
    return out


def _stub_bin(tmp_path) -> str:
    """A `python3` that is the real interpreter, except that with STUB_CRASH
    set `python3 -m rulehawk gate` dies like a traceback: exit 1, no JSON."""
    d = tmp_path / "stub-bin"
    if not d.exists():
        d.mkdir()
        py = d / "python3"
        py.write_text(
            "#!/bin/bash\n"
            'if [ -n "${STUB_CRASH:-}" ] && [ "$1" = "-m" ] && [ "$3" = "gate" ]; then\n'
            '  echo "Traceback (most recent call last): stub crash" >&2; exit 1\n'
            "fi\n"
            f'exec {shlex.quote(sys.executable)} "$@"\n')
        py.chmod(0o755)
    return str(d)


def _invoke(tmp_path, configs: str, fail_on: str, gate_mode: str = "run"):
    """Run one use of the action in a job whose RUNNER_TEMP is tmp_path/runner
    (shared by every use in the job, as on a real runner). gate_mode: `run`;
    `skip` (an earlier step such as setup-python failed, so the gate step never
    ran but the always() enforce step does); `abort` (the gate step dies before
    RuleHawk runs); `crash` (RuleHawk exits 1 with no JSON). Returns (step
    outputs by id, {step name: CompletedProcess})."""
    action = _action()
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    inputs = {k: str(v.get("default", "")) for k, v in action["inputs"].items()}
    inputs.update({"configs": configs, "fail-on": fail_on})
    outs: dict = {}
    procs: dict = {}
    for i, step in enumerate(action["runs"]["steps"]):
        name = step.get("name")
        if name not in _SIM_STEPS or "run" not in step:
            continue
        if name == "Run RuleHawk gate" and gate_mode == "skip":
            continue
        sid = step.get("id") or f"_step{i}"
        out_file = tmp_path / f"out-{len(list(tmp_path.glob('out-*')))}"
        out_file.write_text("")
        env = dict(os.environ)
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.update({k: _gh_resolve(v, inputs, outs)
                    for k, v in (step.get("env") or {}).items()})
        env.update(RUNNER_TEMP=str(runner), GITHUB_OUTPUT=str(out_file),
                   GITHUB_JOB="gate-job",
                   PATH=_stub_bin(tmp_path) + os.pathsep + env.get("PATH", ""))
        if name == "Run RuleHawk gate" and gate_mode == "abort":
            env.pop("RH_CONFIGS", None)        # unbound under `set -u`
        if name == "Run RuleHawk gate" and gate_mode == "crash":
            env["STUB_CRASH"] = "1"
        procs[name] = subprocess.run([_BASH, "-c", step["run"]], cwd=str(tmp_path),
                                     env=env, capture_output=True, text=True)
        outs[sid] = _gh_outputs(str(out_file))
    return outs, procs


@pytest.mark.skipif(not _BASH, reason="needs bash")
@needs_yaml
@pytest.mark.parametrize("gate_mode", ["skip", "abort"])
@pytest.mark.parametrize("fail_on", ["high", "medium", "none"])
def test_action_second_use_never_reads_the_first_ones_verdict(tmp_path, gate_mode,
                                                              fail_on):
    # Two RuleHawk steps in one job share RUNNER_TEMP. The first one runs
    # (advisory, so it records exit 0); the second one's gate step is skipped
    # or aborts. Its enforce step must not pick up the first one's verdict.
    _, first = _invoke(tmp_path, CLEAN, "none")
    assert first["Enforce gate verdict"].returncode == 0
    _, second = _invoke(tmp_path, CLEAN, fail_on, gate_mode)
    p = second["Enforce gate verdict"]
    assert p.returncode == 1, p.stdout
    assert "::error title=RuleHawk gate did not complete" in p.stdout
    assert "exited 0" not in p.stdout


def _gh_if(expr: str, ctx: dict) -> bool:
    """Evaluate a GitHub `if:` expression built from ==, !=, &&, ||, !, (),
    'string' literals and context names (the subset the docs use)."""
    m = _GH_EXPR.fullmatch(expr.strip())
    expr = m.group(1) if m else expr
    toks = re.findall(r"'[^']*'|==|!=|&&|\|\||!|\(|\)|[A-Za-z_][\w.-]*", expr)
    assert "".join(toks) == re.sub(r"\s+", "", expr), expr   # all tokenised
    py = []
    for t in toks:
        if t in ("&&", "||", "!"):
            py.append({"&&": " and ", "||": " or ", "!": " not "}[t])
        elif t in ("==", "!=", "(", ")"):
            py.append(t)
        elif t.startswith("'"):
            py.append(repr(t[1:-1]))
        elif t in ("true", "false"):
            py.append(t.title())
        else:
            assert t in ctx, f"recipe reads {t}, which the action does not set"
            py.append(repr(ctx[t]))
    return bool(eval("".join(py), {"__builtins__": {}}))   # noqa: S307


def _doc_recipes():
    """Every workflow snippet in the changelog and docs that gates on a
    RuleHawk step's outputs (`steps.rh.`)."""
    found = []
    for rel in ["CHANGELOG.md"] + sorted(
            os.path.join("docs", f) for f in os.listdir(os.path.join(_ROOT, "docs"))
            if f.endswith(".md")):
        text = open(os.path.join(_ROOT, rel), encoding="utf-8").read()
        for block in re.findall(r"```ya?ml\n(.*?)```", text, re.S):
            if "steps.rh." in block:
                found.append((rel, block))
    return found


_RECIPE_CASES = {
    # case: (config, gate_mode, should the job fail?)
    "setup failure": ("CLEAN", "skip", True),
    "gate did not complete": ("CLEAN", "abort", True),
    "exit 1 with JSON": ("DIRTY", "run", True),
    "exit 1, no JSON (crash)": ("CLEAN", "crash", True),
    "exit 2 (zero rules parsed)": ("JUNK", "run", True),
    "exit 3 (UNKNOWN)": ("CLEAN", "run", False),
}


@pytest.mark.skipif(not _BASH, reason="needs bash")
@needs_yaml
@pytest.mark.parametrize("case", sorted(_RECIPE_CASES))
def test_documented_fail_only_recipe_blocks_everything_but_unknown(tmp_path, case):
    recipes = _doc_recipes()
    assert recipes, "the FAIL-only recipe is documented in CHANGELOG.md"
    junk = tmp_path / "junk.txt"
    junk.write_text("this is not a firewall config\n")
    cfg_name, gate_mode, should_fail = _RECIPE_CASES[case]
    cfg = {"CLEAN": CLEAN, "DIRTY": DIRTY, "JUNK": str(junk)}[cfg_name]
    action_outputs = _action()["outputs"]
    for rel, block in recipes:
        steps = yaml.safe_load(block)
        rh = next(s for s in steps if s.get("id") == "rh")
        assert rh.get("continue-on-error") is True, rel
        job = tmp_path / f"job-{len(list(tmp_path.glob('job-*')))}"
        job.mkdir()
        outs, procs = _invoke(job, cfg, str(rh["with"].get("fail-on", "high")),
                              gate_mode)
        if case.startswith("exit "):
            assert outs["gate"]["exit_code"] == case.split()[1].rstrip(","), outs
        outcome = ("failure" if any(p.returncode for p in procs.values())
                   else "success")
        ctx = {"steps.rh.outcome": outcome, "steps.rh.conclusion": "success"}
        for name, spec in action_outputs.items():
            ctx[f"steps.rh.outputs.{name}"] = _gh_resolve(spec["value"], {}, outs)
        job_fails = any(_gh_if(s["if"], ctx) and "exit 1" in str(s.get("run", ""))
                        for s in steps if s.get("id") != "rh" and "if" in s)
        assert job_fails == should_fail, (rel, case, outcome, ctx)


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


# Result records a 0.4.0 gate really wrote (tests/fixtures/stopgap/, made by
# `rulehawk gate --result` on the v0.4.0 tree, 28bc79d): a workflow whose gate
# steps are pinned to an older ref, or a cached result artifact, hands these to
# a 0.4.1 combine. Their `passed: true` and "## ✅ ... **PASS**" body must never
# come back out as a PASS.
_LEGACY = os.path.join(_ROOT, "tests", "fixtures", "stopgap")


def _legacy_dir(tmp_path, *names):
    d = tmp_path / "legacy"
    d.mkdir(exist_ok=True)
    for n in names:
        shutil.copy(os.path.join(_LEGACY, n), str(d / n))
    return str(d)


@pytest.mark.parametrize("name", ["gate040_clean_high.json", "gate040_clean_none.json"])
def test_combine_reads_a_pre_stopgap_pass_record_as_unknown(tmp_path, capsys, name):
    rec = json.load(open(os.path.join(_LEGACY, name)))
    assert rec["passed"] is True and rec["exit_code"] == 0       # a real 0.4.0 PASS
    d = _legacy_dir(tmp_path, name)
    checks = combine.collect([d])
    assert [c.verdict for c in checks] == ["UNKNOWN"]
    assert "pre-stopgap" in checks[0].detail and MESSAGE in checks[0].detail
    body, vfile = tmp_path / "c.md", tmp_path / "v.txt"
    rc = combine.main([d, "--comment", str(body), "--verdict", str(vfile)])
    out = capsys.readouterr().out
    assert rc == 2
    assert vfile.read_text().strip() == "UNKNOWN"
    text = body.read_text()
    assert "✅" not in text and "**PASS**" not in text
    assert "VERDICT: PASS" not in out
    _sweep(f"combine legacy {name}", text + out + vfile.read_text())


def test_combine_legacy_fail_record_stays_fail(tmp_path):
    d = _legacy_dir(tmp_path, "gate040_dirty_high.json", "gate040_clean_high.json")
    assert sorted(c.verdict for c in combine.collect([d])) == ["FAIL", "UNKNOWN"]
    assert combine.main([d, "-q"]) == 1


@pytest.mark.skipif(not (_BASH and shutil.which("node")), reason="needs node and bash")
@needs_yaml
def test_comment_action_legacy_pass_record_is_unknown_and_fails(tmp_path):
    from test_sticky_comment_verdict import _run_invocation
    d = _legacy_dir(tmp_path, "gate040_clean_high.json")
    runner = tmp_path / "runner"
    runner.mkdir()
    cdir = os.path.join(_ROOT, "comment")
    run = _run_invocation(_action(os.path.join(cdir, "action.yml")),
                          {"expect": "1", "results": d, "jobs": ""},
                          str(runner), str(tmp_path), action_path=cdir)
    assert run["outputs"]["combine"]["verdict"] == "UNKNOWN"
    body = open(run["outputs"]["combine"]["comment"]).read()
    assert "✅" not in body and "**PASS**" not in body
    enforce = [v for k, v in run["outputs"].items() if k.startswith("_step")]
    assert enforce[-1]["__rc__"] == 1


def _combine_step(tmp_path, rc: int, verdict_line: str, body: str) -> dict:
    """Run the comment action's combine step with `python3` stubbed to exit
    `rc` after writing `body` and `verdict_line` (the only two inputs the
    step's verdict mapping reads), and return the step's outputs."""
    step = _step(_action(os.path.join(_ROOT, "comment", "action.yml")),
                 "Combine every check")
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "python3").write_text(
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do case \"$1\" in --comment) C=\"$2\";; "
        "--verdict) V=\"$2\";; esac; shift; done\n"
        f"printf '%s' {json.dumps(body)} > \"$C\"\n"
        f"printf '%s' {json.dumps(verdict_line)} > \"$V\"\n"
        f"exit {rc}\n")
    os.chmod(str(stub / "python3"), 0o755)
    out = tmp_path / "out"
    out.write_text("")
    env = dict(os.environ, PATH=f"{stub}:{os.environ['PATH']}",
               RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(out),
               RH_EXPECT="1", RH_NEEDS="{}", RH_RESULTS=str(tmp_path))
    subprocess.run([_BASH, "-c", step["run"]], env=env, check=True,
                   capture_output=True, text=True)
    return dict(l.split("=", 1) for l in out.read_text().splitlines() if "=" in l)


@pytest.mark.skipif(not _BASH, reason="needs bash")
@needs_yaml
@pytest.mark.parametrize("verdict_line", ["", "PASS"])
def test_comment_action_exit_0_never_maps_to_pass(tmp_path, verdict_line):
    """combine's exit 0 with no verdict file, or one that says PASS, is the
    old PASS path. This release never reports PASS: it fails closed."""
    o = _combine_step(tmp_path, 0, verdict_line, "<!-- rulehawk-gate -->\n## ❌ x\n")
    assert o["verdict"] == "UNKNOWN" and o["enforced"] == "UNKNOWN", o


@pytest.mark.skipif(not _BASH, reason="needs bash")
@needs_yaml
def test_comment_action_enforce_step_never_says_every_check_passed(tmp_path):
    step = _step(_action(os.path.join(_ROOT, "comment", "action.yml")),
                 "Enforce the combined verdict")
    for verdict, enforced, rc in (("PASS", "PASS", 1), ("UNKNOWN (not enforced)", "PASS", 0),
                                  ("UNKNOWN", "UNKNOWN", 1), ("FAIL", "FAIL", 1)):
        env = dict(os.environ, RH_VERDICT=verdict, RH_ENFORCED=enforced)
        p = subprocess.run([_BASH, "-c", step["run"]], env=env,
                           capture_output=True, text=True)
        assert p.returncode == rc, (verdict, enforced, p.stdout)
        assert "passed." not in p.stdout, p.stdout


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


# docs/index.html's own render() run under node, over the hosted entrypoint's
# real output: the page a user sees, not a substring of its source.
_RENDER_JS = r"""
const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const envs = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const m = html.match(/<script>([\s\S]*?)<\/script>/g);
const src = m[m.length - 1].replace(/^<script>/, '').replace(/<\/script>$/, '');
function stub() {
  const store = {};
  const p = new Proxy(function () {}, {
    get(t, k) { if (k in store) return store[k];
                if (k === Symbol.toPrimitive) return () => '';
                if (k === 'then') return undefined; return p; },
    set(t, k, v) { store[k] = v; return true; },
    apply() { return p; }, construct() { return p; } });
  return p;
}
const boxes = {};
const el = (id) => (boxes[id] = boxes[id] || stub());
const ctx = { console, setTimeout: () => 0, clearTimeout: () => 0, setInterval: () => 0,
  URL: stub(), Blob: stub(), fetch: () => new Promise(() => {}), navigator: stub(),
  location: stub(), localStorage: stub(), Worker: function () { return stub(); },
  loadPyodide: () => new Promise(() => {}), JSON, Math, Date, String, Object, Array,
  Promise, RegExp, encodeURIComponent };
ctx.window = ctx; ctx.self = ctx;
ctx.document = new Proxy({}, { get(t, k) {
  if (k === 'getElementById') return (id) => el(id);
  if (k === 'querySelector') return (q) => el('q:' + q);
  if (k === 'querySelectorAll') return () => [];
  return stub(); } });
vm.createContext(ctx);
vm.runInContext(src, ctx);
const out = envs.map((e) => {
  ctx.__d = e.report_json; ctx.__v = e.vendor || '';
  vm.runInContext('render(__d, __v)', ctx);
  return String(el('results').innerHTML);
});
process.stdout.write(JSON.stringify(out));
"""
_NODE = shutil.which("node")
needs_node = pytest.mark.skipif(_NODE is None, reason="node not available")


def _render_hosted(envs: list) -> list:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        js, data = os.path.join(d, "render.js"), os.path.join(d, "envs.json")
        open(js, "w").write(_RENDER_JS)
        open(data, "w").write(json.dumps(envs))
        p = subprocess.run([_NODE, js, os.path.join(_ROOT, "docs", "index.html"), data],
                           capture_output=True, text=True, check=True)
    return json.loads(p.stdout)


@needs_node
def test_hosted_page_never_shows_an_empty_reason():
    """A FAIL run (a critical hygiene finding, or a broken must_reach) next to
    an undecided segmentation panel has run-level reasons [], yet the panel's
    UNKNOWN must still name the stopgap reason."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from stopgap_fail_baseline import MUST_REACH_POLICY
    cases = [(open(CLEAN).read(), json.dumps(MUST_REACH_POLICY)),
             # telnet from any to a host in no zone: a high finding, no violation
             ("ip access-list extended EDGE\n permit tcp any host 192.0.2.10 eq 23\n",
              open(POLICY).read())]
    envs = [_hosted(cfg, pol) for cfg, pol in cases]
    assert [e["report_json"]["verdict"] for e in envs] == ["FAIL", "FAIL"]
    for html in _render_hosted(envs):
        assert "Segmentation UNKNOWN" in html
        assert "()" not in html and "( )" not in html
        assert f"{CODE}: {MESSAGE}" in html


def test_hosted_page_static_copy_promises_no_passing_claim():
    html = open(os.path.join(_ROOT, "docs", "index.html"), encoding="utf-8").read()
    assert "claims passed or failed" not in html
    assert "claims that passed or failed" not in html


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
# Pre-existing negated sentences that name the word only to deny it. They are
# removed before the sweep; each is an exact phrase, so a new positive PASS
# anywhere still fails the test. The segmentation-error ones are FAIL finding
# messages (high), which the stopgap must leave byte-identical.
NEGATIONS = (
    "fail-closed: no assertion gets a PASS until the policy is fixed",   # segcheck
    "assertions over this zone get no PASS until the policy is fixed",    # segcheck
    "fail-closed: the affected assertion gets no PASS until fixed",       # gate help
    "fail_on=none: nothing blocks, so no PASS is given",                  # mcp ADVISORY
    "not_analysed); no PASS is given",                                    # mcp coverage
    "unrecognised or unreadable input makes the result INCOMPLETE, never PASS",  # mcp
    "This release gives no all-clear",                                    # mcp
    # evidence JSON: the per-control count of VERIFIED claims, always zero
    '"verified": 0',
    "address translation must be verified separately",                   # scope
    "Nothing is proven for those",                                        # evidence md
    "Isolation is NOT proven for those",                                  # evidence md
    "isolation is NOT proven",                                            # evidence basis
    "pass vendor= to force one",                                          # mcp (a verb)
    # hosted page: Hammerhead's own verdicts in its product note, not RuleHawk's
    "gives each change a pass, fail or unknown",
    "verified offline before you push",          # Hammerhead's, in the same note
    "could not be proven open OR closed",                                 # kind help
    "Isolation could not be PROVEN",                                      # kind help
    "This assertion was NOT checked — nothing is proven",                 # segcheck
    "no claim in this report is marked verified",                         # evidence md
    "nothing unanalysed can pass",                                        # mcp INCOMPLETE
    "no all-clear is given",                                              # mcp INCOMPLETE
)
BANNED = [re.compile(p, re.I) for p in (
    r"\bPASS\b", r"\bVERIFIED\b", r"segmentation-ok", r"connectivity-ok",
    r"no violation", r"policy is clean", "✅", r"NO_NEW_RISK",
    r'"passed":\s*true', r"\bproven\b", r"\bholds\b", r"no issues found",
    r"all[- ]clear")]


def _sweep(label: str, text: str):
    for n in NEGATIONS:
        # the phrase as written, and as a JSON string escapes it (— is \u2014)
        text = text.replace(n, "").replace(json.dumps(n)[1:-1], "")
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
    if _NODE:
        out["hosted page"] = _render_hosted([env])[0]
    return out


def _sweep_configs():
    """Every vendor the line reads: the samples, the ten-router corpus, the
    hosted page's own SAMPLE_* configs, and the hosted-parity fixtures (Junos,
    PAN-OS, NX-OS, EOS, an unresolved Cisco object-group) plus an AWS SG."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import test_hosted_parity as hp
    from stopgap_fail_baseline import _web_samples
    cfgs = [(n, open(os.path.join(_S, n)).read()) for n in sorted(os.listdir(_S))
            if n != "policy.json"]
    cdir = os.path.join(_ROOT, "scripts", "corpus", "ten_router_acl")
    cfgs += [(n, open(os.path.join(cdir, n)).read()) for n in sorted(os.listdir(cdir))]
    cfgs += [(n.split(":")[1], text) for n, text in _web_samples()]
    cfgs += [("junos_leak", hp._JUNOS_LEAK), ("panos", hp._PANOS_CFG),
             ("cisco_indet", hp._CISCO_INDET), ("nxos", hp._NXOS_CFG),
             ("eos", hp._EOS_CFG)]
    cfgs.append(("awssg", json.dumps({"SecurityGroups": [{
        "GroupId": "sg-1", "GroupName": "t", "VpcId": "vpc-1",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                           "IpRanges": [{"CidrIp": "10.20.0.0/16"}]}],
        "IpPermissionsEgress": []}]})))
    return cfgs


@pytest.mark.parametrize("name,text", _sweep_configs(), ids=lambda v: v if len(v) < 40 else "")
@pytest.mark.parametrize("with_policy", [False, True], ids=["nopolicy", "policy"])
def test_no_output_path_emits_a_pass_token(tmp_path, name, text, with_policy):
    cfg = tmp_path / ("cfg_" + re.sub(r"[^A-Za-z0-9_.-]", "_", name))
    cfg.write_text(text)
    pol_path = POLICY if with_policy else ""
    pol_obj = json.load(open(POLICY)) if with_policy else None
    for label, out in _all_outputs(tmp_path, str(cfg), pol_path, pol_obj).items():
        _sweep(f"{name} [{label}]", out)


def test_no_output_path_emits_a_pass_token_on_a_must_reach_proof(tmp_path, reach):
    cfg, pol = reach
    for label, text in _all_outputs(tmp_path, cfg, pol, REACH_POLICY).items():
        _sweep(f"reach [{label}]", text)


BAD_POLICY = {"zones": {"PCI": ["10.10.0.0/16", "not-a-cidr"],
                        "CORP": ["10.20.0.0/16"]},
              "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                                  "ports": [445]},
                                 {"src": "CORP", "dst": "NOPE"}]}


def test_no_output_path_emits_a_pass_token_on_bad_input(tmp_path):
    pol = tmp_path / "bad_policy.json"
    pol.write_text(json.dumps(BAD_POLICY))
    for cfg in (CLEAN, DIRTY):
        sub = tmp_path / os.path.basename(cfg)
        sub.mkdir()
        for label, text in _all_outputs(sub, cfg, str(pol), BAD_POLICY).items():
            _sweep(f"bad policy {os.path.basename(cfg)} [{label}]", text)
    empty = tmp_path / "no_rules.txt"
    empty.write_text("hostname r1\n")
    sub = tmp_path / "empty"
    sub.mkdir()
    for label, text in _all_outputs(sub, str(empty), POLICY,
                                    json.load(open(POLICY))).items():
        _sweep(f"no rules [{label}]", text)


def test_preflight_skill_stops_on_unknown_and_exit_3():
    """The published agent skill must tell an agent what to do with the normal
    0.4.1 result: UNKNOWN (audit or compare) and exit 3 are a stop."""
    s = open(os.path.join(_ROOT, "skills", "rulehawk-preflight", "SKILL.md"),
             encoding="utf-8").read()
    rows = [l for l in s.splitlines() if l.lstrip().startswith("|") and "`UNKNOWN`" in l]
    assert rows, "no UNKNOWN row in the verdict table"
    assert "**Stop.**" in rows[0] and CODE in rows[0] and MESSAGE in rows[0], rows[0]
    fallback = s[s.index("## CLI fallback"):]
    assert re.search(r"\b3\b[^.]*UNKNOWN", fallback), fallback
    assert "Treat 1, 2 and 3 as a stop" in fallback, fallback
    assert "Exit 0 is a pass" not in s
    q = open(os.path.join(_ROOT, "docs", "quickstart.md"), encoding="utf-8").read()
    assert "only all-clear" not in q and "`UNKNOWN`" in q


def test_docs_name_no_proven_isolation_or_passing_claim():
    """Docs a user reads to interpret a 0.4.1 result: no stale all-clear."""
    pol = open(os.path.join(_ROOT, "docs", "policy.md"), encoding="utf-8").read()
    assert "proven isolated" not in pol
    ga = open(os.path.join(_ROOT, "docs", "github-action.md"), encoding="utf-8").read()
    assert "unless the combined verdict is PASS" not in ga
    assert "`VERIFIED` means" not in ga
    ca = open(os.path.join(_ROOT, "comment", "action.yml"), encoding="utf-8").read()
    assert "unless the combined verdict is PASS" not in ca
    assert "PASS | FAIL | UNKNOWN" not in ca


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
