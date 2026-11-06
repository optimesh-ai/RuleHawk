"""Fail-closed stopgap (0.3.2): PASS is never emitted.

Until the fail-closed work lands, RuleHawk cannot back a pass on every config
it reads, so every surface reports a would-be pass as UNKNOWN, with reason
code `fail-closed-stopgap` and the message "fail-closed stopgap pending
soundness review". FAIL is unchanged. Exit codes: 1 FAIL, 2 parse failure or
invalid input, 3 UNKNOWN (precedence 2, then 1, then 3); 0 only for the
advisory `--fail-on none`.

The 0.3 line has these surfaces: the CLI (text / --json), the gate (exit
codes, JSON, markdown summary, PR comment, console, SARIF), the GitHub Action
(action.yml) and the engine output of the hosted entrypoint (docs/worker.js
over the docs/rulehawk copy). One test (or a few) per surface, then a token
sweep over every output, and the FAIL-unchanged check against
tests/stopgap_fail_golden.json.
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

from rulehawk import cli, gate

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


def _cli(args):
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
             ("out.sarif", "out.json", "comment.md", "summary.md")}
    rc = gate.main([CLEAN, "--policy", POLICY,
                    "--sarif", paths["out.sarif"], "--json", paths["out.json"],
                    "--comment", paths["comment.md"], "--summary", paths["summary.md"]])
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
    sarif = json.load(open(paths["out.sarif"]))
    assert sarif["runs"][0]["results"] == []          # nothing failed, no "pass"


def test_gate_fail_run_is_unchanged_fail(tmp_path):
    rc = gate.main([DIRTY, "--policy", POLICY, "--json", str(tmp_path / "o.json"), "-q"])
    assert rc == 1
    d = json.load(open(tmp_path / "o.json"))
    assert d["verdict"] == "FAIL" and d["reasons"] == []
    md = gate.to_markdown(gate.run_gate([DIRTY], json.load(open(POLICY)), "high"))
    assert [l for l in md.splitlines() if l.strip()][1].startswith("**FAIL**")


# --------------------------------------------------------------------------- #
# GitHub Action (action.yml). CI on this line installs only pytest, so the
# step script is read with a small block extractor, not PyYAML.
# --------------------------------------------------------------------------- #
_BASH = shutil.which("bash")
_ACTION = os.path.join(_ROOT, "action.yml")


def _action_text() -> str:
    with open(_ACTION, encoding="utf-8") as fh:
        return fh.read()


def _block(text: str, header: str) -> str:
    """The indented block that follows the line `header` (stripped match)."""
    lines = text.splitlines()
    i = next(k for k, l in enumerate(lines) if l.strip() == header)
    ind = len(lines[i]) - len(lines[i].lstrip())
    out = []
    for l in lines[i + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) <= ind:
            break
        out.append(l)
    return "\n".join(out)


def _enforce_script() -> str:
    step = _block(_action_text(), "- name: Enforce gate verdict")
    run = _block(step, "run: |").splitlines()
    ind = min(len(l) - len(l.lstrip()) for l in run if l.strip())
    return "\n".join(l[ind:] for l in run)


def test_action_declares_verdict_and_exit_code_outputs():
    outs = _block(_action_text(), "outputs:")
    assert "steps.gate.outputs.verdict" in _block(outs, "verdict:")
    assert "steps.gate.outputs.exit_code" in _block(outs, "exit-code:")
    assert "never" in _block(outs, "passed:").lower()
    # the gate step publishes the verdict output the outputs map reads
    assert 'print("verdict=" + str(d.get("verdict", "")))' in _action_text()


def _enforce(tmp_path, rc: str, fail_on: str, verdict: str):
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), RH_FAIL_ON=fail_on,
               RH_WORST="none", RH_VERDICT=verdict, RH_RC=rc)
    return subprocess.run([_BASH, "-c", _enforce_script()], env=env,
                          capture_output=True, text=True)


@pytest.mark.skipif(not _BASH, reason="needs bash")
def test_action_exit_3_fails_the_check_with_a_stopgap_annotation(tmp_path):
    p = _enforce(tmp_path, "3", "high", "UNKNOWN")
    assert p.returncode == 1
    assert "::error title=RuleHawk gate UNKNOWN" in p.stdout
    assert CODE in p.stdout and MESSAGE in p.stdout
    assert "passed" not in p.stdout


@pytest.mark.skipif(not _BASH, reason="needs bash")
def test_action_fail_and_parse_failure_still_fail(tmp_path):
    assert _enforce(tmp_path, "1", "high", "FAIL").returncode == 1
    assert _enforce(tmp_path, "2", "high", "FAIL").returncode == 1


@pytest.mark.skipif(not _BASH, reason="needs bash")
def test_action_fail_on_none_never_reads_as_passed(tmp_path):
    p = _enforce(tmp_path, "0", "none", "UNKNOWN")
    assert p.returncode == 0
    assert "::warning" in p.stdout and "UNKNOWN" in p.stdout
    assert "gate passed" not in p.stdout


@pytest.mark.skipif(not _BASH, reason="needs bash")
def test_action_enforced_exit_0_fails_closed(tmp_path):
    p = _enforce(tmp_path, "0", "high", "UNKNOWN")
    assert p.returncode == 1 and "::error" in p.stdout


@pytest.mark.skipif(not _BASH, reason="needs bash")
@pytest.mark.parametrize("fail_on", ["high", "none"])
def test_action_missing_rc_file_never_claims_exit_0(tmp_path, fail_on):
    # The gate step aborted before writing its exit code: there is no verdict,
    # so the step fails, says so, and never claims RuleHawk exited 0 -- not
    # even under fail-on none.
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), RH_FAIL_ON=fail_on,
               RH_WORST="", RH_VERDICT="")
    p = subprocess.run([_BASH, "-c", _enforce_script()], env=env,
                       capture_output=True, text=True)
    assert p.returncode == 1
    assert "exited 0" not in p.stdout
    assert "::error title=RuleHawk gate did not complete" in p.stdout
    assert "No verdict was recorded" in p.stdout


try:
    import yaml
except ImportError:          # the step-by-step Action checks need PyYAML
    yaml = None
needs_yaml = pytest.mark.skipif(yaml is None, reason="PyYAML not installed")


def _action() -> dict:
    with open(_ACTION, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


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
# hosted entrypoint (docs/worker.js over the docs/rulehawk copy)
# --------------------------------------------------------------------------- #
def _hosted(cfg: str, pol: str = "") -> dict:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_hosted_parity import _analyze_py, _read, _run_hosted
    return _run_hosted(_analyze_py(_read(os.path.join(_ROOT, "docs", "worker.js"))),
                       cfg, pol)


def test_hosted_report_is_unknown_with_reason():
    env = _hosted(open(CLEAN).read(), open(POLICY).read())
    rep = env["report_json"]
    assert rep["verdict"] == "UNKNOWN" and rep["reasons"] == REASONS
    assert "VERDICT: UNKNOWN" in env["report_text"]


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
    for flag in ([], ["--json"]):
        out[f"cli {' '.join(flag) or 'text'}"] = _cli([cfg] + flag + pargs)[1]
    for fail_on in ("high", "none"):
        g = gate.run_gate([cfg], pol_obj, fail_on)
        out[f"gate json {fail_on}"] = gate.to_json(g)
        out[f"gate markdown {fail_on}"] = gate.to_markdown(g)
        out[f"gate comment {fail_on}"] = gate.comment_body(g)
        out[f"gate console {fail_on}"] = gate.to_console(g)
        out[f"gate sarif {fail_on}"] = gate.to_sarif(g, version="x")
    env = _hosted(open(cfg).read(), open(pol_path).read() if pol_path else "")
    out["hosted"] = json.dumps(env)
    return out


def _sweep_configs():
    return [os.path.join(_S, n) for n in sorted(os.listdir(_S))
            if n != "policy.json"]


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


def test_kind_help_names_no_pass():
    _sweep("gate kind help", json.dumps(gate._KIND_HELP))


# --------------------------------------------------------------------------- #
# FAIL is unchanged: findings, severities, witnesses, SARIF, exit 1 / exit 2
# — on every sample and fixture
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
        for field in ("findings", "sarif_results", "gate_violations"):
            assert got[field] == was[field], (key, field)
        for field in ("cli_exit", "gate_exit_high"):
            # 1 and 2 stay as they were; the only change is 0 -> 3.
            want = 3 if was[field] == 0 else was[field]
            assert got[field] == want, (key, field, was[field], got[field])
