"""The sticky PR comment must never read PASS while a check in the run failed.

These tests drive the SHIPPED `action.yml` the way a runner does: each `run:`
step executes under bash with its `env:` bound, step outputs are read back from
$GITHUB_OUTPUT, and the github-script comment step is executed under node
against a fake GitHub client. They check what a reviewer would actually see.

Regressions they pin:
  * two gate invocations in one job: the later (passing) one overwrote the
    earlier (failing) one's comment, so the PR read "PASS" beside a red check;
  * the sticky-comment lookup read only the first 100 comments, so on a busy PR
    it lost its own comment and posted a second, stale-free-looking one.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML not installed")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ACTION = os.path.join(_ROOT, "action.yml")
_MARKER = "<!-- rulehawk-gate -->"

_NODE = shutil.which("node")
_BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _read_outputs(path: str) -> dict:
    out = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8").read().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def _resolve(value, inputs: dict, step_outputs: dict, action_path: str) -> str:
    """Resolve the `${{ ... }}` expressions action.yml uses in env values."""
    value = str(value)

    def sub(m: re.Match) -> str:
        expr = m.group(1).strip()
        if expr.startswith("inputs."):
            return str(inputs.get(expr[len("inputs."):], ""))
        if expr == "github.action_path":
            return action_path
        sm = re.fullmatch(r"steps\.([\w-]+)\.outputs\.([\w-]+)", expr)
        if sm:
            return step_outputs.get(sm.group(1), {}).get(sm.group(2), "")
        raise AssertionError(f"test harness cannot resolve ${{{{ {expr} }}}}")
    return re.sub(r"\$\{\{(.*?)\}\}", sub, value)


def _defaults(action: dict, given: dict) -> dict:
    inputs = {k: str(v.get("default", "")) for k, v in action["inputs"].items()}
    inputs.update(given)
    return inputs


def _run_invocation(action: dict, given: dict, runner_temp: str, cwd: str,
                    job: str = "gate-job", action_path: str = _ROOT) -> dict:
    """Run every bash step of one use of the action, in order. Returns
    {"outputs": {step_id: {...}}, "comment_step_env": {...}} — the env the
    github-script comment step would see."""
    inputs = _defaults(action, given)
    step_outputs: dict = {}
    comment_env = None
    for i, step in enumerate(action["runs"]["steps"]):
        sid = step.get("id") or f"_step{i}"
        env = {k: _resolve(v, inputs, step_outputs, action_path)
               for k, v in (step.get("env") or {}).items()}
        if "run" in step:
            out_file = os.path.join(runner_temp, f"out-{os.getpid()}-{sid}-{len(os.listdir(runner_temp))}")
            open(out_file, "w").close()
            full_env = dict(os.environ)
            full_env.update(env)
            full_env.update({"RUNNER_TEMP": runner_temp, "GITHUB_OUTPUT": out_file,
                             "GITHUB_JOB": job, "GITHUB_RUN_ATTEMPT": "1",
                             "GITHUB_ACTION_PATH": action_path})
            full_env.pop("GITHUB_STEP_SUMMARY", None)
            wd = os.path.join(cwd, _resolve(step.get("working-directory", "."),
                                            inputs, step_outputs, action_path))
            subprocess.run([_BASH, "-c", step["run"]], cwd=wd, env=full_env,
                           capture_output=True, text=True)
            step_outputs[sid] = _read_outputs(out_file)
        elif "github-script" in str(step.get("uses", "")) and \
                "comment" in str(step.get("name", "")).lower():
            comment_env = env
            comment_env["__script__"] = step["with"]["script"]
    return {"outputs": step_outputs, "comment_step_env": comment_env}


# Node harness: runs a github-script body against a fake GitHub API that pages
# exactly like the real one (per_page capped at 100, `page` 1-based).
_FAKE_GITHUB_JS = r"""
const fs = require('fs');
const state = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const script = fs.readFileSync(process.argv[3], 'utf8');
const calls = [];
const comments = state.comments;
function page(params) {
  const per = Math.min(params.per_page || 30, 100);
  const p = params.page || 1;
  return comments.slice((p - 1) * per, p * per);
}
const issues = {
  listComments: async (params) => { calls.push(['list', params.page || 1]); return {data: page(params)}; },
  updateComment: async (params) => { calls.push(['update', params.comment_id, params.body]); return {data: {id: params.comment_id}}; },
  createComment: async (params) => { calls.push(['create', params.body]); return {data: {id: 999999}}; },
};
const github = {
  rest: {issues, users: {getAuthenticated: async () => { const e = new Error('Resource not accessible by integration'); e.status = 403; throw e; }}},
  paginate: async (method, params) => {
    const all = []; let p = 1;
    for (;;) {
      const {data} = await method({...params, page: p});
      all.push(...data);
      if (data.length < Math.min(params.per_page || 30, 100)) return all;
      p += 1;
    }
  },
};
const context = {repo: {owner: 'o', repo: 'r'}, payload: {pull_request: {number: 7}},
                 eventName: 'pull_request', sha: 'abc1234', serverUrl: 'https://github.com', runId: 1};
const core = {warning: () => {}, notice: () => {}, info: () => {}, setFailed: (m) => { calls.push(['failed', m]); }};
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
(async () => {
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', script)(
    github, context, core, require, process);
  fs.writeFileSync(process.argv[4], JSON.stringify(calls));
})().catch((e) => { console.error(e); process.exit(1); });
"""


def _run_comment_script(script: str, env: dict, comments: list, tmp: str) -> list:
    state_p = os.path.join(tmp, "state.json")
    script_p = os.path.join(tmp, "script.js")
    harness_p = os.path.join(tmp, "harness.js")
    calls_p = os.path.join(tmp, "calls.json")
    json.dump({"comments": comments}, open(state_p, "w"))
    open(script_p, "w").write(script)
    open(harness_p, "w").write(_FAKE_GITHUB_JS)
    full_env = dict(os.environ)
    full_env.update({k: v for k, v in env.items() if not k.startswith("__")})
    proc = subprocess.run([_NODE, harness_p, state_p, script_p, calls_p],
                          env=full_env, capture_output=True, text=True)
    assert proc.returncode == 0, f"comment script crashed:\n{proc.stderr}"
    return json.load(open(calls_p))


def _posted_body(calls: list) -> str:
    writes = [c for c in calls if c[0] in ("update", "create")]
    assert writes, f"the comment step posted nothing: {calls}"
    return writes[-1][-1]


needs_node_and_bash = pytest.mark.skipif(
    not (_NODE and _BASH), reason="needs node and bash to execute the action")


@needs_node_and_bash
def test_a_later_passing_check_in_the_same_job_does_not_turn_the_comment_green(tmp_path):
    """Two gate steps in one job, both commenting: the first FAILs (critical
    findings on a dirty sample), the second PASSes. The comment the second step
    posts must still lead with FAIL — it is the one reviewers see last."""
    action = _load(_ACTION)
    runner_temp = str(tmp_path / "runner")
    os.makedirs(runner_temp)
    work = str(tmp_path / "ws")
    shutil.copytree(os.path.join(_ROOT, "samples"), os.path.join(work, "samples"))

    _run_invocation(action, {"configs": "samples/ios_acl.txt",
                             "policy": "samples/policy.json",
                             "upload-sarif": "false"}, runner_temp, work)
    second = _run_invocation(action, {"configs": "samples/adv_realistic.txt",
                                      "policy": "samples/policy.json",
                                      "upload-sarif": "false"}, runner_temp, work)
    env = second["comment_step_env"]
    assert env is not None, "no github-script comment step found in action.yml"
    calls = _run_comment_script(env["__script__"], env, [], str(tmp_path))
    body = _posted_body(calls)

    assert body.startswith(_MARKER)
    headline = next(l for l in body.splitlines() if l.startswith("## "))
    assert "❌" in headline and "✅" not in headline, (
        f"the comment the last step posts reads as a pass while an earlier "
        f"check in the job failed:\n{headline}")
    top = "\n".join(body.splitlines()[:6])
    assert "FAIL" in top, f"the comment does not lead with FAIL:\n{top}"
    # Both checks are on the comment, the failing one included.
    assert "samples/ios_acl.txt" in body and "samples/adv_realistic.txt" in body


@needs_node_and_bash
def test_the_sticky_comment_is_found_past_the_first_100_comments(tmp_path):
    """On a PR with 150 comments whose sticky verdict is #120, the step must
    update that comment, not post a second one (which leaves the old verdict
    standing above it)."""
    action = _load(_ACTION)
    runner_temp = str(tmp_path / "runner")
    os.makedirs(runner_temp)
    work = str(tmp_path / "ws")
    shutil.copytree(os.path.join(_ROOT, "samples"), os.path.join(work, "samples"))
    inv = _run_invocation(action, {"configs": "samples/ios_acl.txt",
                                   "policy": "samples/policy.json",
                                   "upload-sarif": "false"}, runner_temp, work)
    env = inv["comment_step_env"]
    comments = [{"id": i, "body": f"comment {i}",
                 "user": {"login": "someone", "type": "User"}} for i in range(1, 151)]
    comments[119] = {"id": 120, "body": f"{_MARKER}\n## ✅ old verdict",
                     "user": {"login": "github-actions[bot]", "type": "Bot"}}
    calls = _run_comment_script(env["__script__"], env, comments, str(tmp_path))
    writes = [c for c in calls if c[0] in ("update", "create")]
    assert writes and writes[-1][0] == "update" and writes[-1][1] == 120, (
        f"expected an update of comment 120, got {writes}")
    assert not [c for c in calls if c[0] == "create"], \
        f"a second sticky comment was created: {calls}"
