"""The GitHub Action manifest — the delivery mechanism for the CI gate.

`action.yml` is a shipped interface: a typo in an output reference or a flag the
CLI does not accept breaks every consumer's pipeline, and nothing else in the
suite would catch it. These tests check the wiring, not the behavior.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML not installed")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ACTION = os.path.join(_ROOT, "action.yml")


def _action() -> dict:
    with open(_ACTION, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _run_block(action: dict) -> str:
    return "\n".join(s.get("run", "") for s in action["runs"]["steps"])


def test_action_manifest_parses():
    a = _action()
    assert a["runs"]["using"] == "composite"
    assert a["inputs"] and a["outputs"]


def test_every_output_reads_a_value_some_step_actually_writes():
    """`value: ${{ steps.X.outputs.Y }}` is silently EMPTY if nothing echoes
    `Y=` to $GITHUB_OUTPUT — a blank output, never an error."""
    a = _action()
    run = _run_block(a)
    written = set(re.findall(r'echo "([a-z_]+)=', run))
    written |= set(re.findall(r'print\("([a-z_-]+)=', run))
    ids = {s.get("id") for s in a["runs"]["steps"]}
    for name, spec in a["outputs"].items():
        m = re.search(r"steps\.([\w-]+)\.outputs\.([\w-]+)", spec["value"])
        assert m, f"output {name}: unparseable value {spec['value']!r}"
        step_id, key = m.groups()
        assert step_id in ids, f"output {name} references unknown step {step_id!r}"
        assert key in written, (
            f"output {name} reads '{key}', which no step writes to $GITHUB_OUTPUT")


def test_every_input_referenced_is_declared():
    a = _action()
    used = set(re.findall(r"inputs\.([\w-]+)", yaml.dump(a)))
    assert not used - set(a["inputs"]), \
        f"action.yml uses undeclared inputs: {used - set(a['inputs'])}"


def test_every_env_var_the_script_reads_is_bound():
    """The script runs under `set -u`; an unbound RH_* var aborts the step."""
    a = _action()
    bound = set()
    for step in a["runs"]["steps"]:
        bound |= set(step.get("env", {}))
    for var in set(re.findall(r"\$\{(RH_[A-Z_]+)\}", _run_block(a))):
        assert var in bound, f"{var} is read but never set in a step `env:`"


def test_gate_accepts_every_flag_the_action_passes():
    """A flag the gate does not know is a hard failure for every consumer."""
    run = _run_block(_action())
    flags = set(re.findall(r"\s(--[a-z-]+)\s", run))
    flags |= {"--policy", "--evidence", "--evidence-md"}   # built into bash arrays
    help_text = subprocess.run(
        [sys.executable, "-m", "rulehawk", "gate", "--help"],
        cwd=_ROOT, capture_output=True, text=True).stdout
    for flag in sorted(flags):
        assert flag in help_text, \
            f"action.yml passes {flag}, but `rulehawk gate` does not accept it"


def test_evidence_is_opt_in():
    """Evidence writes extra files; it must not switch on for existing users."""
    assert str(_action()["inputs"]["evidence"]["default"]).lower() == "false"


def test_documented_action_inputs_match_the_manifest():
    """docs/github-action.md is the contract users read before adopting it."""
    doc_path = os.path.join(_ROOT, "docs", "github-action.md")
    if not os.path.exists(doc_path):
        pytest.skip("no github-action.md")
    doc = open(doc_path, encoding="utf-8").read()
    for name in _action()["inputs"]:
        assert re.search(rf"`{re.escape(name)}`", doc), \
            f"input {name!r} is undocumented in docs/github-action.md"


# --------------------------------------------------------------------------- #
# bash 3.2 safety — the failure Linux CI structurally cannot catch
# --------------------------------------------------------------------------- #
def test_no_unguarded_empty_array_expansion():
    """`"${ARR[@]}"` on an EMPTY array is an unbound variable under `set -u` in
    bash 3.2 — still the default `bash` on macOS runners. Bash 4.4 fixed it, so
    Ubuntu runners pass and macOS aborts the step before the gate verdict is
    even written. Every array expansion must use `${ARR[@]+"${ARR[@]}"}`.

    Regression: EVIDENCE_ARGS shipped unguarded and broke the macOS dogfood job
    on the DEFAULT path (evidence off => empty array), two lines below a comment
    explaining the trap for POLICY_ARGS.
    """
    # Strip comment lines first: the guarded form is *documented* in a comment
    # that necessarily quotes the unsafe one as the counter-example.
    run = "\n".join(l for l in _run_block(_action()).splitlines()
                     if not l.lstrip().startswith("#"))
    unguarded = re.findall(r'(?<!\+)"\$\{([A-Za-z_][A-Za-z0-9_]*)\[@\]\}"', run)
    assert not unguarded, (
        f"unguarded empty-array expansion(s) {sorted(set(unguarded))} — bash 3.2 "
        f"aborts on these under `set -u`. Use ${{ARR[@]+\"${{ARR[@]}}\"}}.")


@pytest.mark.skipif(not os.path.exists("/bin/bash"), reason="no /bin/bash")
def test_gate_command_line_survives_bash_with_set_u():
    """Execute the SHIPPED command line under the system bash with `set -u` and
    both arrays empty — the exact shape a default-configured macOS run takes."""
    run = _run_block(_action())
    m = re.search(r"(python3 -m rulehawk gate .*?)\n\s*RC=\$\?", run, re.S)
    assert m, "gate invocation not found in action.yml"
    # Replace the real invocation with `true` so we test the SHELL expansion,
    # not the audit: an unbound-variable abort happens before argv is built.
    cmd = m.group(1).replace("python3 -m rulehawk gate", "true")
    script = ("set -euo pipefail\n"
              "RH_CONFIGS=cfg.txt\nRH_FAIL_ON=high\nRH_VENDOR=auto\n"
              "SARIF=/tmp/s\nJSON=/tmp/j\nCOMMENT=/tmp/c\n"
              "POLICY_ARGS=()\nEVIDENCE_ARGS=()\n" + cmd + "\necho SHELL_OK\n")
    proc = subprocess.run(["/bin/bash", "-c", script],
                          capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"the shipped gate command line fails under "
        f"bash {os.popen('/bin/bash -c \"echo $BASH_VERSION\"').read().strip()}"
        f" with empty arrays:\n{proc.stderr}")
    assert "SHELL_OK" in proc.stdout
