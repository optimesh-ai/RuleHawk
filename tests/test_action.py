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
