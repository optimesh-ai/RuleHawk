"""RH-G1, engine gap "engine ignores filter bindings (Junos)": guard tests.

The engine searches every Junos filter as its own first-match context and
does not check where a filter is bound. A filter that would isolate two
zones, bound where it never sees the traffic between them, therefore reads
as isolating. Released v0.3.1 (before the fail-closed stopgap) reported
PASS, exit 0, for each file below; v0.3.2 and later report UNKNOWN.

These tests pin that the CLI and the gate never report PASS and never exit
0 for these files, whatever changes in the engine, until the engine reads
bindings. Every address is RFC 5737 documentation space.

- g1_pci_side_input_only: F bound only as input on the PCI-side unit;
- g1_corp_side_output_only: F bound only as output on the CORP-side unit;
- g1_wrong_unit: F bound as input on another unit of the CORP-side port;
- g1_unbound_filter: F defined, bound nowhere;
- g1_set_pci_side_input_only: the first case in set form.
In each, CORP (192.0.2.0/24) reaches PCI (198.51.100.0/24) through no filter.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "junos_binding")
_POLICY = os.path.join(_D, "policy.json")
_CASES = sorted(n for n in os.listdir(_D) if n.startswith("g1_"))


def _run(*args):
    env = {k: v for k, v in os.environ.items() if k != "RULEHAWK_SHADOW"}
    env["PYTHONPATH"] = _ROOT
    r = subprocess.run([sys.executable, "-m", "rulehawk", *args], capture_output=True,
                       text=True, cwd=_ROOT, env=env, timeout=120)
    return r.returncode, r.stdout


def test_the_five_cases_are_present():
    assert len(_CASES) == 5, _CASES


@pytest.mark.parametrize("name", _CASES)
def test_cli_never_reports_isolation(name):
    path = os.path.join(_D, name)
    rc, out = _run(path, "--policy", _POLICY)
    assert rc != 0, (rc, out)
    assert "PASS" not in out, out
    rc, out = _run(path, "--policy", _POLICY, "--json")
    assert rc != 0, (rc, out)
    d = json.loads(out)
    seg = [f for f in d["findings"] if f["kind"].startswith("segmentation")]
    assert seg, d
    for f in seg:
        assert f["kind"] != "segmentation-ok", f
        assert f["kind"] == "segmentation-violation" or f.get("verdict") == "UNKNOWN", f


@pytest.mark.parametrize("name", _CASES)
def test_gate_never_passes(name):
    path = os.path.join(_D, name)
    rc, out = _run("gate", path, "--policy", _POLICY)
    assert rc != 0, (rc, out)
    assert "VERDICT: PASS" not in out, out
    rc, out = _run("gate", path, "--policy", _POLICY, "--json", "-")
    assert rc != 0, (rc, out)
    d = json.loads(out[out.index("{"):])
    assert d["passed"] is False, d
    assert d.get("verdict") != "PASS", d
    for fl in d["files"]:
        for f in fl["findings"]:
            assert f["kind"] != "segmentation-ok", f
