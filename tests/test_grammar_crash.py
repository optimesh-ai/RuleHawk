"""Review r2 of #52-#59, N2: a grammar that crashes while parsing fails
a shadow run closed (`file-uncertified`, a `grammar_unavailable` entry),
never with a traceback. With the switch unset the grammar is not run."""
from __future__ import annotations

import importlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_POL = os.path.join(_D, "pol", "v4_ip.json")
_CASES = [("grammar_junos", os.path.join(_D, "controls", "k00_base.conf")),
          ("grammar_panos", os.path.join(_D, "controls", "p00_base.set")),
          ("grammar_iptables", os.path.join(_D, "controls", "i00_base.sh"))]


def _gate(path):
    with open(_POL, encoding="utf-8") as fh:
        pol = json.load(fh)
    d = json.loads(g.to_json(g.run_gate([path], pol, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    return f.get("shadow")


@pytest.mark.parametrize("mod,path", _CASES, ids=[c[0] for c in _CASES])
def test_a_grammar_that_crashes_fails_a_shadow_run_closed(monkeypatch, mod, path):
    try:
        gm = importlib.import_module("rulehawk." + mod)
    except ImportError:
        pytest.skip(mod + " is not on this branch")
    if not os.path.exists(path):
        pytest.skip("no control for " + mod)

    def boom(*a, **k):
        raise RuntimeError("boom")
    for name in ("parse", "parse_model"):
        if hasattr(gm, name):
            monkeypatch.setattr(gm, name, boom)
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")
    sh = _gate(path)
    if sh["boundary"]["reason"] is not None:
        pytest.skip("the boundary refuses this control on this branch")
    assert "grammar" not in sh, sh
    assert "RuntimeError" in sh["grammar_unavailable"], sh
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["would_pass"] is False, sh
