"""#42 phase 2, the legacy-parser dual read, in shadow (design v2 section
2.2, v3 section 6.2, v4 section 5). Its own slice, before slice 7.

For a file the grammar parses, the shadow block gets a `dual_read` entry:
side A is the grammar's final model, side B the existing dialect parser's
output (`parse_junos`, `parse_panos`, `parse_iptables`) mapped into the same
shape by `rulehawk/dualread.py`, which imports no grammar module.
- every access list's entries are compared in order, grouped by the
  statement that made them; any difference, a legacy parse note, or a
  legacy parser that fails, is `reading-mismatch`, and that is the
  blocking reason;
- a field side B does not expose (Junos interface addresses and filter
  bindings, PAN-OS zones, application and service) is listed under
  `single`, with the entry's reason `reading-single`; the file stays
  `file-uncertified` until slice 7's checker re-derives those fields.

The dual read is an extra check, not independence; nothing rests on it
alone, nothing changes with the switch unset, and `would_pass` stays false.
"""
from __future__ import annotations

import ast
import importlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_K00 = os.path.join(_D, "controls", "k00_base.conf")
_P00 = os.path.join(_D, "controls", "p00_base.set")
_I00 = os.path.join(_D, "controls", "i00_base.sh")
_POL = os.path.join(_D, "pol", "v4_ip.json")
_KEYS = {"reason", "compared", "single", "mismatch"}


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _policy():
    with open(_POL, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def shadow(monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")


def _gate_shadow(path, policy="default"):
    pol = _policy() if policy == "default" else policy
    d = json.loads(g.to_json(g.run_gate([path], pol, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    return f.get("shadow")


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return str(p)


def _ace(**kw):
    import ipaddress
    from rulehawk.model import ACE
    base = dict(seq=1, action="deny", proto="ip", src=ipaddress.ip_network("192.0.2.0/24"),
                dst=ipaddress.ip_network("198.51.100.0/24"), acl="security", line=1)
    base.update(kw)
    return ACE(**base)


# ------------------------------------------------------------------ the module

def test_the_dual_read_module_imports_no_grammar_module():
    """v3 section 6.2: side B's adapter may not import the grammar, so the
    fold is not compared with itself."""
    path = os.path.join(_ROOT, "rulehawk", "dualread.py")
    tree = ast.parse(_read(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names |= {mod} | {f"{mod}.{a.name}" if mod else a.name for a in node.names}
    # Modules named by string (importlib) count too.
    names |= {n.value.lstrip(".") for n in ast.walk(tree)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)
              and n.value.startswith(".")}
    flat = " ".join(sorted(names))
    for banned in ("grammar", "failclosed", "dialects", "placement", "boundary"):
        assert banned not in flat, (banned, names)
    local = {n for n in names if n.startswith(("parse", "model"))}
    assert local <= {"parse_junos", "parse_junos.parse_junos", "parse_panos",
                     "parse_panos.parse_panos", "parse_iptables",
                     "parse_iptables.parse_iptables"}, local


# ------------------------------------------------------------------ the controls

def test_k00_agrees_and_lists_its_single_fields(shadow):
    sh = _gate_shadow(_K00)
    dr = sh["dual_read"]
    assert set(dr) == _KEYS, dr
    assert dr == {"reason": "reading-single", "compared": ["F"],
                  "single": ["junos-filter-binding", "junos-interface-address"],
                  "mismatch": None}, dr
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["would_pass"] is False, sh


def test_p00_agrees_and_lists_its_single_fields(shadow):
    dr = _gate_shadow(_P00)["dual_read"]
    assert dr == {"reason": "reading-single", "compared": ["security"],
                  "single": ["panos-application", "panos-service", "panos-zones"],
                  "mismatch": None}, dr


def test_i00_agrees_with_nothing_single(shadow):
    sh = _gate_shadow(_I00)
    assert sh["dual_read"] == {"reason": None, "compared": ["FORWARD"], "single": [],
                               "mismatch": None}, sh
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["would_pass"] is False, sh


def test_the_cli_carries_the_same_dual_read(monkeypatch, capsys):
    from rulehawk import cli
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")
    try:
        cli.main([_K00, "--policy", _POL, "--json"])
    except SystemExit:
        pass
    sh = json.loads(capsys.readouterr().out)["shadow"]
    assert sh["dual_read"]["reason"] == "reading-single", sh


def test_no_dual_read_without_the_switch(monkeypatch):
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    assert _gate_shadow(_K00) is None


def test_a_file_the_grammar_does_not_parse_gets_no_dual_read(tmp_path, shadow):
    p = _write(tmp_path, "x.set", _read(_P00).replace("action deny", "action drop"))
    sh = _gate_shadow(p)
    assert "dual_read" not in sh and sh["blocking_reason"] == "line-not-allowlisted", sh


# ------------------------------------------------------------------ agreement

_K = _read(_K00)


@pytest.mark.parametrize("name,text", [
    ("two.conf", _K.replace("source-address { 192.0.2.0/24; }",
                            "source-address { 192.0.2.0/24; 192.0.2.128/25; }")),
    ("nofrom.conf", _K.replace(
        "term a { from { source-address { 203.0.113.0/24; } } then accept; }",
        "term a { then accept; }")),
    ("pol.sh", "iptables -P FORWARD ACCEPT\n"),
    ("any.set", "set rulebase security rules r1 from any to any source any "
                "destination any application any service any action allow\n"),
])
def test_the_two_readings_agree(tmp_path, shadow, name, text):
    sh = _gate_shadow(_write(tmp_path, name, text))
    assert sh["grammar"]["parses"] is True, sh
    assert sh["dual_read"]["mismatch"] is None, sh
    assert sh["dual_read"]["reason"] in (None, "reading-single"), sh


# ------------------------------------------------------------------ mismatch

def test_a_legacy_parse_note_is_reading_mismatch(tmp_path, shadow):
    """The legacy parser notes a chain with rules and no policy: no second
    reading agrees, so the file is reading-mismatch."""
    sh = _gate_shadow(_write(tmp_path, "nopol.sh",
                             "iptables -A FORWARD -s 192.0.2.0/24 -j DROP\n"))
    assert sh["grammar"]["parses"] is True, sh
    assert sh["dual_read"]["reason"] == "reading-mismatch", sh
    assert "note" in sh["dual_read"]["mismatch"], sh
    assert sh["blocking_reason"] == "reading-mismatch", sh
    assert sh["would_pass"] is False, sh


def test_a_different_action_is_reading_mismatch(monkeypatch, shadow):
    parse_panos = importlib.import_module("rulehawk.parse_panos")
    monkeypatch.setattr(parse_panos, "parse_panos",
                        lambda text: ([_ace(action="permit")], []))
    sh = _gate_shadow(_P00)
    assert sh["dual_read"]["reason"] == "reading-mismatch", sh
    assert sh["blocking_reason"] == "reading-mismatch", sh


@pytest.mark.parametrize("field,value", [
    ("proto", "tcp"), ("stateful", True), ("imprecise", True), ("icmp_type", "echo"),
    ("acl", "other"),
])
def test_any_entry_field_that_differs_is_reading_mismatch(monkeypatch, shadow, field, value):
    parse_panos = importlib.import_module("rulehawk.parse_panos")
    monkeypatch.setattr(parse_panos, "parse_panos",
                        lambda text: ([_ace(**{field: value})], []))
    assert _gate_shadow(_P00)["dual_read"]["reason"] == "reading-mismatch"


def test_the_unchanged_legacy_reading_agrees(monkeypatch, shadow):
    """The control for the mutations above: the same ACE as the legacy
    parser's agrees."""
    parse_panos = importlib.import_module("rulehawk.parse_panos")
    monkeypatch.setattr(parse_panos, "parse_panos", lambda text: ([_ace()], []))
    assert _gate_shadow(_P00)["dual_read"]["reason"] == "reading-single"


def test_an_extra_legacy_entry_is_reading_mismatch(monkeypatch, shadow):
    parse_panos = importlib.import_module("rulehawk.parse_panos")
    monkeypatch.setattr(parse_panos, "parse_panos",
                        lambda text: ([_ace(), _ace(seq=2, line=2)], []))
    assert _gate_shadow(_P00)["dual_read"]["reason"] == "reading-mismatch"


def test_a_missing_legacy_entry_is_reading_mismatch(monkeypatch, shadow):
    parse_panos = importlib.import_module("rulehawk.parse_panos")
    monkeypatch.setattr(parse_panos, "parse_panos", lambda text: ([], []))
    assert _gate_shadow(_P00)["dual_read"]["reason"] == "reading-mismatch"


def test_order_is_compared(monkeypatch, shadow):
    parse_junos = importlib.import_module("rulehawk.parse_junos")
    real = parse_junos.parse_junos
    monkeypatch.setattr(parse_junos, "parse_junos",
                        lambda text: (list(reversed(real(text)[0])), []))
    assert _gate_shadow(_K00)["dual_read"]["reason"] == "reading-mismatch"


def test_a_legacy_parser_that_fails_is_reading_mismatch(monkeypatch, shadow):
    parse_iptables = importlib.import_module("rulehawk.parse_iptables")

    def boom(text):
        raise RuntimeError("boom")
    monkeypatch.setattr(parse_iptables, "parse_iptables", boom)
    sh = _gate_shadow(_I00)
    assert sh["dual_read"]["reason"] == "reading-mismatch", sh
    assert sh["blocking_reason"] == "reading-mismatch", sh


def test_a_mismatch_comes_before_placement(monkeypatch, shadow):
    """With a policy, a reading-mismatch is the blocking reason in both
    modes, ahead of any placement reason."""
    parse_junos = importlib.import_module("rulehawk.parse_junos")
    monkeypatch.setattr(parse_junos, "parse_junos", lambda text: ([], []))
    sh = _gate_shadow(_K00)
    assert "placement" in sh, sh
    assert sh["blocking_reason"] == "reading-mismatch", sh
    assert sh["blocking_reason_strict"] == "reading-mismatch", sh


def test_no_all_clear_word_in_the_entry(shadow):
    for path in (_K00, _P00, _I00):
        text = json.dumps(_gate_shadow(path)["dual_read"])
        for word in ("PASS", "VERIFIED", "certified", "complete"):
            assert word not in text, (path, word)
