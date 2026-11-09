"""#42 phase 2, slice 7 (first part): the certificate record and the
independent checker, in shadow (design v2 sections 1.2, 1.3 and 12, v4
section 5).

For a file the grammar parses, the engine builds a certificate record:
the hash of the exact input bytes, the policy's assertions as canonical
JSON, the engine version, the declaration (none yet), and one
sub-record per reading with its final model, rows and pending rows. The
independent checker in `rulehawk_check/` (standard library and
`rulehawk/citations.py` only) re-derives the final model from the raw
bytes with its own splitter and tokenizer, and checks the hash, the
assertions, the version, the declaration and every citation. Any
difference is `checker-disagrees`, the blocking reason.

In this slice no record is eligible: every record lists its blockers
(pending rows, the dual read, placement, legacy reasons) and always
`checker-verdict-deferred`, because the checker's own evaluation of the
assertion is the step that could make `would_pass` true, and it comes
after review. `would_pass` stays false, and nothing changes with the
switch unset.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
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
_CHECK = os.path.join(_ROOT, "rulehawk_check")
_ENTRY = {"config_sha256", "blockers", "checker"}
_DEFERRED = "checker-verdict-deferred"


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


def _record(path, policy="default"):
    """The engine's certificate record for one control, and its bytes."""
    from rulehawk import certificate, dialects
    pol = _policy() if policy == "default" else policy
    raw = open(path, "rb").read()
    sh = dialects.shadow_block(raw, "auto", pol)
    return certificate.build(raw, sh["grammar"], sh["model"], sh["dual_read"],
                             sh.get("placement"), pol, None), raw, pol


def _check(rec, raw, pol):
    """Review of #52-#57, G11: the checker takes the raw policy and resolves
    the zones itself."""
    import rulehawk
    from rulehawk_check import check
    return check(rec, raw, pol, rulehawk.__version__)


def _sources():
    return sorted(os.path.join(_CHECK, n) for n in os.listdir(_CHECK) if n.endswith(".py"))


# ------------------------------------------------------- independence of the checker

def test_checker_imports_closure():
    """v2 section 1.3, v4 section 5: the checker's whole import closure is
    the standard library and citations.py; importing it loads no engine
    module, not even the `rulehawk` package."""
    code = ("import sys; import rulehawk_check; "
            "bad = sorted(m for m in sys.modules if m == 'rulehawk' or "
            "m.startswith('rulehawk.')); print(bad); sys.exit(1 if bad else 0)")
    r = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {_ROOT!r}); " + code],
                       capture_output=True, text=True, cwd=_ROOT)
    assert r.returncode == 0, (r.stdout, r.stderr)


_STDLIB = {"__future__", "hashlib", "ipaddress", "json", "os", "re", "typing",
           "importlib", "importlib.util", "dataclasses", "types", "sys"}


def test_checker_imports_only_the_standard_library_and_its_own_modules():
    for path in _sources():
        for node in ast.walk(ast.parse(_read(path))):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    continue                    # its own modules
                mods = [node.module or ""]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert m in _STDLIB, (path, m)


def test_checker_names_no_engine_module():
    for path in _sources():
        text = _read(path)
        for name in ("parse_", "failclosed", "segcheck", "grammar_", "dialects",
                     "placement", "dualread", "boundary"):
            assert name not in text, (path, name)


def test_checker_shares_no_regex_with_the_grammars():
    """v2 section 5: an identical regular expression fails the copy check."""
    def strings(path):
        return {n.value for n in ast.walk(ast.parse(_read(path)))
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and len(n.value) > 6 and any(c in n.value for c in "[]()*+?\\")}
    eng = set()
    for n in ("grammar_junos.py", "grammar_panos.py", "grammar_iptables.py",
              "parse_junos.py", "parse_panos.py", "parse_iptables.py"):
        eng |= strings(os.path.join(_ROOT, "rulehawk", n))
    for path in _sources():
        assert not strings(path) & eng, (path, strings(path) & eng)


def test_checker_writes_no_all_clear_word():
    for path in _sources():
        text = _read(path)
        for word in ("PASS", "VERIFIED", "NO_NEW_RISK", "certified", "complete"):
            assert word not in text, (path, word)


# ------------------------------------------------------------ the controls in shadow

@pytest.mark.parametrize("path", [_K00, _P00, _I00])
def test_a_control_gets_a_record_the_checker_agrees_with(path, shadow):
    sh = _gate_shadow(path)
    c = sh["certificate"]
    assert set(c) == _ENTRY, c
    assert c["checker"] == {"agrees": True, "reason": None, "detail": None}, c
    assert _DEFERRED in c["blockers"], c
    assert any(b.startswith("pending:") for b in c["blockers"]), c
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["would_pass"] is False, sh


def test_the_record_hashes_the_exact_bytes(shadow):
    import hashlib
    sh = _gate_shadow(_K00)
    assert sh["certificate"]["config_sha256"] == hashlib.sha256(
        open(_K00, "rb").read()).hexdigest()


def test_the_cli_carries_the_same_record(monkeypatch, capsys):
    from rulehawk import cli
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")
    try:
        cli.main([_K00, "--policy", _POL, "--json"])
    except SystemExit:
        pass
    sh = json.loads(capsys.readouterr().out)["shadow"]
    assert sh["certificate"]["checker"]["agrees"] is True, sh


def test_no_record_without_the_switch(monkeypatch):
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    assert _gate_shadow(_K00) is None


def test_no_record_for_a_file_the_grammar_does_not_parse(tmp_path, shadow):
    p = tmp_path / "x.set"
    p.write_text(_read(_P00).replace("action deny", "action drop"))
    assert "certificate" not in _gate_shadow(str(p))


def test_no_all_clear_word_in_the_entry(shadow):
    for path in (_K00, _P00, _I00):
        text = json.dumps(_gate_shadow(path)["certificate"])
        for word in ("PASS", "VERIFIED", "certified", "complete"):
            assert word not in text, (path, word)


# ------------------------------------------------------------ blockers

def test_no_record_is_eligible_in_this_slice():
    from rulehawk import certificate
    rec, _, _ = _record(_K00)
    assert _DEFERRED in rec["blockers"], rec
    assert certificate.eligible(rec) is False


def test_legacy_reasons_and_notes_block():
    """v2 section 1.1: the full legacy reason set must be empty."""
    from rulehawk import certificate, dialects
    raw = open(_I00, "rb").read()
    sh = dialects.shadow_block(raw, "auto", _policy())
    rec = certificate.build(raw, sh["grammar"], sh["model"], sh["dual_read"],
                            sh.get("placement"), _policy(),
                            {"reasons": ["nat-present"], "notes": ["n"]})
    assert "legacy:nat-present" in rec["blockers"], rec
    assert "legacy:parse-notes" in rec["blockers"], rec


def test_the_gate_passes_its_legacy_reasons(monkeypatch, shadow):
    from rulehawk import certificate
    seen = {}
    real = certificate.build

    def spy(*a):
        seen["legacy"] = a[-1]
        return real(*a)
    monkeypatch.setattr(certificate, "build", spy)
    _gate_shadow(_K00)
    assert seen["legacy"] == {"reasons": [], "notes": []}, seen


# ------------------------------------------------------------ the checker disagrees

def test_a_transplanted_record_is_refused():
    """Family 11: a record from k00 checked against p00's bytes."""
    rec, _, pol = _record(_K00)
    r = _check(rec, open(_P00, "rb").read(), pol)
    assert r["agrees"] is False and r["reason"] == "checker-disagrees", r


def test_a_one_byte_change_is_refused():
    rec, raw, pol = _record(_K00)
    changed = raw.replace(b"203.0.113.0/24", b"203.0.113.0/25")
    assert len(changed) == len(raw) and changed != raw
    r = _check(rec, changed, pol)
    assert r["agrees"] is False and r["reason"] == "checker-disagrees", r


def test_another_policy_is_refused():
    rec, raw, pol = _record(_K00)
    other = json.loads(json.dumps(pol))
    other["zones"]["PCI"] = ["198.51.100.0/25"]
    r = _check(rec, raw, other)
    assert r["agrees"] is False, r


def test_another_engine_version_is_refused():
    from rulehawk_check import check
    rec, raw, pol = _record(_K00)
    r = check(rec, raw, pol, "0.0.0")
    assert r["agrees"] is False, r


def _mutate_k00(rec, how):
    rec = json.loads(json.dumps(rec))
    objs = rec["subs"][0]["model"]["objects"]
    by = {tuple(o["path"]): o for o in objs}
    f = ("firewall", "family inet", "filter F")
    if how == "address":
        by[("interfaces", "ge-0/0/0", "unit 0", "family inet")]["values"]["address"] = "192.0.2.2/24"
    elif how == "order":
        by[f]["ordered"].reverse()
    elif how == "action":
        by[f + ("term d",)]["values"]["then"] = "accept"
    elif how == "binding":
        by[("interfaces", "ge-0/0/1", "unit 0", "family inet", "filter")]["values"].clear()
    elif how == "drop":
        objs.remove(by[f + ("term a", "from", "source-address", "203.0.113.0/24")])
    elif how == "add":
        objs.append({"path": list(f + ("term a", "from", "source-address", "10.0.0.0/8")),
                     "values": {}, "ordered": []})
    elif how == "dialect":
        rec["subs"][0]["dialect"] = "panos"
    elif how == "declaration":
        rec["declaration"] = {"platform": "x"}
    elif how == "uncited-row":
        rec["subs"][0]["rows"].append("junos-no-such-row")
    elif how == "pending-row-as-cited":
        rec["subs"][0]["rows"].append("junos-lexing")
    elif how == "no-subs":
        rec["subs"] = []
    return rec


@pytest.mark.parametrize("how", ["address", "order", "action", "binding", "drop", "add",
                                 "dialect", "declaration", "uncited-row",
                                 "pending-row-as-cited", "no-subs"])
def test_a_record_that_misstates_the_file_is_refused(how):
    rec, raw, pol = _record(_K00)
    assert _check(rec, raw, pol)["agrees"] is True
    r = _check(_mutate_k00(rec, how), raw, pol)
    assert r["agrees"] is False and r["reason"] == "checker-disagrees", (how, r)


@pytest.mark.parametrize("path", [_P00, _I00])
def test_panos_and_iptables_records_that_misstate_the_file_are_refused(path):
    rec, raw, pol = _record(path)
    rec2 = json.loads(json.dumps(rec))
    obj = [o for o in rec2["subs"][0]["model"]["objects"] if o["values"]][0]
    k = sorted(obj["values"])[0]
    obj["values"][k] = obj["values"][k] + "x"
    r = _check(rec2, raw, pol)
    assert r["agrees"] is False and r["reason"] == "checker-disagrees", r


@pytest.mark.parametrize("bad", [b"\r\n", b"\t", b"\x00", " ".encode(), b"\x7f"])
def test_the_checker_splitter_refuses_control_and_non_ascii_bytes(bad):
    """Its own splitter: LF only, printable ASCII (v2 section 7)."""
    rec, raw, pol = _record(_I00)
    raw2 = raw.replace(b"\n", bad + b"\n", 1) if bad != b"\r\n" else raw.replace(b"\n", b"\r\n", 1)
    import hashlib
    rec = json.loads(json.dumps(rec))
    rec["config_sha256"] = hashlib.sha256(raw2).hexdigest()
    r = _check(rec, raw2, pol)
    assert r["agrees"] is False, (bad, r)


def test_a_disagreeing_checker_blocks_the_shadow_run(monkeypatch, shadow):
    import rulehawk_check
    monkeypatch.setattr(rulehawk_check, "check", lambda *a: {
        "agrees": False, "reason": "checker-disagrees", "detail": "test"})
    sh = _gate_shadow(_K00)
    assert sh["blocking_reason"] == "checker-disagrees", sh
    assert sh["blocking_reason_strict"] == "checker-disagrees", sh
    assert sh["would_pass"] is False, sh


def test_a_checker_that_fails_blocks_the_shadow_run(monkeypatch, shadow):
    import rulehawk_check

    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(rulehawk_check, "check", boom)
    sh = _gate_shadow(_K00)
    assert sh["certificate"]["checker"]["agrees"] is False, sh
    assert sh["blocking_reason"] == "checker-disagrees", sh


# ------------------------------------------------- review of #52-#57, G8, G10-G13

_CONTROLS = [_K00, _P00, _I00]


def _copy(rec):
    return json.loads(json.dumps(rec))


@pytest.mark.parametrize("path", _CONTROLS)
@pytest.mark.parametrize("field", ["pending", "rows", "scope_assumptions", "blockers", "all"])
def test_an_emptied_record_is_refused(path, field):
    """G10: the checker re-derives or verifies the pending rows, the rows,
    the scope assumptions and the blockers; emptying any of them is
    `checker-disagrees`."""
    rec, raw, pol = _record(path)
    assert _check(rec, raw, pol)["agrees"] is True
    rec = _copy(rec)
    sub = rec["subs"][0]
    if field in ("pending", "all"):
        sub["pending"] = []
    if field in ("rows", "all"):
        sub["rows"] = []
    if field in ("scope_assumptions", "all"):
        sub["scope_assumptions"] = []
    if field in ("blockers", "all"):
        rec["blockers"] = []
    r = _check(rec, raw, pol)
    assert r["agrees"] is False and r["reason"] == "checker-disagrees", (field, r)


@pytest.mark.parametrize("path,row", [
    (_K00, "junos-interface-name"), (_K00, "junos-unit-number"),
    (_K00, "junos-v4-prefix"), (_K00, "junos-address-list-or"),
    (_K00, "junos-lexing"), (_P00, "panos-rule-order"),
    (_P00, "panos-one-line-order"), (_P00, "panos-rule-name-chars"),
    (_P00, "panos-v4-prefix"), (_I00, "iptables-script-scope")])
def test_a_record_that_drops_one_pending_row_is_refused(path, row):
    """G10: a pending row the file's constructs rest on, dropped from the
    sub-record and from the blockers, is refused."""
    rec, raw, pol = _record(path)
    rec = _copy(rec)
    assert row in rec["subs"][0]["pending"], rec["subs"][0]["pending"]
    rec["subs"][0]["pending"].remove(row)
    rec["blockers"].remove("pending:" + row)
    r = _check(rec, raw, pol)
    assert r["agrees"] is False and r["reason"] == "checker-disagrees", (row, r)


@pytest.mark.parametrize("path", _CONTROLS)
def test_a_record_without_a_pending_blocker_or_the_deferral_is_refused(path):
    rec, raw, pol = _record(path)
    for drop in (rec["blockers"][0], _DEFERRED):
        r2 = _copy(rec)
        r2["blockers"].remove(drop)
        r = _check(r2, raw, pol)
        assert r["agrees"] is False and r["reason"] == "checker-disagrees", (drop, r)


def test_a_record_with_another_scope_sentence_is_refused():
    rec, raw, pol = _record(_K00)
    rec = _copy(rec)
    rec["subs"][0]["scope_assumptions"] = ["zones are on separate segments"]
    assert _check(rec, raw, pol)["agrees"] is False


def test_a_record_with_a_scope_sentence_but_no_zones_is_refused():
    rec, raw, pol = _record(_K00)
    r = _check(rec, raw, {"must_not_reach": []})
    assert r["agrees"] is False, r


def test_the_checker_scope_sentence_is_the_engine_one():
    from rulehawk import placement
    from rulehawk_check import verify
    assert verify.SCOPE_SENTENCE == placement.SCOPE


@pytest.mark.parametrize("path", _CONTROLS)
def test_forged_empty_blockers_never_make_a_record_eligible(path):
    """G10: `eligible()` is false for every record, even one whose
    blockers were emptied."""
    from rulehawk import certificate
    rec, _, _ = _record(path)
    forged = _copy(rec)
    forged["blockers"] = []
    assert certificate.eligible(forged) is False
    assert certificate.eligible({"blockers": []}) is False
    assert certificate.eligible({}) is False


def test_the_shadow_run_hands_the_checker_the_raw_policy(monkeypatch, shadow):
    """G11: the checker gets the policy itself, not the engine's resolved
    assertions."""
    import rulehawk_check
    seen = {}
    real = rulehawk_check.check

    def spy(*a):
        seen["args"] = a
        return real(*a)
    monkeypatch.setattr(rulehawk_check, "check", spy)
    sh = _gate_shadow(_K00)
    assert seen["args"][2] == _policy(), seen
    assert sh["certificate"]["checker"]["agrees"] is True, sh


def test_the_checker_resolves_the_zones_itself(monkeypatch, shadow):
    """G11: an engine that resolves a zone wrongly, in the record and in
    what it would hand the checker, is refused."""
    from rulehawk import certificate
    real = certificate.assertions

    def forged(policy):
        return [a.replace("203.0.113.0/24", "10.0.0.0/8") for a in real(policy)]
    monkeypatch.setattr(certificate, "assertions", forged)
    pol = _policy()
    pol["zones"]["DMZ"] = ["203.0.113.0/24"]
    pol.setdefault("must_not_reach", []).append({"src": "DMZ", "dst": "PCI"})
    sh = _gate_shadow(_K00, pol)
    assert any("10.0.0.0/8" in a for a in forged(pol)), forged(pol)
    assert sh["certificate"]["checker"]["agrees"] is False, sh
    assert sh["blocking_reason"] == "checker-disagrees", sh


def test_a_record_that_fails_to_build_blocks_the_shadow_run(monkeypatch, shadow):
    """G8: an error building the record fails closed, with no traceback."""
    from rulehawk import certificate

    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(certificate, "build", boom)
    sh = _gate_shadow(_K00)
    c = sh["certificate"]
    assert set(c) == _ENTRY, c
    assert c["checker"]["agrees"] is False, c
    assert c["blockers"], c
    assert sh["blocking_reason"] == "checker-disagrees", sh
    assert sh["blocking_reason_strict"] == "checker-disagrees", sh
    assert sh["would_pass"] is False, sh


def _drop_checker_modules():
    for name in [m for m in sys.modules if m == "rulehawk_check" or m.startswith("rulehawk_check.")]:
        del sys.modules[name]


def test_the_engine_finds_the_checker_next_to_its_own_package(tmp_path, monkeypatch, shadow):
    """G13: a `rulehawk_check` earlier on sys.path is not the checker."""
    fake = tmp_path / "rulehawk_check"
    fake.mkdir()
    (fake / "__init__.py").write_text(
        "def check(*a):\n    return {'agrees': True, 'reason': None, 'detail': 'fake'}\n")
    saved = {m: sys.modules[m] for m in list(sys.modules)
             if m == "rulehawk_check" or m.startswith("rulehawk_check.")}
    monkeypatch.syspath_prepend(str(tmp_path))
    _drop_checker_modules()
    try:
        sh = _gate_shadow(_K00)
    finally:
        _drop_checker_modules()
        sys.modules.update(saved)
    assert sh["certificate"]["checker"].get("detail") != "fake", sh


def test_a_loaded_checker_from_elsewhere_fails_closed(monkeypatch, shadow):
    """G13: a module already loaded as `rulehawk_check` from another file
    is refused."""
    import types
    fake = types.ModuleType("rulehawk_check")
    fake.__file__ = "/elsewhere/rulehawk_check/__init__.py"
    fake.check = lambda *a: {"agrees": True, "reason": None, "detail": "fake"}
    monkeypatch.setitem(sys.modules, "rulehawk_check", fake)
    sh = _gate_shadow(_K00)
    assert sh["certificate"]["checker"]["agrees"] is False, sh
    assert sh["blocking_reason"] == "checker-disagrees", sh


def test_citations_does_nothing_at_import_but_build_its_tables():
    """G12 (accepted: the checker loads citations.py by path): its module
    level holds only the docstring, imports, definitions and assignments,
    and the only calls it makes are to its own `_row` and `dataclass`."""
    tree = ast.parse(_read(os.path.join(_ROOT, "rulehawk", "citations.py")))
    for node in tree.body:
        assert isinstance(node, (ast.Expr, ast.ImportFrom, ast.FunctionDef,
                                 ast.ClassDef, ast.Assign, ast.AnnAssign)), ast.dump(node)[:80]
        if isinstance(node, ast.Expr):
            assert isinstance(node.value, ast.Constant), ast.dump(node)[:80]
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    assert isinstance(sub.func, ast.Name) and sub.func.id == "_row", \
                        ast.unparse(sub)[:80]
