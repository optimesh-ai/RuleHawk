"""Single-file CLI (rulehawk/cli.py) — exit-code contract and robustness.

Exit codes are the CI interface: 0 clean, 1 critical/high finding, 2 error or
zero rules parsed (fail-closed, same contract as `rulehawk gate`).
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import cli  # noqa: E402

_CLEAN = """ip access-list extended CLEAN
 permit tcp 10.20.0.0 0.0.255.255 host 10.20.5.5 eq 443
 deny ip any any
"""

_BAD = """ip access-list extended EDGE
 permit ip any any
"""


def _write(d, name, text):
    p = os.path.join(d, name)
    with open(p, "w") as fh:
        fh.write(text)
    return p


def test_clean_config_exits_0(tmp_path, capsys):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    assert cli.main([p]) == 0
    assert "Hygiene score" in capsys.readouterr().out


def test_critical_finding_exits_1(tmp_path, capsys):
    p = _write(str(tmp_path), "edge.acl", _BAD)
    assert cli.main([p]) == 1
    assert "permit-any-any" in capsys.readouterr().out


def test_zero_rules_fails_closed_exit_2(tmp_path, capsys):
    # Parity with the gate: a garbled config must not exit 0 in CI.
    p = _write(str(tmp_path), "junk.txt", "! nothing parseable here\n")
    assert cli.main([p]) == 2
    assert "NO ACL RULES PARSED" in capsys.readouterr().out


def test_json_output_is_valid(tmp_path, capsys):
    p = _write(str(tmp_path), "edge.acl", _BAD)
    assert cli.main([p, "--json"]) == 1
    d = json.loads(capsys.readouterr().out)
    assert d["status"] == "ok" and d["findings_total"] >= 1


def test_missing_file_exits_2(tmp_path):
    assert cli.main([os.path.join(str(tmp_path), "nope.acl")]) == 2


def test_unknown_flag_is_usage_error(tmp_path):
    # A typo'd flag must not be read as a config filename or silently ignored.
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    assert cli.main([p, "--jsn"]) == 2


def test_multiple_files_is_usage_error(tmp_path):
    a = _write(str(tmp_path), "a.acl", _CLEAN)
    b = _write(str(tmp_path), "b.acl", _CLEAN)
    assert cli.main([a, b]) == 2


def test_bad_policy_json_exits_2(tmp_path):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    pol = _write(str(tmp_path), "policy.json", "{not json")
    assert cli.main([p, "--policy", pol]) == 2


def test_semantically_bad_policy_fails_closed(tmp_path, capsys):
    # Valid JSON, unknown zone: policy-error finding (high) -> exit 1, never a
    # traceback and never a certified PASS.
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    pol = _write(str(tmp_path), "policy.json", json.dumps(
        {"zones": {"PCI": ["10.10.0.0/16"]},
         "must_not_reach": [{"src": "CROP", "dst": "PCI"}]}))
    assert cli.main([p, "--policy", pol]) == 1
    assert "CANNOT EVALUATE" in capsys.readouterr().out


def test_help_exits_0(capsys):
    assert cli.main(["--help"]) == 0
    assert "usage" in capsys.readouterr().out


def test_non_utf8_stdin_does_not_crash(monkeypatch, capsys):
    # A latin-1 / binary / BOM config on stdin must degrade like a file path
    # (errors="replace"), never raise UnicodeDecodeError and exit 1.
    import io
    payload = ("ip access-list extended E\n"
               " permit tcp 10.20.0.0 0.0.255.255 10.99.0.0 0.0.255.255 eq 445\n"
               " deny ip any any\n").encode("utf-8")
    payload = b"\xff\xfe" + payload            # invalid UTF-8 prefix

    class _Stdin(io.StringIO):
        buffer = io.BytesIO(payload)
    monkeypatch.setattr(sys, "stdin", _Stdin())
    rc = cli.main(["-"])
    assert rc in (0, 1)                          # parsed, not a traceback/2
    assert "Hygiene score" in capsys.readouterr().out
