"""The failure paths a first-time user (or their agent) hits, each with an
actionable message and the right verdict. Unknown input is INCOMPLETE, never
PASS; a bad request is a structured ERROR (error, error_code, hint)."""

from __future__ import annotations

import os
import shutil
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rulehawk import cli, gate  # noqa: E402
from rulehawk import mcp_server as m  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")
IOS = os.path.join(SAMPLES, "ios_acl.txt")


@pytest.fixture
def ws(tmp_path, monkeypatch):
    """A workspace that is also RULEHAWK_MCP_ROOT, with the samples copied in."""
    shutil.copytree(SAMPLES, tmp_path / "samples")
    monkeypatch.setenv("RULEHAWK_MCP_ROOT", str(tmp_path))
    monkeypatch.delenv("RULEHAWK_MCP_MAX_ACL_RULES", raising=False)
    return tmp_path


def _na(r):
    return r["coverage"]["not_analysed"]


def test_relative_path_resolves_against_the_root(ws, monkeypatch):
    monkeypatch.chdir("/")
    r = m.audit("samples/ios_acl.txt")
    assert r["verdict"] == "FAIL"
    assert r["coverage"]["analysed"][0]["rules_analysed"] == 10


def test_missing_relative_path_says_where_it_looked(ws):
    r = m.audit("ios_acl.txt")
    assert r["verdict"] == "ERROR" and r["error_code"] == "path_not_found"
    assert str(ws) in r["error"] and "absolute path" in r["hint"]


def test_missing_relative_path_without_root_names_the_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("RULEHAWK_MCP_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)
    r = m.audit("nope.txt")
    assert r["error_code"] == "path_not_found"
    assert "working directory" in r["hint"] and "absolute path" in r["hint"]


def test_path_outside_root_is_refused_with_a_way_out(ws):
    r = m.audit(IOS)
    assert r["verdict"] == "ERROR" and r["error_code"] == "path_outside_root"
    assert "outside RULEHAWK_MCP_ROOT" in r["error"]
    assert "RULEHAWK_MCP_ROOT" in r["hint"]
    r = m.audit("../../etc/hosts")
    assert r["error_code"] == "path_outside_root"


@pytest.mark.parametrize("content, words", [
    (b"", "the file is empty"),
    (b"\n  \n\t\n", "the file is empty"),
    (b"hostname core1\ninterface Gi0/1\n description uplink\n",
     "no supported firewall vendor recognised"),
])
def test_unreadable_content_is_incomplete_never_pass(ws, content, words):
    p = ws / "x.txt"
    p.write_bytes(content)
    for fail_on in ("high", "critical", "low"):
        r = m.audit(str(p), fail_on=fail_on)
        assert r["verdict"] == "INCOMPLETE", r
        assert words in _na(r)[0]["reason"]
        assert _na(r)[0]["hint"]


def test_wrong_vendor_guess_points_back_to_auto(ws):
    r = m.audit(str(ws / "samples" / "ios_acl.txt"), vendor="junos")
    assert r["verdict"] == "INCOMPLETE"
    reason = _na(r)[0]["reason"]
    assert "forced to junos" in reason and "looks like ios-asa" in reason


def test_vendor_aliases_are_accepted(ws):
    for alias in ("cisco", "Cisco", "asa", "ios"):
        r = m.audit(str(ws / "samples" / "ios_acl.txt"), vendor=alias)
        assert r["verdict"] == "FAIL", (alias, r.get("error"))
    r = m.audit(str(ws / "samples" / "ios_acl.txt"), vendor="fortigate")
    assert r["verdict"] == "ERROR" and r["error_code"] == "bad_argument"


def test_mixed_vendor_directory_is_audited_per_file_and_flags_the_stranger(ws):
    d = ws / "mixed"
    d.mkdir()
    for f in ("ios_acl.txt", "iptables_save.txt", "aws_security_groups.json"):
        shutil.copy(ws / "samples" / f, d / f)
    (d / "README.txt").write_text("these are our firewall configs\n")
    r = m.audit(str(d))
    vendors = {a["file"]: a["vendor"] for a in r["coverage"]["analysed"]}
    assert vendors == {"ios_acl.txt": "ios-asa", "iptables_save.txt": "iptables",
                       "aws_security_groups.json": "aws-sg"}
    assert [n["path"] for n in _na(r)] == ["README.txt"]
    assert r["verdict"] == "FAIL" and r["coverage"]["state"] == "incomplete"
    # Without the risky files the stranger alone keeps it from passing.
    for f in ("ios_acl.txt", "iptables_save.txt", "aws_security_groups.json"):
        os.remove(d / f)
    shutil.copy(ws / "samples" / "adv_realistic.txt", d / "edge.txt")
    assert m.audit(str(d))["verdict"] == "INCOMPLETE"


def test_windows_line_endings_give_the_same_findings_and_lines(ws):
    crlf = ws / "crlf.txt"
    crlf.write_bytes(open(IOS, "rb").read().replace(b"\n", b"\r\n"))
    a = m.list_findings(str(ws / "samples" / "ios_acl.txt"))["findings"]
    b = m.list_findings(str(crlf))["findings"]
    assert [(f["kind"], f["line"], f["rule"]) for f in a] == \
           [(f["kind"], f["line"], f["rule"]) for f in b]


def _big_acl(n):
    return "ip access-list extended BIG\n" + "".join(
        f" permit tcp host 10.0.{i // 256}.{i % 256} any eq {1024 + i}\n"
        for i in range(n))


def test_an_acl_over_the_size_limit_is_incomplete_with_a_cli_hint(ws, monkeypatch):
    monkeypatch.setenv("RULEHAWK_MCP_MAX_ACL_RULES", "50")
    (ws / "big.txt").write_text(_big_acl(60))
    r = m.audit(str(ws / "big.txt"))
    assert r["verdict"] == "INCOMPLETE"
    na = _na(r)[0]
    assert "60 rules" in na["reason"] and "limit of 50" in na["reason"]
    assert "rulehawk FILE" in na["hint"]
    assert m.supported_inputs()["limits"]["max_rules_per_acl"] == 50
    # Many small ACLs are fine: the limit is per ACL, not per file.
    (ws / "many.txt").write_text("".join(
        _big_acl(40).replace("BIG", f"A{k}") for k in range(3)))
    assert m.audit(str(ws / "many.txt"))["coverage"]["state"] != "incomplete"


def test_compare_does_not_call_an_oversized_file_resolved(ws, monkeypatch):
    monkeypatch.setenv("RULEHAWK_MCP_MAX_ACL_RULES", "50")
    before = ws / "before.txt"
    after = ws / "after.txt"
    before.write_text(open(IOS).read())
    after.write_text(_big_acl(60))
    r = m.compare(str(before), str(after))
    assert r["verdict"] == "INCOMPLETE"
    assert r["resolved_total"] == 0
    assert r["files"][0]["comparable"] is False


def test_fail_on_none_is_advisory_not_pass(ws):
    r = m.audit(str(ws / "samples" / "ios_acl.txt"), fail_on="none")
    assert r["verdict"] == "ADVISORY"
    assert r["findings_by_severity"]["critical"] >= 1
    s = ws / "samples"
    r = m.compare(str(s / "adv_realistic.txt"), str(s / "ios_acl.txt"), fail_on="none")
    assert r["verdict"] == "ADVISORY"


def test_explain_with_an_id_but_no_path_names_the_missing_argument(ws):
    p = str(ws / "samples" / "ios_acl.txt")
    fid = m.list_findings(p)["findings"][0]["id"]
    r = m.explain_finding(fid)
    assert r["error_code"] == "path_required" and "path" in r["error"]
    assert m.explain_finding(fid, path=p)["found"] is True


def test_finding_ids_are_stable_across_tools_and_path_spellings(ws, monkeypatch):
    p = str(ws / "samples" / "ios_acl.txt")
    monkeypatch.chdir(ws)
    ids_abs = [f["id"] for f in m.list_findings(p)["findings"]]
    ids_rel = [f["id"] for f in m.list_findings("samples/ios_acl.txt")["findings"]]
    ids_again = [f["id"] for f in m.list_findings(p)["findings"]]
    blocking = {f["id"] for f in m.audit(p)["blocking_findings"]}
    assert ids_abs == ids_rel == ids_again
    assert blocking <= set(ids_abs)
    empty = ws / "empty.txt"
    empty.write_text("ip access-list extended EDGE_IN\n deny ip any any\n")
    introduced = {f["id"] for f in m.compare(str(empty), p)["introduced"]}
    assert introduced <= set(ids_abs) and introduced


def test_version_without_the_sdk_explains_the_python_floor(monkeypatch, capsys):
    monkeypatch.setattr(m, "_sdk_version", lambda: None)
    assert m.main(["--version"]) == 2
    err = capsys.readouterr().err
    assert "3.10" in err and "pip install" in err


def test_cli_on_a_directory_points_at_gate(tmp_path, capsys):
    assert cli.main([str(tmp_path)]) == 2
    assert f"rulehawk gate {tmp_path}" in capsys.readouterr().err


def test_gate_console_says_why_a_file_was_not_audited(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hello\n")
    g = gate.run_gate([str(p)], None)
    reason = gate.no_rules_reason(g.files[0], g.vendor)
    assert "no supported firewall vendor recognised" in reason
    assert reason in gate.to_console(g)
