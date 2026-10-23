"""MCP tool functions (rulehawk/mcp_server.py), one block per tool.

These call the plain tool functions, so they run without the MCP SDK (and on
the 3.9 floor). The contract under test is the one an agent relies on:

  * every result states what was and was not analysed (`coverage`) and that
    the scope is the rule layer only (`scope`);
  * unrecognised, unreadable or missing input is never a PASS;
  * a finding id resolves back to the same finding on an unchanged file;
  * compare reports what a change introduces, keyed on rule text rather than
    sequence numbers, and never gives an all-clear over an unread file.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import mcp_server as m  # noqa: E402

_CLEAN = """ip access-list extended EDGE
 permit tcp 10.20.0.0 0.0.255.255 host 10.20.5.5 eq 443
 deny ip any any
"""

# The same ACL with one risky rule inserted ABOVE the existing ones, so every
# existing rule's sequence number shifts by one.
_RISKY = """ip access-list extended EDGE
 permit tcp any any eq 3389
 permit tcp 10.20.0.0 0.0.255.255 host 10.20.5.5 eq 443
 deny ip any any
"""

_DIRTY = """ip access-list extended EDGE
 permit ip any any
 deny tcp any any eq 23
"""

_PARTIAL = """ip access-list extended EDGE
 permit tcp 10.20.0.0 0.0.255.255 host 10.20.5.5 eq 443
 permit tcp any any time-range WORKHOURS
 deny ip any any
"""

_FORTIGATE = """config firewall policy
    edit 1
        set srcintf "port1"
        set srcaddr "all"
        set action accept
    next
end
"""

_POLICY = {
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                        "ports": [445]}],
}


def _write(d, name, text):
    p = os.path.join(str(d), name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)
    return p


def _assert_contract(r):
    """Fields every result must carry, whatever the verdict."""
    assert "verdict" in r or "found" in r or r.get("tool") == "rulehawk_supported_inputs"
    assert r["scope"]["statement"].startswith("Rule layer only")
    json.dumps(r)  # results must be JSON-serialisable for the protocol


# --------------------------------------------------------------------------- #
# rulehawk_audit
# --------------------------------------------------------------------------- #
def test_audit_clean_file_passes_with_complete_coverage(tmp_path):
    r = m.audit(_write(tmp_path, "edge.cfg", _CLEAN))
    _assert_contract(r)
    assert r["verdict"] == "PASS"
    assert r["coverage"]["state"] == "complete"
    assert r["coverage"]["files_analysed"] == 1
    assert r["coverage"]["not_analysed"] == []
    assert r["coverage"]["analysed"][0]["vendor"] == "ios-asa"
    assert r["scope"]["not_evaluated"] == ["routing", "nat", "topology",
                                           "change-impact"]


def test_audit_dirty_file_fails_and_names_the_blocking_rule(tmp_path):
    r = m.audit(_write(tmp_path, "edge.cfg", _DIRTY))
    assert r["verdict"] == "FAIL"
    kinds = {f["kind"] for f in r["blocking_findings"]}
    assert "permit-any-any" in kinds
    f = r["blocking_findings"][0]
    assert f["file"] == "edge.cfg" and f["line"] >= 2
    assert f["id"].startswith("RH-")


def test_audit_unsupported_vendor_is_incomplete_never_pass(tmp_path):
    r = m.audit(_write(tmp_path, "fgt.conf", _FORTIGATE))
    _assert_contract(r)
    assert r["verdict"] == "INCOMPLETE"
    assert r["coverage"]["state"] == "incomplete"
    na = r["coverage"]["not_analysed"]
    assert na and na[0]["path"] == "fgt.conf"
    assert "no firewall rules recognised" in na[0]["reason"]


def test_audit_directory_reports_every_file_and_skips_hidden(tmp_path):
    _write(tmp_path, "a/edge.cfg", _CLEAN)
    _write(tmp_path, "b/notes.txt", "just some notes, not a config\n")
    _write(tmp_path, ".git/config", "[core]\n")
    r = m.audit(str(tmp_path))
    assert r["verdict"] == "INCOMPLETE"       # the notes file is not a config
    assert r["coverage"]["files_analysed"] == 1
    paths = [x["path"] for x in r["coverage"]["not_analysed"]]
    assert os.path.join("b", "notes.txt") in paths
    assert any("hidden" in x["reason"] for x in r["coverage"]["not_analysed"])


def test_audit_unmodelled_lines_make_coverage_partial(tmp_path):
    r = m.audit(_write(tmp_path, "edge.cfg", _PARTIAL))
    cov = r["coverage"]
    assert r["verdict"] == "PASS"            # nothing blocking was found...
    assert cov["state"] == "partial"         # ...but not every line was modelled
    assert cov["files_with_unmodelled_lines"] == 1
    assert "time-range" in cov["analysed"][0]["unmodelled_lines"][0]


def test_audit_with_policy_reports_the_witness(tmp_path):
    cfg = _write(tmp_path, "edge.cfg",
                 "ip access-list extended EDGE\n permit tcp any any eq 445\n")
    pol = _write(tmp_path, "policy.json", json.dumps(_POLICY))
    r = m.audit(cfg, policy_path=pol)
    assert r["policy_applied"] is True
    seg = [f for f in r["blocking_findings"] if f["kind"] == "segmentation-violation"]
    assert seg and "445" in seg[0]["witness"]


def test_audit_errors_are_results_not_exceptions(tmp_path):
    for r in (m.audit(str(tmp_path / "missing.cfg")),
              m.audit(""),
              m.audit(_write(tmp_path, "e.cfg", _CLEAN), vendor="fortigate"),
              m.audit(_write(tmp_path, "f.cfg", _CLEAN), fail_on="sometimes"),
              m.audit(_write(tmp_path, "g.cfg", _CLEAN),
                      policy_path=_write(tmp_path, "bad.json", "{not json"))):
        assert r["verdict"] == "ERROR"
        assert r["coverage"]["state"] == "incomplete"
        assert r["error"]


def test_audit_refuses_paths_outside_the_root(tmp_path, monkeypatch):
    inside = tmp_path / "in"
    outside = _write(tmp_path, "out/edge.cfg", _CLEAN)
    _write(inside, "edge.cfg", _CLEAN)
    monkeypatch.setenv("RULEHAWK_MCP_ROOT", str(inside))
    assert m.audit(str(inside / "edge.cfg"))["verdict"] == "PASS"
    r = m.audit(outside)
    assert r["verdict"] == "ERROR" and "outside RULEHAWK_MCP_ROOT" in r["error"]


def test_audit_fail_on_none_is_advisory(tmp_path):
    r = m.audit(_write(tmp_path, "edge.cfg", _DIRTY), fail_on="none")
    assert r["verdict"] == "PASS" and r["blocking_findings"] == []
    assert r["findings_by_severity"]["critical"] >= 1


# --------------------------------------------------------------------------- #
# rulehawk_list_findings
# --------------------------------------------------------------------------- #
def test_list_findings_filters_and_sorts(tmp_path):
    p = _write(tmp_path, "edge.cfg", _DIRTY)
    allf = m.list_findings(p)
    _assert_contract({**allf, "verdict": "-"})
    sev = [f["severity"] for f in allf["findings"]]
    rank = [m._SEV_RANK[s] for s in sev]
    assert rank == sorted(rank, reverse=True)
    crit = m.list_findings(p, min_severity="critical")
    assert crit["findings"] and all(f["severity"] == "critical" for f in crit["findings"])
    only = m.list_findings(p, kinds=["permit-any-any"])
    assert {f["kind"] for f in only["findings"]} == {"permit-any-any"}
    assert m.list_findings(p, kinds=["no-such-kind"])["unknown_kinds"] == ["no-such-kind"]


def test_list_findings_limit_truncates_visibly(tmp_path):
    p = _write(tmp_path, "edge.cfg", _DIRTY)
    r = m.list_findings(p, min_severity="info", limit=1)
    assert r["findings_returned"] == 1
    assert r["truncated"] is (r["findings_total"] > 1)


def test_list_findings_carries_coverage(tmp_path):
    r = m.list_findings(_write(tmp_path, "fgt.conf", _FORTIGATE))
    assert r["findings"] == []
    assert r["coverage"]["state"] == "incomplete"


# --------------------------------------------------------------------------- #
# rulehawk_explain_finding
# --------------------------------------------------------------------------- #
def test_explain_finding_by_id_round_trips(tmp_path):
    p = _write(tmp_path, "edge.cfg", _DIRTY)
    f = m.list_findings(p)["findings"][0]
    e = m.explain_finding(f["id"], p)
    _assert_contract(e)
    assert e["found"] is True
    assert e["finding"]["id"] == f["id"]
    assert e["finding"]["source_line"].strip() == f["rule"].strip()
    assert e["kind_explanation"]


def test_explain_finding_stale_id_is_not_found(tmp_path):
    p = _write(tmp_path, "edge.cfg", _DIRTY)
    fid = m.list_findings(p)["findings"][0]["id"]
    _write(tmp_path, "edge.cfg", _CLEAN)        # the file changed
    e = m.explain_finding(fid, p)
    assert e["found"] is False and e["verdict"] == "ERROR"


def test_explain_finding_by_kind_and_bad_input():
    e = m.explain_finding(kind="redundant")
    assert "safe to delete" in e["explanation"]
    bad = m.explain_finding(kind="nope")
    assert bad["verdict"] == "ERROR" and "redundant" in bad["known_kinds"]
    assert m.explain_finding()["verdict"] == "ERROR"
    assert m.explain_finding("not-an-id", "x")["verdict"] == "ERROR"


# --------------------------------------------------------------------------- #
# rulehawk_compare
# --------------------------------------------------------------------------- #
def test_compare_reports_the_introduced_rule_despite_resequencing(tmp_path):
    before = _write(tmp_path, "before.cfg", _CLEAN)
    after = _write(tmp_path, "after.cfg", _RISKY)
    c = m.compare(before, after)
    _assert_contract(c)
    assert c["verdict"] == "INTRODUCES_RISK"
    assert [f["kind"] for f in c["introduced"]] == ["dangerous-exposure"]
    assert c["resolved"] == []                 # seq shift did not churn findings
    added = c["files"][0]["rules_added"]
    assert [a["rule"] for a in added] == ["permit tcp any any eq 3389"]


def test_compare_no_change_and_fix(tmp_path):
    clean = _write(tmp_path, "clean.cfg", _CLEAN)
    risky = _write(tmp_path, "risky.cfg", _RISKY)
    same = m.compare(clean, clean)
    assert same["verdict"] == "NO_NEW_RISK" and same["introduced_total"] == 0
    fixed = m.compare(risky, clean)
    assert fixed["verdict"] == "NO_NEW_RISK"
    assert [f["kind"] for f in fixed["resolved"]] == ["dangerous-exposure"]


def test_compare_pre_existing_risk_is_counted_not_introduced(tmp_path):
    dirty = _write(tmp_path, "dirty.cfg", _DIRTY)
    c = m.compare(dirty, dirty)
    assert c["verdict"] == "NO_NEW_RISK"
    assert c["pre_existing_blocking"] >= 1
    assert "pre-existing" in c["verdict_reason"]


def test_compare_unsupported_side_is_incomplete(tmp_path):
    clean = _write(tmp_path, "clean.cfg", _CLEAN)
    fgt = _write(tmp_path, "fgt.conf", _FORTIGATE)
    for b, a in ((clean, fgt), (fgt, clean)):
        c = m.compare(b, a)
        assert c["verdict"] == "INCOMPLETE"
        assert c["files"][0]["comparable"] is False


def test_compare_directories_pair_by_relative_path(tmp_path):
    _write(tmp_path, "b/fw1.cfg", _CLEAN)
    _write(tmp_path, "b/gone.cfg", _DIRTY)
    _write(tmp_path, "a/fw1.cfg", _RISKY)
    _write(tmp_path, "a/new.cfg", _DIRTY)
    c = m.compare(str(tmp_path / "b"), str(tmp_path / "a"))
    changes = {(e["before"], e["after"]): e["change"] for e in c["files"]}
    assert changes == {("fw1.cfg", "fw1.cfg"): "modified",
                       (None, "new.cfg"): "added",
                       ("gone.cfg", None): "removed"}
    assert c["verdict"] == "INTRODUCES_RISK"
    files = {f["file"] for f in c["introduced"]}
    assert files == {"fw1.cfg", "new.cfg"}
    assert {f["file"] for f in c["resolved"]} == {"gone.cfg"}


def test_compare_rejects_file_vs_directory(tmp_path):
    f = _write(tmp_path, "x/fw.cfg", _CLEAN)
    c = m.compare(f, str(tmp_path / "x"))
    assert c["verdict"] == "ERROR"


# --------------------------------------------------------------------------- #
# rulehawk_supported_inputs
# --------------------------------------------------------------------------- #
def test_supported_inputs_lists_vendors_kinds_and_limits():
    s = m.supported_inputs()
    _assert_contract(s)
    vendors = {v["vendor"] for v in s["supported_vendors"]}
    assert vendors == set(m._VENDOR_CHOICES) - {"auto"}
    assert "permit-any-any" in s["finding_kinds"]
    assert any("NAT" in x for x in s["not_modelled"])
    assert any("network" in g for g in s["guarantees"])


def test_the_engine_package_does_not_import_the_mcp_layer():
    """The hosted tool loads `rulehawk` in Pyodide, which has no MCP SDK."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "rulehawk", "__init__.py")).read()
    assert "mcp" not in src


def test_the_tool_layer_never_reaches_the_network_or_a_subprocess():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "rulehawk", "mcp_server.py")).read()
    for banned in ("import socket", "import subprocess", "urllib", "http.client",
                   "requests", "pathground", "os.system", "Popen"):
        assert banned not in src, banned


def test_console_script_help_version_and_bad_args(capsys):
    assert m.main(["--help"]) == 0
    assert "rulehawk-mcp" in capsys.readouterr().out
    assert m.main(["--version"]) == 0
    assert m.main(["--bogus"]) == 2


def test_rulehawk_mcp_subcommand_reaches_the_server_entry_point(capsys):
    """`rulehawk mcp` is what the MCP registry entry runs (uvx rulehawk mcp)."""
    from rulehawk import cli
    assert cli.main(["mcp", "--version"]) == 0
    assert "rulehawk-mcp" in capsys.readouterr().out
