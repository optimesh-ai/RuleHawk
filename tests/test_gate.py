"""CI gate (rulehawk/gate.py) — the GitHub Action engine.

These tests pin the properties a PR gate must hold:
  1. discovery   — globs expand, de-duplicate, and sort deterministically;
  2. per-file    — the right vendor frontend is chosen and each finding maps to
                   its EXACT source line (so SARIF annotates the right diff line);
  3. threshold   — --fail-on critical|high|medium|low|none gates exactly the
                   findings it should, and INFO good-news (segmentation-ok) never
                   fails the build nor appears in SARIF;
  4. soundness   — a file that parses to ZERO rules is `no_rules_parsed`, never a
                   silent clean pass (the engine's "never a false bill of health");
  5. outputs     — SARIF 2.1.0 is well-formed with correct levels/lines, the JSON
                   aggregate is correct, the markdown carries the witness packet,
                   and main() returns 0/1 to drive the check.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate  # noqa: E402

# A Cisco ACL with: a critical permit-any-any, a redundant (low), and — under the
# policy below — a CORP->PCI:445 segmentation violation (critical, with witness).
_CISCO = """ip access-list extended EDGE
 permit tcp any host 203.0.113.10 eq 443
 permit tcp host 198.51.100.5 host 203.0.113.10 eq 443
 permit tcp any any eq 445
 permit ip any any
"""

# A clean Cisco ACL: scoped permits + a default deny, no forbidden flow.
_CLEAN = """ip access-list extended CLEAN
 permit tcp 10.20.0.0 0.0.255.255 host 10.20.5.5 eq 443
 deny ip any any
"""

_IPTABLES = """*filter
:FORWARD DROP [0:0]
-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT
COMMIT
"""

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def _write(d, name, text):
    p = os.path.join(d, name)
    with open(p, "w") as fh:
        fh.write(text)
    return p


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def test_discover_expands_globs_dedups_and_sorts(tmp_path):
    d = str(tmp_path)
    _write(d, "b.acl", _CLEAN)
    _write(d, "a.acl", _CLEAN)
    found, unmatched = gate.discover([os.path.join(d, "*.acl"),
                                      os.path.join(d, "a.acl")])  # overlap -> de-duped
    assert found == [os.path.join(d, "a.acl"), os.path.join(d, "b.acl")]
    assert unmatched == []


def test_discover_recursive_globstar(tmp_path):
    d = str(tmp_path)
    sub = os.path.join(d, "fw")
    os.makedirs(sub)
    _write(sub, "edge.acl", _CLEAN)
    found, unmatched = gate.discover([os.path.join(d, "**", "*.acl")])
    assert found == [os.path.join(sub, "edge.acl")]
    assert unmatched == []


def test_discover_walks_a_bare_directory(tmp_path):
    # `configs: firewall` (a dir, not a glob) should walk it recursively.
    d = str(tmp_path)
    sub = os.path.join(d, "firewall", "site-a")
    os.makedirs(sub)
    _write(os.path.join(d, "firewall"), "edge.acl", _CLEAN)
    _write(sub, "core.acl", _CLEAN)
    found, unmatched = gate.discover([os.path.join(d, "firewall")])
    assert found == [os.path.join(d, "firewall", "edge.acl"),
                     os.path.join(sub, "core.acl")]
    assert unmatched == []


def test_discover_reports_unmatched_patterns(tmp_path):
    d = str(tmp_path)
    _write(d, "a.acl", _CLEAN)
    found, unmatched = gate.discover([os.path.join(d, "a.acl"),
                                      os.path.join(d, "typo-*.acl")])
    assert found == [os.path.join(d, "a.acl")]
    assert unmatched == [os.path.join(d, "typo-*.acl")]


# --------------------------------------------------------------------------- #
# per-file audit: vendor pick + exact line mapping
# --------------------------------------------------------------------------- #
def test_audit_file_detects_vendor_and_maps_lines(tmp_path):
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    fr = gate.audit_file(p, _POLICY)
    assert fr.vendor == "ios-asa" and fr.status == "ok" and fr.n_rules == 4
    # permit ip any any is on physical line 5 (1=acl header, 2..5=rules).
    paa = next(f for f in fr.findings if f.kind == "permit-any-any")
    assert fr.line_of(paa) == 5
    # the segmentation violation's witness rule (permit tcp any any eq 445) is line 4.
    seg = next(f for f in fr.findings if f.kind == "segmentation-violation")
    assert fr.line_of(seg) == 4
    assert seg.witness == "10.20.0.1 -> 10.10.0.1:445 (tcp)"


def test_audit_file_iptables_forward_line(tmp_path):
    p = _write(str(tmp_path), "host.rules", _IPTABLES)
    fr = gate.audit_file(p, _POLICY)
    assert fr.vendor == "iptables"
    seg = next(f for f in fr.findings if f.kind == "segmentation-violation")
    assert fr.line_of(seg) == 3                 # the -A FORWARD line


def test_forced_vendor_overrides_autodetect(tmp_path):
    # Cisco text forced as iptables parses to nothing (no -A/-j) -> no_rules.
    p = _write(str(tmp_path), "x.txt", _CISCO)
    fr = gate.audit_file(p, None, vendor="iptables")
    assert fr.vendor == "iptables" and fr.status == "no_rules_parsed"


# --------------------------------------------------------------------------- #
# soundness: zero rules is surfaced, never a silent clean pass
# --------------------------------------------------------------------------- #
def test_empty_file_fails_closed_not_clean(tmp_path):
    # The anti-false-green guarantee: a file that parses to ZERO rules must not
    # pass the gate. check_segmentation([], policy) returns an all-PASS verdict,
    # so without fail-closed a garbled config would masquerade as isolated.
    p = _write(str(tmp_path), "empty.acl", "! just a comment\n")
    fr = gate.audit_file(p, _POLICY)
    assert fr.status == "no_rules_parsed"
    assert fr.score is None                     # NOT 100/100
    g = gate.GateResult([fr], "high")
    assert not g.passed                         # fail-closed...
    assert g.exit_code() == 2                   # ...with the dedicated error code
    assert g.parse_failures == [fr]
    # advisory mode (--fail-on none) is the explicit opt-out: never blocks.
    assert gate.GateResult([fr], "none").exit_code() == 0


def test_unparsed_file_emits_sarif_parse_result(tmp_path):
    p = _write(str(tmp_path), "empty.acl", "! nothing here\n")
    g = gate.GateResult([gate.audit_file(p, _POLICY)], "high")
    s = json.loads(gate.to_sarif(g))
    ids = {r["ruleId"] for r in s["runs"][0]["results"]}
    assert "RH-PARSE-000" in ids                # surfaces in code scanning
    parse_res = next(r for r in s["runs"][0]["results"]
                     if r["ruleId"] == "RH-PARSE-000")
    assert parse_res["level"] == "error"


def test_main_returns_2_on_unparseable(tmp_path):
    p = _write(str(tmp_path), "empty.acl", "! nothing\n")
    assert gate.main([p, "--fail-on", "high", "-q"]) == 2
    assert gate.main([p, "--fail-on", "none", "-q"]) == 0   # advisory opt-out


# --------------------------------------------------------------------------- #
# threshold semantics
# --------------------------------------------------------------------------- #
def _gate(tmp, fail_on):
    p = _write(str(tmp), "edge.acl", _CISCO)
    return gate.run_gate([p], _POLICY, fail_on)


def test_fail_on_high_blocks_on_critical(tmp_path):
    g = _gate(tmp_path, "high")
    assert not g.passed and g.worst == "critical"
    assert g.violations                         # critical >= high


def test_fail_on_critical_still_blocks_here(tmp_path):
    g = _gate(tmp_path, "critical")
    assert not g.passed                         # there IS a critical


def test_fail_on_none_never_blocks(tmp_path):
    g = _gate(tmp_path, "none")
    assert g.passed and g.violations == []
    assert g.worst == "critical"                # worst still reported, just not gated


def test_low_only_config_passes_at_high(tmp_path):
    # A redundant-only config (low) must NOT fail at --fail-on high.
    cfg = ("ip access-list extended R\n permit tcp any host 10.0.0.1 eq 443\n"
           " permit tcp host 1.2.3.4 host 10.0.0.1 eq 443\n")
    p = _write(str(tmp_path), "r.acl", cfg)
    g = gate.run_gate([p], None, "high")
    assert g.passed and g.worst == "low"
    g_low = gate.run_gate([p], None, "low")
    assert not g_low.passed                     # ...but fails when low is gated


def test_clean_config_passes(tmp_path):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    g = gate.run_gate([p], _POLICY, "high")
    assert g.passed and g.worst == "none"


# --------------------------------------------------------------------------- #
# info good-news is excluded from gating and SARIF
# --------------------------------------------------------------------------- #
def test_segmentation_ok_is_info_not_a_violation(tmp_path):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    g = gate.run_gate([p], _POLICY, "high")
    kinds = {f.kind for fr in g.files for f in fr.findings}
    assert "segmentation-ok" in kinds           # the PASS is recorded...
    assert g.real_findings == []                # ...but is not a "real" finding
    sarif = json.loads(gate.to_sarif(g))
    assert sarif["runs"][0]["results"] == []    # ...and never annotates a line


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 well-formedness
# --------------------------------------------------------------------------- #
def test_sarif_startline_exact_values(tmp_path):
    """SARIF physicalLocation.region.startLine must equal the ACE's source-file
    line number — not the rule sequence number and not a default 1.

    Pins the full path: ACE.line -> line_by_id / Finding.line -> line_of ->
    SARIF region.  The existing shape test only asserts startLine >= 1; this
    test asserts the exact values so a regression (e.g. seq number emitted
    instead of file line) is caught immediately."""
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    g = gate.run_gate([p], _POLICY, "high")
    s = json.loads(gate.to_sarif(g))
    by_kind = {r["ruleId"]: r["locations"][0]["physicalLocation"]["region"]["startLine"]
               for r in s["runs"][0]["results"]}
    # _CISCO layout: line 1 = ACL header; lines 2-5 = rules in order.
    assert by_kind["permit-any-any"] == 5        # `permit ip any any`     (seq 4)
    assert by_kind["segmentation-violation"] == 4 # `permit tcp any any eq 445` (seq 3)
    assert by_kind["redundant"] == 3              # the covered permit       (seq 2)


def test_line_of_falls_back_to_finding_line():
    """line_of must consult Finding.line when line_by_id cannot give a positive
    line number.  Two concrete cases:

      A. The entry in line_by_id exists but is 0 (parser did not track the line).
         Finding.line (set by analyze / segcheck) is the authoritative fallback.
      B. The rule_id is a zone-pair label (not acl:seq), so line_by_id has no
         entry.  Finding.line is the only source of truth.
      C. Both are absent/zero: hard minimum 1."""
    from rulehawk.analyze import Finding

    # Case A: line_by_id entry is 0, Finding.line carries the real line.
    f_a = Finding("EDGE:3", "permit-any-any", "critical", "msg", "r", line=9)
    fr_a = gate.FileResult("x.acl", "ios-asa", "ok", 1,
                           findings=[f_a], line_by_id={("EDGE", 3): 0})
    assert fr_a.line_of(f_a) == 9

    # Case B: zone-pair rule_id — no acl:seq parse possible, line_by_id empty.
    f_b = Finding("CORP!->PCI/tcp", "segmentation-indeterminate", "medium",
                  "msg", "", line=7)
    fr_b = gate.FileResult("x.acl", "ios-asa", "ok", 1,
                           findings=[f_b], line_by_id={})
    assert fr_b.line_of(f_b) == 7

    # Case C: both unknown — sentinel 1 (SARIF lower-bound).
    f_c = Finding("ZONE", "segmentation-ok", "info", "msg", "", line=0)
    fr_c = gate.FileResult("x.acl", "ios-asa", "ok", 1,
                           findings=[f_c], line_by_id={})
    assert fr_c.line_of(f_c) == 1


def test_sarif_shape_levels_and_lines(tmp_path):
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    g = gate.run_gate([p], _POLICY, "high")
    s = json.loads(gate.to_sarif(g))
    assert s["version"] == "2.1.0" and "$schema" in s
    run = s["runs"][0]
    drv = run["tool"]["driver"]
    assert drv["name"] == "RuleHawk"
    # every result references a declared rule, an error/warning/note level, and a
    # concrete >=1 startLine on the right file.
    rule_ids = {r["id"] for r in drv["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note")
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].endswith("edge.acl")
        assert loc["region"]["startLine"] >= 1
        assert "partialFingerprints" in res
    # criticals/highs map to error; the redundant (low) maps to note.
    by_kind = {r["ruleId"]: r["level"] for r in run["results"]}
    assert by_kind["permit-any-any"] == "error"
    assert by_kind["segmentation-violation"] == "error"
    assert by_kind["redundant"] == "note"
    # security-severity band present for code-scanning sorting.
    paa_rule = next(r for r in drv["rules"] if r["id"] == "permit-any-any")
    assert paa_rule["properties"]["security-severity"] == "9.5"


def test_sarif_fingerprints_distinct_per_zone_pair():
    """One permissive rule that breaches several boundaries yields several
    segmentation-violation Findings that SHARE rule_id ({acl}:{seq}), kind, and
    startLine — differing only in their witness. Their SARIF partialFingerprints
    must stay DISTINCT so GitHub code scanning keeps each real breach as its own
    alert instead of collapsing them into one (which would hide genuine
    isolation failures — the engine's 'never a false bill of health' promise)."""
    from rulehawk.analyze import Finding
    # `permit ip any any` at seq 30 breaching CORP->PCI, DMZ->PCI, CORP->DB:
    # identical rule_id / kind / line, three different witnesses.
    findings = [
        Finding("EDGE:30", "segmentation-violation", "critical",
                "CORP must not reach PCI", "permit ip any any",
                witness="10.1.0.1 -> 10.9.0.1 (ip)", line=30),
        Finding("EDGE:30", "segmentation-violation", "critical",
                "DMZ must not reach PCI", "permit ip any any",
                witness="10.2.0.1 -> 10.9.0.1 (ip)", line=30),
        Finding("EDGE:30", "segmentation-violation", "critical",
                "CORP must not reach DB", "permit ip any any",
                witness="10.1.0.1 -> 10.8.0.1 (ip)", line=30),
    ]
    fr = gate.FileResult("edge.acl", "ios-asa", "ok", 1,
                         findings=findings, line_by_id={("EDGE", 30): 30})
    g = gate.GateResult([fr], "high")
    s = json.loads(gate.to_sarif(g))
    results = s["runs"][0]["results"]
    assert len(results) == 3
    fps = [r["partialFingerprints"]["ruleHawk/v2"] for r in results]
    # All three genuine breaches must be uniquely fingerprinted.
    assert len(set(fps)) == 3, fps
    # And the witness must be what disambiguates them: the same finding with
    # only the witness changed hashes differently; an identical twin does not.
    base, other = findings[0], findings[1]
    assert gate._fingerprint("edge.acl", base) != gate._fingerprint("edge.acl", other)
    twin = Finding("EDGE:30", "segmentation-violation", "critical",
                   base.message, base.rule, witness=base.witness, line=30)
    assert gate._fingerprint("edge.acl", twin) == gate._fingerprint("edge.acl", base)


# --------------------------------------------------------------------------- #
# JSON aggregate + markdown + console
# --------------------------------------------------------------------------- #
def test_json_aggregate_shape(tmp_path):
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    g = gate.run_gate([p], _POLICY, "high")
    d = json.loads(gate.to_json(g))
    assert d["passed"] is False and d["worst_severity"] == "critical"
    assert d["fail_on"] == "high" and d["files_audited"] == 1
    assert d["findings_by_severity"]["critical"] >= 2
    f0 = d["files"][0]
    assert f0["vendor"] == "ios-asa" and f0["status"] == "ok"
    assert all("line" in finding for finding in f0["findings"])


def test_markdown_carries_witness_and_verdict(tmp_path):
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    g = gate.run_gate([p], _POLICY, "high")
    md = gate.to_markdown(g)
    assert "FAIL" in md
    assert "10.20.0.1 -> 10.10.0.1:445 (tcp)" in md      # the witness packet
    assert "Segmentation violations" in md
    # the sticky-comment body carries the dedup marker.
    assert gate.comment_body(g).startswith(gate._COMMENT_MARKER)


def test_worst_and_json_survive_unknown_severity():
    # Defensive: engine findings always carry a known severity, but `worst` and
    # `to_json` must not crash if an unexpected one ever appears (no KeyError).
    from rulehawk.analyze import Finding
    fr = gate.FileResult("x.acl", "ios-asa", "ok", 1,
                         findings=[Finding("x:1", "weird", "bogus", "m", "r")])
    g = gate.GateResult([fr], "high")
    assert g.worst == "bogus"            # unknown rank 0, still surfaced, no crash
    assert g.passed                      # rank 0 < high threshold -> not a violation
    json.loads(gate.to_json(g))          # must not raise
    json.loads(gate.to_sarif(g))         # must not raise


def test_console_is_emoji_light_and_greppable(tmp_path):
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    g = gate.run_gate([p], _POLICY, "high")
    out = gate.to_console(g)
    assert "VERDICT: FAIL" in out and "CRITICAL segmentation-violation" in out


# --------------------------------------------------------------------------- #
# main(): exit codes + file outputs
# --------------------------------------------------------------------------- #
def test_main_returns_1_on_fail_and_writes_outputs(tmp_path):
    d = str(tmp_path)
    p = _write(d, "edge.acl", _CISCO)
    pol = _write(d, "policy.json", json.dumps(_POLICY))
    sarif = os.path.join(d, "out.sarif")
    js = os.path.join(d, "out.json")
    rc = gate.main([p, "--policy", pol, "--fail-on", "high",
                    "--sarif", sarif, "--json", js, "-q"])
    assert rc == 1
    assert os.path.exists(sarif) and os.path.exists(js)
    json.loads(open(sarif).read())              # valid JSON
    assert json.loads(open(js).read())["passed"] is False


def test_main_returns_0_on_clean(tmp_path):
    d = str(tmp_path)
    p = _write(d, "clean.acl", _CLEAN)
    pol = _write(d, "policy.json", json.dumps(_POLICY))
    rc = gate.main([p, "--policy", pol, "--fail-on", "high", "-q"])
    assert rc == 0


def test_main_writes_github_step_summary_env(tmp_path, monkeypatch):
    d = str(tmp_path)
    p = _write(d, "edge.acl", _CISCO)
    summary = os.path.join(d, "step_summary.md")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", summary)
    rc = gate.main([p, "-q", "--fail-on", "high"])
    assert rc == 1
    assert "RuleHawk firewall gate" in open(summary).read()


def test_main_bad_fail_on_is_usage_error(tmp_path):
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    assert gate.main([p, "--fail-on", "bogus"]) == 2


def test_main_unknown_vendor_is_usage_error(tmp_path, capsys):
    """A --vendor typo must error out (exit 2), never silently fall back to
    the ios-asa parser and audit under the wrong grammar."""
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    assert gate.main([p, "--vendor", "cisc0"]) == 2
    err = capsys.readouterr().err
    assert "unknown --vendor" in err and "cisc0" in err
    # The error should teach the full vendor list, including nxos/eos.
    assert "nxos" in err and "eos" in err


def test_main_known_vendor_aliases_accepted(tmp_path, capsys):
    """Every alias in _VENDORS (and 'auto', any case) passes validation.

    A forced vendor on a mismatched file may still exit 2 via the fail-closed
    no_rules_parsed path — that is correct — so we assert on the *reason*:
    no 'unknown --vendor' usage error may appear for a valid alias."""
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    for v in list(gate._VENDORS) + ["auto", "IOS", "Arista"]:
        gate.main([p, "--vendor", v, "-q"])
        assert "unknown --vendor" not in capsys.readouterr().err, \
            f"valid vendor {v!r} rejected as unknown"


def test_main_no_match_is_error(tmp_path):
    assert gate.main([os.path.join(str(tmp_path), "nope-*.acl")]) == 2


def test_main_partial_pattern_miss_fails_closed(tmp_path):
    # One good file + one typo'd pattern: the gate must refuse to run a partial
    # audit and call it green (the typo'd firewall would never be audited).
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    assert gate.main([p, os.path.join(str(tmp_path), "typo-*.acl"), "-q"]) == 2


def test_main_unknown_vendor_is_usage_error(tmp_path):
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    assert gate.main([p, "--vendor", "iptable", "-q"]) == 2   # typo'd vendor


def test_main_unknown_flag_is_usage_error(tmp_path):
    # `--fail-onn low` used to be silently dropped (default threshold kept,
    # `low` treated as a file pattern) — the user's intent ignored twice.
    p = _write(str(tmp_path), "edge.acl", _CISCO)
    assert gate.main([p, "--fail-onn", "low", "-q"]) == 2


def test_main_unwritable_output_is_error_not_traceback(tmp_path):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    bad = os.path.join(str(tmp_path), "no-such-dir", "out.sarif")
    assert gate.main([p, "--sarif", bad, "-q"]) == 2


def test_main_semantically_bad_policy_fails_closed(tmp_path):
    # Valid JSON, invalid content (bad CIDR): must be a policy-error finding
    # that blocks at the default threshold — never a traceback, never a PASS.
    d = str(tmp_path)
    p = _write(d, "clean.acl", _CLEAN)
    pol = _write(d, "policy.json", json.dumps(
        {"zones": {"PCI": ["10.10.0.0/33"], "CORP": ["10.20.0.0/16"]},
         "must_not_reach": [{"src": "CORP", "dst": "PCI"}]}))
    assert gate.main([p, "--policy", pol, "-q"]) == 1


# --------------------------------------------------------------------------- #
# SARIF fingerprint stability + URI anchoring
# --------------------------------------------------------------------------- #
def _fingerprints(g):
    s = json.loads(gate.to_sarif(g))
    return {r["ruleId"]: r["partialFingerprints"]["ruleHawk/v2"]
            for r in s["runs"][0]["results"]}


def test_fingerprints_survive_unrelated_insertion(tmp_path):
    # Inserting an unrelated rule ABOVE shifts every seq; the alert identity
    # (content-based fingerprint) must not change, or code scanning would
    # close-and-reopen every downstream alert on each PR.
    d = str(tmp_path)
    p = _write(d, "edge.acl", _CISCO)
    before = _fingerprints(gate.run_gate([p], _POLICY, "high"))
    inserted = _CISCO.replace(
        " permit tcp any host 203.0.113.10 eq 443\n",
        " permit udp host 192.0.2.9 host 203.0.113.9 eq 53\n"
        " permit tcp any host 203.0.113.10 eq 443\n")
    p2 = _write(d, "edge.acl", inserted)
    after = _fingerprints(gate.run_gate([p2], _POLICY, "high"))
    for kind, fp in before.items():
        assert after.get(kind) == fp, f"fingerprint churn for {kind}"


def test_distinct_violations_on_one_rule_get_distinct_fingerprints(tmp_path):
    # Two breached boundaries via the SAME permit must stay two alerts.
    d = str(tmp_path)
    p = _write(d, "edge.acl", _CISCO)
    pol = {
        "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"],
                  "DMZ": ["10.30.0.0/16"]},
        "must_not_reach": [
            {"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]},
            {"src": "DMZ", "dst": "PCI", "proto": "tcp", "ports": [445]},
        ],
    }
    s = json.loads(gate.to_sarif(gate.run_gate([p], pol, "high")))
    fps = [r["partialFingerprints"]["ruleHawk/v2"]
           for r in s["runs"][0]["results"]
           if r["ruleId"] == "segmentation-violation"]
    assert len(fps) == 2 and len(set(fps)) == 2


def test_sarif_uri_is_workspace_relative(tmp_path, monkeypatch):
    # With working-directory below the checkout root, the URI must still be
    # repo-root-relative or GitHub attaches annotations to a nonexistent path.
    d = str(tmp_path)
    sub = os.path.join(d, "network")
    os.makedirs(sub)
    p = _write(sub, "edge.acl", _CISCO)
    monkeypatch.setenv("GITHUB_WORKSPACE", d)
    monkeypatch.chdir(sub)
    s = json.loads(gate.to_sarif(gate.run_gate(["edge.acl"], None, "high")))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in s["runs"][0]["results"]}
    assert uris == {"network/edge.acl"}
    assert p  # silence lint
