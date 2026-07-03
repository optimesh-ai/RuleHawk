"""Fail-closed verdict RENDERING — the words the end user actually sees.

tests/test_gate.py proves the gate's *logic* (exit codes, thresholds, SARIF).
This file pins the *rendered verdicts* — the sticky PR comment / Step Summary
(`to_markdown`) and the CI log (`to_console`) — for the three states that had
never been exercised end-to-end:

  1. error            — a file the runner cannot READ (directory, chmod-000)
                        must surface as status 'error', exit 2, and render the
                        fail-closed wording in both renderers;
  2. no_rules_parsed  — an empty/garbage file must render the 'no rules parsed
                        ... not a clean bill of health' block and exit 2;
  3. PASS             — a clean gate must render the exact '**PASS**' verdict
                        (the one line every green PR shows) and exit 0.

Plus the forced --vendor nxos/eos parser picks through main(), the unreadable
--policy usage error (exit 2), and the _split_rule_id non-digit-seq guard.

The verdict substrings are pinned EXACTLY: a wording regression in the PR
comment — or worse, an unreadable file no longer failing closed — must go red.
All tests are additive; no engine files are touched.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate  # noqa: E402

# A clean Cisco ACL: scoped permits + a default deny (same as test_gate._CLEAN).
_CLEAN = """ip access-list extended CLEAN
 permit tcp 10.20.0.0 0.0.255.255 host 10.20.5.5 eq 443
 deny ip any any
"""

# A Cisco ACL with a critical permit-any-any (drives the FAIL+unparseable mix).
_DIRTY = """ip access-list extended EDGE
 permit ip any any
"""

# A vendor-neutral numbered ACL: parses under BOTH the NX-OS and EOS frontends
# when forced, with no auto-detect markers — so the vendor label in the output
# can only come from the forced --vendor pick (_pick_parser lines 189-191).
_NUMBERED = """ip access-list CORP-IN
  10 permit tcp 10.0.0.0/8 any eq 22
  20 deny ip any any
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
# 1. unreadable file — the fail-closed 'error' path, end to end
# --------------------------------------------------------------------------- #
def test_unreadable_path_is_error_exit2_and_rendered(tmp_path):
    """A path that cannot be read (here: a directory) must become
    FileResult.status 'error' — never a silent skip or a clean pass — and the
    fail-closed verdict must render in BOTH the PR comment and the CI log."""
    d = os.path.join(str(tmp_path), "iamadir")
    os.makedirs(d)
    g = gate.run_gate([d], _POLICY, "high")

    fr = g.files[0]
    assert fr.status == "error"
    assert fr.n_rules == 0 and fr.score is None      # NOT a clean bill of health
    assert fr.error                                  # the OSError text is kept
    assert g.parse_failures == [fr]
    assert g.exit_code() == 2 and not g.passed       # fail-closed exit code

    md = gate.to_markdown(g)
    # exact fail-closed verdict wording (gate.py:499-501)
    assert "**FAIL (fail-closed)**" in md
    assert "1 file(s) parsed to zero rules" in md
    assert "not a clean bill of health" in md
    # the per-file error block (gate.py:543-544) names the file and the cause
    assert "ERROR, could not read:" in md
    assert fr.error in md
    assert "❌" in md and "**PASS**" not in md

    con = gate.to_console(g)
    # the greppable error row (gate.py:619) + fail-closed verdict (640-643)
    assert f"[ERROR] {fr.path}: {fr.error}" in con
    assert "VERDICT: FAIL (exit 2, fail-closed)" in con
    assert "cannot certify isolation" in con
    assert "VERDICT: PASS" not in con


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root ignores file permissions")
def test_chmod_000_file_fails_closed_via_audit_file(tmp_path):
    """The audit_file OSError entry point (gate.py:210-211): a chmod-000 config
    must yield status 'error' and drive exit 2 — a permission-denied config can
    never masquerade as clean."""
    p = _write(str(tmp_path), "locked.acl", _CLEAN)
    os.chmod(p, 0o000)
    try:
        fr = gate.audit_file(p, _POLICY)
        assert fr.status == "error" and fr.vendor == "?"
        assert "Permission denied" in fr.error
        g = gate.GateResult([fr], "high")
        assert g.exit_code() == 2
        assert "VERDICT: FAIL (exit 2, fail-closed)" in gate.to_console(g)
        assert "**FAIL (fail-closed)**" in gate.to_markdown(g)
    finally:
        os.chmod(p, 0o644)                           # let tmp_path clean up


# --------------------------------------------------------------------------- #
# 2. PASS — the verdict line every green PR shows (gate.py:497)
# --------------------------------------------------------------------------- #
def test_pass_verdict_rendered_in_markdown_and_console(tmp_path):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    g = gate.run_gate([p], _POLICY, "high")
    assert g.passed and g.exit_code() == 0

    md = gate.to_markdown(g)
    # exact PASS wording — the first line a reviewer reads on a green gate
    assert "**PASS** — no findings at or above `high`." in md
    assert "✅" in md and "FAIL" not in md
    # the proven isolation is celebrated, not hidden
    assert "Segmentation proven:" in md
    # privacy promise footer is always present
    assert "never leaves your infrastructure" in md

    con = gate.to_console(g)
    assert "VERDICT: PASS (threshold --fail-on high)" in con
    assert "[ok   ]" in con or "[ok" in con
    assert "FAIL" not in con


# --------------------------------------------------------------------------- #
# 3. no_rules_parsed — empty/garbage file renders the fail-closed block
# --------------------------------------------------------------------------- #
def test_garbage_file_renders_no_rules_block_and_exits_2(tmp_path):
    p = _write(str(tmp_path), "garbled.acl", "!! not a firewall config ??\n")
    g = gate.run_gate([p], _POLICY, "high")
    assert g.exit_code() == 2
    assert g.files[0].status == "no_rules_parsed"

    md = gate.to_markdown(g)
    assert "**FAIL (fail-closed)**" in md
    # the per-file block (gate.py:547-554)
    assert "no rules parsed" in md
    assert "not a clean bill of health" in md
    assert "check the vendor/format" in md.replace("\n", " ")

    con = gate.to_console(g)
    # the greppable warn row (gate.py:621-622) + fail-closed verdict
    assert "[WARN ]" in con and "no rules parsed" in con
    assert "VERDICT: FAIL (exit 2, fail-closed)" in con
    assert "1 file(s) parsed to zero rules; cannot certify isolation" in con


def test_fail_verdict_mentions_unparseable_extras(tmp_path):
    """When real violations AND an unparseable file coexist, the FAIL verdict
    must disclose both (gate.py:503-505) — the unreadable file may not hide
    behind the findings."""
    d = str(tmp_path)
    dirty = _write(d, "edge.acl", _DIRTY)
    empty = _write(d, "empty.acl", "! nothing\n")
    g = gate.run_gate([dirty, empty], None, "high")
    assert g.exit_code() == 2                        # parse failure outranks 1
    md = gate.to_markdown(g)
    assert "**FAIL**" in md
    assert "plus 1 unparseable file(s)" in md


# --------------------------------------------------------------------------- #
# 4. forced --vendor nxos / eos through main() (gate.py:194,196 forced picks)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vendor,alias", [("nxos", "nxos"), ("nxos", "nexus"),
                                          ("eos", "eos"), ("eos", "arista")])
def test_main_forced_vendor_nxos_eos_label(tmp_path, vendor, alias):
    d = str(tmp_path)
    p = _write(d, "numbered.acl", _NUMBERED)
    js = os.path.join(d, f"out-{alias}.json")
    rc = gate.main([p, "--vendor", alias, "--json", js, "-q"])
    doc = json.loads(open(js).read())
    f0 = doc["files"][0]
    # the forced parser actually ran AND parsed real rules under that grammar
    assert f0["vendor"] == vendor
    assert f0["status"] == "ok" and f0["rules_analyzed"] == 2
    assert rc == 0                                   # clean, scoped ACL


def test_forced_vendor_label_in_renderers(tmp_path):
    """The vendor label the user sees in the report must reflect the forced
    pick, for both markdown and console."""
    p = _write(str(tmp_path), "numbered.acl", _NUMBERED)
    for v in ("nxos", "eos"):
        g = gate.run_gate([p], None, "high", vendor=v)
        assert g.files[0].vendor == v and g.passed
        assert f"({v}, 2 rules" in gate.to_markdown(g)
        assert f"({v}, 2 rules" in gate.to_console(g)


# --------------------------------------------------------------------------- #
# 5. unreadable --policy is a hard usage error (gate.py:730-733)
# --------------------------------------------------------------------------- #
def test_main_unreadable_policy_exits_2(tmp_path, capsys):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    missing = os.path.join(str(tmp_path), "no-such-policy.json")
    assert gate.main([p, "--policy", missing, "-q"]) == 2
    assert "cannot read policy" in capsys.readouterr().err


def test_main_invalid_policy_json_exits_2(tmp_path, capsys):
    """A present-but-garbled policy is the same failure class (ValueError):
    the gate must refuse to run with a policy it cannot trust, never silently
    audit without segmentation checks."""
    d = str(tmp_path)
    p = _write(d, "clean.acl", _CLEAN)
    pol = _write(d, "policy.json", "{ not json")
    assert gate.main([p, "--policy", pol, "-q"]) == 2
    assert "cannot read policy" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# auto-detect picks the nxos/eos frontends inside the gate (not just forced)
# --------------------------------------------------------------------------- #
def test_autodetect_nxos_and_eos_in_gate(tmp_path):
    d = str(tmp_path)
    nxos = _write(d, "nexus.cfg",
                  "version 9.3(10)\n"
                  "ip access-list CORP-IN\n"
                  "  10 permit tcp 10.0.0.0/8 any eq 22\n"
                  "  20 deny ip any any\n")
    eos = _write(d, "arista.cfg",
                 "! Command: show running-config\n"
                 "ip access-list CORP-IN\n"
                 "   10 permit tcp 10.0.0.0/8 any eq 22\n"
                 "   20 deny ip any any\n")
    junos = _write(d, "srx.conf",
                   "firewall {\n"
                   "    filter EDGE {\n"
                   "        term allow-ssh {\n"
                   "            from { source-address 10.0.0.0/8; "
                   "protocol tcp; destination-port 22; }\n"
                   "            then accept;\n"
                   "        }\n"
                   "        term deny-all { then discard; }\n"
                   "    }\n"
                   "}\n")
    panos = _write(d, "pa.set",
                   "set rulebase security rules allow-web from CORP to DMZ "
                   "source 10.0.0.0/8 destination 10.20.0.0/16 "
                   "application any service service-https action allow\n")
    g = gate.run_gate([nxos, eos, junos, panos], None, "high")  # vendor=auto
    assert [fr.vendor for fr in g.files] == ["nxos", "eos", "junos", "panos"]
    assert all(fr.status == "ok" for fr in g.files)
    assert g.passed


# --------------------------------------------------------------------------- #
# renderer plumbing users see: parse notes, --comment, stdout emit, console
# --------------------------------------------------------------------------- #
def test_notes_block_renders_and_caps():
    out = gate._notes_block([f"note {i}" for i in range(30)], cap=25)
    assert "<i>Parse notes (30):</i>" in out[1]
    assert "- note 0" in out and "- note 24" in out
    assert "- note 25" not in "\n".join(out)         # capped...
    assert out[-1] == "- …and 5 more (see `--json`)."  # ...and says so honestly


def test_notes_render_for_parsed_file_in_markdown(tmp_path):
    # An iptables config with an unmodeled extension: rules parse (status ok)
    # AND a parse note is surfaced in the per-file markdown block (gate.py:582).
    p = _write(str(tmp_path), "host.rules",
               "*filter\n"
               ":FORWARD DROP [0:0]\n"
               "-A FORWARD -m connlimit --connlimit-above 10 -j REJECT\n"
               "-A FORWARD -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT\n"
               "COMMIT\n")
    g = gate.run_gate([p], None, "high")
    fr = g.files[0]
    assert fr.status == "ok" and fr.notes            # parsed, with honest notes
    assert "Parse notes" in gate.to_markdown(g)


def test_main_writes_sticky_comment_and_stdout_summary(tmp_path, capsys):
    d = str(tmp_path)
    p = _write(d, "clean.acl", _CLEAN)
    comment = os.path.join(d, "comment.md")
    rc = gate.main([p, "--comment", comment, "--summary", "-", "-q"])
    assert rc == 0
    body = open(comment).read()
    assert body.startswith(gate._COMMENT_MARKER)     # sticky-update anchor first
    assert "**PASS** — no findings at or above `high`." in body
    # --summary - streams the same PASS report to stdout (gate.py:761-762)
    assert "**PASS**" in capsys.readouterr().out


def test_main_prints_console_report_unless_quiet(tmp_path, capsys):
    p = _write(str(tmp_path), "clean.acl", _CLEAN)
    assert gate.main([p]) == 0                       # no -q
    assert "VERDICT: PASS" in capsys.readouterr().out
    assert gate.main([p, "-q"]) == 0
    assert "VERDICT" not in capsys.readouterr().out  # -q suppresses it


# --------------------------------------------------------------------------- #
# CLI usage errors: help, no files, flag missing its value
# --------------------------------------------------------------------------- #
def test_main_help_and_empty_argv(capsys):
    assert gate.main(["--help"]) == 0                # asked for help: success
    assert "rulehawk gate" in capsys.readouterr().out
    assert gate.main([]) == 2                        # no args: usage error


def test_main_no_patterns_is_usage_error(capsys):
    assert gate.main(["--fail-on", "high"]) == 2
    assert "no config files/globs given" in capsys.readouterr().err


def test_take_flag_missing_value_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        gate._take(["--policy"], "--policy")
    assert exc.value.code == 2
    assert "--policy requires a value" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# _split_rule_id: non-digit seq guard (gate.py:159-160)
# --------------------------------------------------------------------------- #
def test_split_rule_id_non_digit_seq_is_none():
    # colon present but the trailing segment is not a sequence number -> None
    assert gate._split_rule_id("EDGE:abc") is None
    assert gate._split_rule_id("EDGE:") is None
    # no colon at all (zone-pair label) -> None via the early guard
    assert gate._split_rule_id("CORP!->PCI/tcp") is None
    # the happy path still holds (rsplit keeps colons inside the acl name)
    assert gate._split_rule_id("EDGE:4") == ("EDGE", 4)
    assert gate._split_rule_id("a:b:7") == ("a:b", 7)
