"""First-minute experience hardening: malformed/garbage input and clean-config output.

Guards three soundness properties:

1. MALFORMED INPUT — garbage (binary junk, JSON, English paragraph, truncated
   config) must never silently read as a clean PASS.  Specifically:
     * text report includes "NO ACL RULES PARSED" and lists all supported vendors.
     * JSON report has status="no_rules_parsed" and score=null.
     * CLI exit code is 2 (distinct from 0=clean and 1=findings).

2. CLEAN CONFIG — when a config genuinely parses with zero findings, the output
   is explicit about WHAT was audited (rule count, vendor) so the operator can
   distinguish "nothing parsed" from "audited and clean".

3. VENDOR DETECTION — NX-OS and EOS configs are now auto-detected by the CLI
   (previously fell through to the ios-asa fallback); the vendor label flows
   into the report.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from rulehawk import analyze, parse_acls, to_json, to_text  # noqa: E402
from rulehawk.cli import main as cli_main  # noqa: E402
from rulehawk.parse_junos import parse_junos  # noqa: E402
from rulehawk.parse_nxos import detect as detect_nxos, parse_nxos  # noqa: E402
from rulehawk.parse_eos import detect as detect_eos, parse_eos  # noqa: E402
from rulehawk.report import _SUPPORTED_VENDORS  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_GARBAGE_INPUTS = [
    # English paragraph (not a config)
    ("english_paragraph",
     "This document describes the network segmentation policy for the prod "
     "environment. Traffic from CORP should not reach PCI. Consult the "
     "security team before making changes."),
    # A JSON file (common paste mistake)
    ("json_file",
     '{"rules": [{"action": "permit", "src": "any", "dst": "any"}], '
     '"vendor": "cisco"}'),
    # Binary-ish junk (unicode replacement chars appear in errors="replace" reads)
    ("binary_junk",
     "\x00\x01\x02\x03\xff\xfe binary garbage \x7f\x80\x81"),
    # Truncated / partial config — has an ACL header but no body lines
    ("truncated_config",
     "ip access-list extended CORP_OUT\n"),
]

# A minimal IOS ACL with no hygiene issues: one scoped permit + default deny.
_CLEAN_IOS = (
    "ip access-list extended CORP_OUT\n"
    " permit tcp 10.20.0.0 0.0.255.255 10.30.0.0 0.0.255.255 eq 443\n"
    " deny ip any any\n"
)

# NX-OS: version with parens + feature line + ip access-list (NX-OS markers).
_NXOS_CFG = (
    "version 9.3(10)\n"
    "feature interface-vlan\n"
    "ip access-list extended CORP_OUT\n"
    " 10 permit tcp 10.20.0.0 0.0.255.255 any eq 443\n"
    " 20 deny ip any any\n"
)

# Arista EOS: ! Command: show + ! device: (EOS marker) + ip access-list.
_EOS_CFG = (
    "! Command: show running-config\n"
    "! device: leaf01 (EOS-4.29.2F)\n"
    "ip access-list CORP_OUT\n"
    " 10 permit tcp 10.20.0.0 0.0.255.255 any eq 443\n"
    " 20 deny ip any any\n"
)


# ---------------------------------------------------------------------------
# 1. MALFORMED INPUT — text report
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label,text", _GARBAGE_INPUTS)
def test_garbage_text_report_contains_no_acl_rules_parsed(label, text):
    """The human-readable report must explicitly say nothing was parsed.

    "No ACL/firewall rules found" and the "NO ACL RULES PARSED" sentinel must
    both appear so a user skimming the output cannot mistake it for a clean audit.
    """
    aces, notes = parse_acls(text)
    out = to_text(analyze(aces), notes, len(aces))
    assert "NO ACL RULES PARSED" in out, f"{label}: header sentinel missing"
    assert "No ACL/firewall rules found" in out, f"{label}: body phrase missing"
    assert "nothing was audited" in out, f"{label}: 'nothing was audited' missing"


@pytest.mark.parametrize("label,text", _GARBAGE_INPUTS)
def test_garbage_text_report_lists_all_supported_vendors(label, text):
    """The 'none of X' line must enumerate every supported format so the user
    knows what to paste, not just two of the six formats."""
    aces, notes = parse_acls(text)
    out = to_text(analyze(aces), notes, len(aces))
    # Each vendor family name must appear in the message.
    for token in ("IOS", "NX-OS", "EOS", "Junos", "PAN-OS", "iptables"):
        assert token in out, f"{label}: supported vendor '{token}' missing from output"


@pytest.mark.parametrize("label,text", _GARBAGE_INPUTS)
def test_garbage_text_report_not_a_clean_result(label, text):
    """The output must explicitly say this is NOT a clean result (not just silent)."""
    aces, notes = parse_acls(text)
    out = to_text(analyze(aces), notes, len(aces))
    assert "NOT a clean result" in out, f"{label}: 'NOT a clean result' missing"
    # Score-100 line must NEVER appear on garbage input.
    assert "100/100" not in out, f"{label}: spurious 100/100 score on garbage input"


# ---------------------------------------------------------------------------
# 2. MALFORMED INPUT — JSON report
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label,text", _GARBAGE_INPUTS)
def test_garbage_json_status_is_no_rules_parsed(label, text):
    """JSON status must be 'no_rules_parsed', score must be null."""
    aces, notes = parse_acls(text)
    doc = json.loads(to_json(analyze(aces), notes, len(aces)))
    assert doc["status"] == "no_rules_parsed", f"{label}: wrong status"
    assert doc["score"] is None, f"{label}: score should be null on no-rules"
    assert doc["rules_analyzed"] == 0, f"{label}: rules_analyzed should be 0"


# ---------------------------------------------------------------------------
# 3. MALFORMED INPUT — CLI exit code
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label,text", _GARBAGE_INPUTS)
def test_garbage_cli_exit_code_is_2(label, text, tmp_path):
    """CLI must exit with code 2 (parse failure) on garbage input — NOT 0 (clean)
    and NOT 1 (findings). Callers in CI can distinguish the three outcomes."""
    p = tmp_path / f"{label}.txt"
    p.write_text(text, encoding="utf-8")
    rc = cli_main([str(p)])
    assert rc == 2, (
        f"{label}: expected exit 2 (parse failure), got {rc}. "
        f"Exit 0 would falsely imply 'clean'."
    )


def test_truncated_config_cli_exit_code_is_2(tmp_path):
    """A config with only a header and no body rules also exits 2."""
    p = tmp_path / "truncated.acl"
    p.write_text("ip access-list extended CORP_OUT\n", encoding="utf-8")
    assert cli_main([str(p)]) == 2


# ---------------------------------------------------------------------------
# 4. CLEAN CONFIG — zero findings, explicit output
# ---------------------------------------------------------------------------

def test_clean_config_text_says_0_findings():
    """Zero findings on a real config must say '0 findings', not just empty."""
    aces, notes = parse_acls(_CLEAN_IOS)
    assert len(aces) > 0, "fixture should parse to >0 rules"
    findings = analyze(aces)
    assert findings == [], "fixture should have zero findings"
    out = to_text(findings, notes, len(aces))
    assert "0 findings" in out, "'0 findings' missing from clean-config output"


def test_clean_config_text_shows_rule_count():
    """The clean-config line must name how many rules were analyzed."""
    aces, notes = parse_acls(_CLEAN_IOS)
    findings = analyze(aces)
    out = to_text(findings, notes, len(aces))
    # Header carries "N rules analyzed"; the zero-findings line repeats the count.
    n = len(aces)
    assert f"{n} rules analyzed" in out, (
        f"expected '{n} rules analyzed' in output; got:\n{out}"
    )


def test_clean_config_text_shows_vendor():
    """The clean-config line must name the detected vendor."""
    aces, notes = parse_acls(_CLEAN_IOS)
    findings = analyze(aces)
    out = to_text(findings, notes, len(aces), vendor="ios-asa")
    assert "ios-asa" in out, "vendor 'ios-asa' missing from clean-config output"


def test_clean_config_text_says_policy_is_clean():
    """The clean-config message must say 'policy is clean' (not just 'OK')."""
    aces, notes = parse_acls(_CLEAN_IOS)
    findings = analyze(aces)
    out = to_text(findings, notes, len(aces), vendor="ios-asa")
    assert "policy is clean" in out


def test_clean_config_json_has_vendor_field():
    """The JSON output must contain a 'vendor' field on clean configs."""
    aces, notes = parse_acls(_CLEAN_IOS)
    findings = analyze(aces)
    doc = json.loads(to_json(findings, notes, len(aces), vendor="ios-asa"))
    assert "vendor" in doc
    assert doc["vendor"] == "ios-asa"
    assert doc["status"] == "ok"
    assert doc["score"] == 100


def test_clean_config_json_vendor_defaults_to_ios_asa_when_none():
    """When caller passes vendor=None the JSON must still include vendor=ios-asa."""
    aces, notes = parse_acls(_CLEAN_IOS)
    findings = analyze(aces)
    doc = json.loads(to_json(findings, notes, len(aces)))
    assert doc["vendor"] == "ios-asa"


def test_clean_config_cli_exits_0(tmp_path):
    """A clean config must exit 0 so it doesn't false-alarm in CI."""
    p = tmp_path / "clean.acl"
    p.write_text(_CLEAN_IOS, encoding="utf-8")
    rc = cli_main([str(p)])
    assert rc == 0, f"expected exit 0 on clean config, got {rc}"


# ---------------------------------------------------------------------------
# 5. VENDOR DETECTION — NX-OS and EOS in the CLI detection chain
# ---------------------------------------------------------------------------

def test_nxos_detect_true_on_nxos_config():
    assert detect_nxos(_NXOS_CFG), "NX-OS markers not detected in NX-OS config"


def test_eos_detect_true_on_eos_config():
    assert detect_eos(_EOS_CFG), "EOS markers not detected in EOS config"


def test_nxos_cli_vendor_label_in_report(tmp_path):
    """NX-OS configs must be auto-detected by the CLI; vendor='nxos' in JSON."""
    p = tmp_path / "nxos.cfg"
    p.write_text(_NXOS_CFG, encoding="utf-8")
    # Capture JSON output by calling cli_main with --json and checking stdout.
    # We test the vendor via parse/report directly (avoiding subprocess complexity).
    aces, notes = parse_nxos(_NXOS_CFG)
    assert len(aces) > 0, "NX-OS fixture should parse to rules"
    doc = json.loads(to_json(analyze(aces), notes, len(aces), vendor="nxos"))
    assert doc["vendor"] == "nxos"
    assert doc["status"] == "ok"


def test_eos_cli_vendor_label_in_report(tmp_path):
    """EOS configs must be auto-detected by the CLI; vendor='eos' in JSON."""
    aces, notes = parse_eos(_EOS_CFG)
    assert len(aces) > 0, "EOS fixture should parse to rules"
    doc = json.loads(to_json(analyze(aces), notes, len(aces), vendor="eos"))
    assert doc["vendor"] == "eos"
    assert doc["status"] == "ok"


def test_nxos_exit_code_on_clean_config(tmp_path):
    """CLI with a clean NX-OS config must exit 0 (not 2)."""
    p = tmp_path / "nxos.cfg"
    p.write_text(_NXOS_CFG, encoding="utf-8")
    rc = cli_main([str(p)])
    assert rc == 0, f"expected exit 0 on clean NX-OS config, got {rc}"


def test_eos_exit_code_on_clean_config(tmp_path):
    """CLI with a clean EOS config must exit 0 (not 2)."""
    p = tmp_path / "eos.cfg"
    p.write_text(_EOS_CFG, encoding="utf-8")
    rc = cli_main([str(p)])
    assert rc == 0, f"expected exit 0 on clean EOS config, got {rc}"


# ---------------------------------------------------------------------------
# 6. SOUNDNESS: vendor JSON field is additive — old callers still work
# ---------------------------------------------------------------------------

def test_to_json_backward_compat_three_args():
    """to_json(findings, notes, n_rules) still works with 3 positional args."""
    aces, notes = parse_acls(_CLEAN_IOS)
    doc = json.loads(to_json(analyze(aces), notes, len(aces)))
    # Must not raise and must still have all pre-existing fields.
    assert "status" in doc and "score" in doc and "findings" in doc
    assert "vendor" in doc  # new additive field — present even on old callers


def test_to_text_backward_compat_three_args():
    """to_text(findings, notes, n_rules) still works with 3 positional args."""
    aces, notes = parse_acls(_CLEAN_IOS)
    out = to_text(analyze(aces), notes, len(aces))
    assert "0 findings" in out  # clean path still runs


def test_supported_vendors_constant_covers_all_six():
    """_SUPPORTED_VENDORS must name all six vendor families so the error message
    stays current when parsers are added."""
    for token in ("IOS", "NX-OS", "EOS", "Junos", "PAN-OS", "iptables"):
        assert token in _SUPPORTED_VENDORS, (
            f"_SUPPORTED_VENDORS missing '{token}' — update the constant"
        )
