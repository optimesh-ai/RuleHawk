"""Finding.line — source file line number must be surfaced in text and JSON output.

ACE.line is tracked by every parser frontend but was previously discarded before
it reached Finding. A network engineer looking at a 200-line config needs to jump
directly to the problem: 'rule 5 of ACL T' is ambiguous without the file line.

Each test pins a concrete line number so a refactor that drops the propagation
immediately fails. Soundness is untouched — these are output-layer assertions only.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import analyze, parse_acls, to_json, to_text  # noqa: E402
from rulehawk.segcheck import check_segmentation             # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings(text):
    aces, notes = parse_acls(text)
    return analyze(aces), notes, len(aces)


# ---------------------------------------------------------------------------
# Finding.line is propagated from ACE.line
# ---------------------------------------------------------------------------

def test_redundant_finding_carries_correct_line():
    # Line 1: header; line 2: broad permit (rule 1); line 3: narrower permit (rule 2)
    # → rule 2 (line 3) is redundant.
    text = (
        "ip access-list extended T\n"            # line 1
        " permit ip 10.0.0.0 0.255.255.255 any\n"  # line 2 → seq 1
        " permit ip 10.1.0.0 0.0.255.255 any\n"    # line 3 → seq 2, redundant
    )
    findings, _, _ = _findings(text)
    red = [f for f in findings if f.kind == "redundant"]
    assert red, "expected a redundant finding"
    assert red[0].line == 3, (
        f"redundant finding should report line 3 (the covered rule), got {red[0].line}")


def test_intent_inversion_permit_dead_carries_correct_line():
    # Line 2: deny (kills line 3's permit); line 3: permit (dead).
    text = (
        "ip access-list extended T\n"                               # line 1
        " deny tcp 10.0.0.0 0.255.255.255 any eq 23\n"             # line 2
        " permit tcp 10.0.0.0 0.255.255.255 host 1.1.1.1 eq 23\n"  # line 3, dead
    )
    findings, _, _ = _findings(text)
    inv = [f for f in findings if f.kind == "intent-inversion-permit-dead"]
    assert inv, "expected intent-inversion-permit-dead"
    assert inv[0].line == 3


def test_intent_inversion_deny_dead_carries_correct_line():
    # Line 2: permit-any-any; line 3: deny (dead, can never be reached).
    text = (
        "ip access-list extended T\n"  # line 1
        " permit ip any any\n"         # line 2, permit-any-any
        " deny tcp any any eq 22\n"    # line 3, dead
    )
    findings, _, _ = _findings(text)
    inv = [f for f in findings if f.kind == "intent-inversion-deny-dead"]
    assert inv, "expected intent-inversion-deny-dead"
    assert inv[0].line == 3


def test_permit_any_any_carries_correct_line():
    text = (
        "ip access-list extended T\n"  # line 1
        " permit ip any any\n"         # line 2
    )
    findings, _, _ = _findings(text)
    paa = [f for f in findings if f.kind == "permit-any-any"]
    assert paa, "expected permit-any-any"
    assert paa[0].line == 2


def test_dangerous_exposure_carries_correct_line():
    text = (
        "ip access-list extended T\n"       # line 1
        " permit tcp any any eq 3389\n"     # line 2 → rdp from any → dangerous
    )
    findings, _, _ = _findings(text)
    de = [f for f in findings if f.kind == "dangerous-exposure"]
    assert de, "expected dangerous-exposure"
    assert de[0].line == 2


def test_zero_line_when_unknown():
    # Findings constructed without a source line (e.g. programmatic ACE) carry line=0.
    from rulehawk.analyze import Finding
    f = Finding("X:1", "redundant", "low", "msg", "rule text")
    assert f.line == 0


# ---------------------------------------------------------------------------
# Text report surfaces the line number
# ---------------------------------------------------------------------------

def test_text_report_shows_line_for_known_finding():
    text = (
        "ip access-list extended T\n"           # line 1
        " permit ip 10.0.0.0 0.255.255.255 any\n"  # line 2
        " permit ip 10.1.0.0 0.0.255.255 any\n"    # line 3
    )
    findings, notes, n = _findings(text)
    report = to_text(findings, notes, n)
    assert "line : 3" in report, (
        "text report must show 'line : 3' for the redundant finding at line 3")


def test_text_report_omits_line_when_zero():
    # A Finding with line=0 must not print a 'line :' row (avoid 'line : 0').
    from rulehawk.analyze import Finding
    from rulehawk.report import to_text
    f = Finding("X:1", "redundant", "low", "test message", "permit ip any any")
    report = to_text([f], [], 1)
    assert "line : 0" not in report
    assert "line :" not in report


# ---------------------------------------------------------------------------
# JSON report includes the "line" field
# ---------------------------------------------------------------------------

def test_json_report_includes_line_field():
    text = (
        "ip access-list extended T\n"           # line 1
        " permit ip 10.0.0.0 0.255.255.255 any\n"  # line 2
        " permit ip 10.1.0.0 0.0.255.255 any\n"    # line 3
    )
    findings, notes, n = _findings(text)
    doc = json.loads(to_json(findings, notes, n))
    f_json = next(f for f in doc["findings"] if f["kind"] == "redundant")
    assert "line" in f_json, "JSON finding must have a 'line' key"
    assert f_json["line"] == 3, (
        f"JSON 'line' should be 3 for the redundant finding, got {f_json['line']}")


def test_json_report_line_zero_when_unknown():
    from rulehawk.analyze import Finding
    from rulehawk.report import to_json
    f = Finding("X:1", "permit-any-any", "critical", "msg", "permit ip any any")
    doc = json.loads(to_json([f], [], 1))
    assert doc["findings"][0]["line"] == 0


# ---------------------------------------------------------------------------
# Segmentation findings carry the permitting rule's source line
# ---------------------------------------------------------------------------

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def test_segmentation_violation_carries_correct_line():
    # The CORP→PCI permit is on line 2.
    text = (
        "ip access-list extended T\n"                                         # line 1
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"  # line 2
    )
    aces, _ = parse_acls(text)
    findings = check_segmentation(aces, _POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol, "expected segmentation-violation"
    assert viol[0].line == 2, (
        f"segmentation violation should point to line 2, got {viol[0].line}")


# ---------------------------------------------------------------------------
# RH-FIX-LINES: fix strings cite source-file line numbers (never "line 0")
# ---------------------------------------------------------------------------

def test_fix_string_redundant_includes_line():
    # rule 2 (line 3) is redundant; fix must say "remove rule 2 (line 3)".
    text = (
        "ip access-list extended T\n"               # line 1
        " permit ip 10.0.0.0 0.255.255.255 any\n"  # line 2 → seq 1
        " permit ip 10.1.0.0 0.0.255.255 any\n"    # line 3 → seq 2, redundant
    )
    aces, _ = parse_acls(text)
    findings = analyze(aces)
    red = [f for f in findings if f.kind == "redundant"]
    assert red, "expected a redundant finding"
    assert "(line 3)" in red[0].fix, (
        f"redundant fix must cite the covered rule's file line, got: {red[0].fix!r}")


def test_fix_string_intent_inversion_permit_dead_cites_both_lines():
    # line 2: deny (seq 1) kills line 3's permit (seq 2).
    text = (
        "ip access-list extended T\n"                               # line 1
        " deny tcp 10.0.0.0 0.255.255.255 any eq 23\n"             # line 2 → seq 1
        " permit tcp 10.0.0.0 0.255.255.255 host 1.1.1.1 eq 23\n"  # line 3, dead
    )
    aces, _ = parse_acls(text)
    findings = analyze(aces)
    inv = [f for f in findings if f.kind == "intent-inversion-permit-dead"]
    assert inv, "expected intent-inversion-permit-dead"
    fix = inv[0].fix
    assert "(line 3)" in fix, (
        f"fix must cite the dead rule's line (3), got: {fix!r}")
    assert "(line 2)" in fix, (
        f"fix must cite the coverer's line (2), got: {fix!r}")


def test_fix_string_intent_inversion_deny_dead_cites_both_lines():
    # line 2: permit-any-any (seq 1); line 3: deny (seq 2, dead).
    text = (
        "ip access-list extended T\n"  # line 1
        " permit ip any any\n"         # line 2 → seq 1
        " deny tcp any any eq 22\n"    # line 3, dead
    )
    aces, _ = parse_acls(text)
    findings = analyze(aces)
    inv = [f for f in findings if f.kind == "intent-inversion-deny-dead"]
    assert inv, "expected intent-inversion-deny-dead"
    fix = inv[0].fix
    assert "(line 3)" in fix, (
        f"fix must cite the dead rule's line (3), got: {fix!r}")
    assert "(line 2)" in fix, (
        f"fix must cite the coverer's line (2), got: {fix!r}")


def test_fix_string_no_line_annotation_when_line_is_zero():
    # Programmatic ACEs (line=0) must never emit '(line 0)' in fix strings.
    import ipaddress
    from rulehawk.analyze import _analyze_one_acl
    from rulehawk.model import ACE
    a1 = ACE(seq=1, action="permit", proto="ip",
             src=ipaddress.ip_network("10.0.0.0/8"),
             dst=ipaddress.ip_network("0.0.0.0/0"),
             acl="X", line=0)
    a2 = ACE(seq=2, action="permit", proto="ip",
             src=ipaddress.ip_network("10.1.0.0/16"),
             dst=ipaddress.ip_network("0.0.0.0/0"),
             acl="X", line=0)
    findings = _analyze_one_acl([a1, a2])
    red = [f for f in findings if f.kind == "redundant"]
    assert red, "expected a redundant finding from programmatic ACEs"
    assert "(line 0)" not in red[0].fix, (
        "fix must not emit '(line 0)' for unknown-line rules")
    assert "(line" not in red[0].fix, (
        "fix must omit line annotation entirely when line is 0")


# ---------------------------------------------------------------------------
# RH-SEG-PASTEABLE: segcheck fix strings are paste-ready (concrete CIDRs)
# ---------------------------------------------------------------------------

_SEG_POLICY = {
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def test_segcheck_fix_contains_concrete_src_cidr():
    text = (
        "ip access-list extended T\n"                                         # line 1
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"  # line 2
    )
    aces, _ = parse_acls(text)
    viol = [f for f in check_segmentation(aces, _SEG_POLICY)
            if f.kind == "segmentation-violation"]
    assert viol, "expected segmentation-violation"
    fix = viol[0].fix
    # The fix must reference a CIDR from the source intersection (10.20/16), not just
    # zone labels — so it can be pasted directly into an ACL deny rule.
    assert "10.20" in fix, (
        f"fix must contain the concrete src CIDR, got: {fix!r}")


def test_segcheck_fix_contains_concrete_dst_cidr():
    text = (
        "ip access-list extended T\n"                                         # line 1
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"  # line 2
    )
    aces, _ = parse_acls(text)
    viol = [f for f in check_segmentation(aces, _SEG_POLICY)
            if f.kind == "segmentation-violation"]
    assert viol
    fix = viol[0].fix
    assert "10.10" in fix, (
        f"fix must contain the concrete dst CIDR, got: {fix!r}")


def test_segcheck_fix_contains_port():
    text = (
        "ip access-list extended T\n"
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"
    )
    aces, _ = parse_acls(text)
    viol = [f for f in check_segmentation(aces, _SEG_POLICY)
            if f.kind == "segmentation-violation"]
    assert viol
    assert "445" in viol[0].fix, (
        f"fix must cite the forbidden port, got: {viol[0].fix!r}")


def test_segcheck_fix_contains_permitting_rule_line():
    # The permitting rule is on line 2; the fix must include '(line 2)'.
    text = (
        "ip access-list extended T\n"                                         # line 1
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"  # line 2
    )
    aces, _ = parse_acls(text)
    viol = [f for f in check_segmentation(aces, _SEG_POLICY)
            if f.kind == "segmentation-violation"]
    assert viol
    fix = viol[0].fix
    assert "(line 2)" in fix, (
        f"fix must cite the permitting rule's file line, got: {fix!r}")
