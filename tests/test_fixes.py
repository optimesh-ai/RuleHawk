"""Regression tests for the audit-found trust-killers (must never recur).

These are the bugs all three reviewers flagged as fatal: fabricated criticals on
ordinary rule forms and destructive 'safe to delete' advice. A network engineer
hits these on the FIRST real ACL they paste, so each gets a guard.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import analyze, parse_acls, to_json, to_text  # noqa: E402


def _findings(text):
    aces, _ = parse_acls(text)
    return analyze(aces)


def _kinds(text):
    return {(f.rule_id, f.kind) for f in _findings(text)}


# --- neq must not produce destructive 'safe to delete' advice -------------

def test_neq_does_not_kill_loadbearing_permit():
    # deny ... neq 443 does NOT match 443, so the eq-443 permit is load-bearing.
    text = ("ip access-list extended T\n"
            " deny tcp any any neq 443\n"
            " permit tcp any host 10.0.0.9 eq 443\n")
    kinds = {k for _, k in _kinds(text)}
    assert "intent-inversion-permit-dead" not in kinds
    assert "redundant" not in kinds


# --- established must not fabricate a critical / broad / exposure ----------

def test_established_return_traffic_not_false_critical():
    text = ("ip access-list extended T\n"
            " permit tcp any any established\n"
            " deny tcp any host 10.0.0.5 eq 22\n")
    kinds = {k for _, k in _kinds(text)}
    assert "intent-inversion-deny-dead" not in kinds
    assert "broad-any-any" not in kinds
    assert "dangerous-exposure" not in kinds


# --- ICMP types are distinct packet spaces --------------------------------

def test_icmp_echo_vs_echo_reply_not_shadowed():
    text = ("ip access-list extended T\n"
            " permit icmp any any echo\n"
            " deny icmp any any echo-reply\n")
    kinds = {k for _, k in _kinds(text)}
    assert "intent-inversion-deny-dead" not in kinds


# --- ASA normal masks vs IOS inverse wildcards ----------------------------

def test_asa_netmask_not_inverted():
    aces, _ = parse_acls(
        "access-list OUT extended permit ip 10.1.2.0 255.255.255.0 any\n")
    assert str(aces[0].src) == "10.1.2.0/24"   # NOT 10.0.0.0/8


def test_ios_wildcard_still_correct():
    aces, _ = parse_acls(
        "ip access-list extended T\n permit ip 10.1.2.0 0.0.0.255 any\n")
    assert str(aces[0].src) == "10.1.2.0/24"


def test_noncontiguous_mask_is_imprecise_and_noted():
    aces, notes = parse_acls(
        "ip access-list extended T\n permit ip 10.0.5.0 0.0.255.0 any\n")
    assert aces[0].imprecise is True
    assert any("imprecise" in n for n in notes)


# --- empty / unparseable input is NOT a clean bill of health --------------

def test_empty_input_not_scored_clean():
    aces, notes = parse_acls("this is not a config\n")
    assert aces == []
    txt = to_text(analyze(aces), notes, len(aces))
    assert "NO ACL RULES PARSED" in txt and "100" not in txt
    import json
    j = json.loads(to_json(analyze(aces), notes, len(aces)))
    assert j["status"] == "no_rules_parsed" and j["score"] is None


# --- dangerous-exposure over a port range reports ALL sensitive ports -----

def test_dangerous_exposure_reports_all_in_range():
    text = ("ip access-list extended T\n permit tcp any any range 22 3389\n")
    msgs = " ".join(f.message for f in _findings(text)
                    if f.kind == "dangerous-exposure")
    for svc in ("rdp", "mssql", "mysql", "telnet"):
        assert svc in msgs


def test_ssh_from_any_is_medium_not_high():
    text = ("ip access-list extended T\n permit tcp any host 10.0.0.1 eq 22\n")
    sev = {f.kind: f.severity for f in _findings(text)}
    assert sev.get("ssh-exposure") == "medium"


def test_ipv4_keyword_any_any_is_critical():
    assert ("T:1", "permit-any-any") in _kinds(
        "ip access-list extended T\n permit ipv4 any any\n")
