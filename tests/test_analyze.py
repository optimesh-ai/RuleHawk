"""Correctness tests for the rule-space analysis — the product's core IP."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import analyze, parse_acls, score  # noqa: E402
from rulehawk.model import covers  # noqa: E402
from rulehawk.parse import _parse_entry  # noqa: E402


def _ace(line, seq=1, acl="A"):
    toks = line.split()
    return _parse_entry(toks, seq, acl, line)[0]  # _parse_entry -> (ace, note)


def _kinds(text):
    aces, _ = parse_acls(text)
    return {(f.rule_id, f.kind) for f in analyze(aces)}


# --- covers() primitive --------------------------------------------------

def test_ip_any_any_covers_specific_tcp():
    a = _ace("permit ip any any")
    b = _ace("permit tcp host 10.0.0.1 host 10.0.0.2 eq 443", seq=2)
    assert covers(a, b) and not covers(b, a)


def test_supernet_covers_subnet():
    a = _ace("permit ip 10.0.0.0 0.255.255.255 any")
    b = _ace("permit ip 10.1.2.0 0.0.0.255 any", seq=2)
    assert covers(a, b) and not covers(b, a)


def test_port_range_containment():
    a = _ace("permit tcp any any range 1 1024")
    b = _ace("permit tcp any any eq 443", seq=2)
    assert covers(a, b) and not covers(b, a)


def test_different_specific_ports_do_not_cover():
    a = _ace("permit tcp any any eq 80")
    b = _ace("permit tcp any any eq 443", seq=2)
    assert not covers(a, b)


# --- intent inversions (the scary ones) ----------------------------------

def test_earlier_deny_kills_later_permit_is_high():
    text = ("ip access-list extended T\n"
            " deny tcp 10.0.0.0 0.255.255.255 any eq 23\n"
            " permit tcp 10.0.0.0 0.255.255.255 host 1.1.1.1 eq 23\n")
    assert ("T:2", "intent-inversion-permit-dead") in _kinds(text)


def test_earlier_permit_kills_later_deny_is_critical():
    text = ("ip access-list extended T\n"
            " permit ip any any\n"
            " deny tcp any any eq 22\n")
    k = _kinds(text)
    assert ("T:2", "intent-inversion-deny-dead") in k
    assert ("T:1", "permit-any-any") in k


def test_redundant_same_action_is_flagged():
    text = ("ip access-list extended T\n"
            " permit ip 10.0.0.0 0.255.255.255 any\n"
            " permit ip 10.1.0.0 0.0.255.255 any\n")
    assert ("T:2", "redundant") in _kinds(text)


# --- exposure ------------------------------------------------------------

def test_rdp_from_any_is_dangerous_exposure():
    text = ("ip access-list extended T\n permit tcp any any eq 3389\n")
    kinds = {k for _, k in _kinds(text)}
    assert "dangerous-exposure" in kinds


def test_clean_acl_scores_100():
    text = ("ip access-list extended T\n"
            " permit tcp host 10.0.0.1 host 203.0.113.10 eq 443\n"
            " permit udp host 10.0.0.2 host 203.0.113.11 eq 53\n")
    aces, _ = parse_acls(text)
    assert score(analyze(aces)) == 100


# --- parser fidelity -----------------------------------------------------

def test_object_group_is_noted_not_dropped_silently():
    text = ("ip access-list extended T\n"
            " permit tcp object-group SRC any eq 443\n")
    aces, notes = parse_acls(text)
    assert aces == [] and any("object-group" in n for n in notes)


def test_asa_access_list_form_parses():
    text = ("access-list OUT extended permit tcp any host 203.0.113.10 eq https\n"
            "access-list OUT extended permit ip any any\n")
    aces, _ = parse_acls(text)
    assert len(aces) == 2 and aces[0].dst_port.lo == 443
