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
    # _parse_entry -> (aces_list, notes); a line may expand to >1 ACE (multi-port
    # `eq`). These covers() cases are single-port, so take the first ACE.
    return _parse_entry(toks, seq - 1, acl, line)[0][0]


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


def test_narrow_src_port_does_not_cover_any_src_port():
    # Pins model.covers() lines 136-137 (the src_port gate): a rule that only
    # permits a NARROW source-port range must NOT be proven to cover a rule with
    # ANY source port on the same net/proto/dst-port. If that branch regressed,
    # analyze() would emit an unsound "SHADOWED / DEAD — safe to delete" verdict
    # on a load-bearing rule (the false-positive-deletion failure model.py's own
    # docstring warns against). The reverse (any src-port covers a narrow one)
    # must stay True so the gate is proven not to be a blanket False.
    narrow = _ace("permit tcp any range 1024 2048 host 10.0.0.1 eq 443")
    wide = _ace("permit tcp any host 10.0.0.1 eq 443", seq=2)
    assert (narrow.src_port.lo, narrow.src_port.hi) == (1024, 2048)
    assert wide.src_port.is_any()
    assert not covers(narrow, wide)
    assert covers(wide, narrow)


def test_narrow_src_port_rule_not_reported_dead_end_to_end():
    # Integration: the narrow-src-port gate through parse -> analyze. An earlier
    # rule that only matches source ports 1024-2048 must NOT make a later
    # any-source-port rule (broader) report as dead/shadowed/redundant.
    text = ("ip access-list extended S\n"
            " permit tcp any range 1024 2048 host 10.0.0.1 eq 443\n"
            " permit tcp any host 10.0.0.1 eq 443\n")
    k = _kinds(text)
    assert not any(rid == "S:2" for rid, _ in k)
    # Sanity of the harness (guards against the gate silently short-circuiting):
    # reverse the order and the narrow rule IS redundant under the wide one.
    text_rev = ("ip access-list extended S\n"
                " permit tcp any host 10.0.0.1 eq 443\n"
                " permit tcp any range 1024 2048 host 10.0.0.1 eq 443\n")
    assert ("S:2", "redundant") in _kinds(text_rev)


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
    # An object-group permit is surfaced as a note AND kept as a fail-CLOSED
    # opaque ACE (imprecise, any/any) — never dropped. Dropping it let segcheck
    # FALSE-PASS a real leak hidden behind the group (see the soundness audit).
    text = ("ip access-list extended T\n"
            " permit tcp object-group SRC any eq 443\n")
    aces, notes = parse_acls(text)
    assert len(aces) == 1 and aces[0].imprecise is True
    assert any("object-group" in n for n in notes)


def test_asa_access_list_form_parses():
    text = ("access-list OUT extended permit tcp any host 203.0.113.10 eq https\n"
            "access-list OUT extended permit ip any any\n")
    aces, _ = parse_acls(text)
    assert len(aces) == 2 and aces[0].dst_port.lo == 443


# --- source-port-only trust (spoofable return-traffic permits) ------------

def test_source_port_only_permit_is_flagged_high():
    # `permit tcp any eq 53 any` — trusts an attacker-controlled source port
    # to admit traffic to EVERY destination port.
    text = ("ip access-list extended T\n"
            " permit tcp any eq 53 any\n")
    assert ("T:1", "source-port-trust") in _kinds(text)
    aces, _ = parse_acls(text)
    f = next(f for f in analyze(aces) if f.kind == "source-port-trust")
    assert f.severity == "high" and "SOURCE port" in f.message


def test_source_port_trust_established_is_exempt():
    # `established` marks genuine return traffic — not source-port trust.
    text = ("ip access-list extended T\n"
            " permit tcp any eq 53 any established\n")
    assert not any(k == "source-port-trust" for _, k in _kinds(text))


def test_source_port_with_dst_port_is_not_flagged():
    # A rule that ALSO scopes the destination port is properly constrained.
    text = ("ip access-list extended T\n"
            " permit tcp any eq 1024 any eq 443\n")
    assert not any(k == "source-port-trust" for _, k in _kinds(text))


def test_source_port_trust_imprecise_and_deny_are_exempt():
    import dataclasses as _dc
    a = _ace("permit tcp any eq 53 any")
    assert any(f.kind == "source-port-trust" for f in analyze([a]))
    # An over-approximated (imprecise) space must never drive the verdict.
    assert not any(f.kind == "source-port-trust"
                   for f in analyze([_dc.replace(a, imprecise=True)]))
    # A deny is never over-permissive.
    assert not any(f.kind == "source-port-trust"
                   for f in analyze([_dc.replace(a, action="deny")]))
