"""Segmentation-intent checks — the paid/compliance hook.

A violation must be a CONCRETE permitted witness packet (auditor-grade), and an
earlier deny that blocks the forbidden flow must yield NO false alarm.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def _kinds(acl_text, policy=_POLICY):
    aces, _ = parse_acls(acl_text)
    return [(f.kind, f.severity) for f in check_segmentation(aces, policy)]


def test_violation_detected_with_concrete_witness():
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n")
    aces, _ = parse_acls(acl)
    f = check_segmentation(aces, _POLICY)
    assert any(x.kind == "segmentation-violation" and x.severity == "critical" for x in f)
    viol = next(x for x in f if x.kind == "segmentation-violation")
    assert "10.20" in viol.message and "10.10" in viol.message  # witness shown


def test_earlier_deny_blocks_no_false_alarm():
    # The forbidden flow is denied before any permit -> PASS, not a violation.
    acl = ("ip access-list extended T\n"
           " deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"
           " permit ip any any\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_permit_any_any_violates_segmentation():
    acl = ("ip access-list extended T\n permit ip any any\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" in kinds


def test_unrelated_permit_does_not_violate():
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.30.0.0 0.0.255.255 eq 445\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_neq_covering_445_is_precise_critical():
    # `neq 80` permits EVERY port except 80 — including the forbidden 445. The
    # complement is the exact union of [0,79] and [81,65535]; we model it
    # precisely (two ACEs), so this is a CONCRETE violation, not a vague
    # INDETERMINATE. (It was INDETERMINATE before neq precision; never a PASS.)
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 neq 80\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" in kinds
    assert "segmentation-indeterminate" not in kinds


def test_neq_excluding_445_is_precise_pass_never_false():
    # `neq 445` is the ONE operator that does NOT permit 445 — its complement is
    # [0,444] U [446,65535]. Port 445 is genuinely uncovered, so (with no other
    # permit) CORP truly cannot reach PCI:445 -> a PRECISE pass, and crucially
    # NEVER a false PASS: the verdict is segmentation-ok ONLY because 445 sits in
    # neither modeled range. Soundness guard: never ok when 445 IS in the complement.
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 neq 445\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


# ---------------------------------------------------------------------------
# Match-narrowing trailing qualifiers (fragments / time-range / dscp / tos /
# precedence / ttl): on a real device these RESTRICT what the ACE matches, so
# modeling them full-width is unsound — a narrowed deny evaluated full-width
# shadowed a later broad permit and produced a FALSE PASS on a real leak.
# The parser now marks such ACEs imprecise -> segcheck fails closed
# (indeterminate), never a green PASS.
# ---------------------------------------------------------------------------

def test_deny_fragments_above_broad_permit_is_not_a_false_pass():
    # On real IOS `deny ... fragments` matches ONLY non-initial fragments; a
    # normal (initial-fragment / unfragmented) CORP->PCI packet sails past it
    # into the broad permit. Modeled full-width the deny shadowed the permit and
    # segcheck said PASS on a reachable segment. It must fail closed instead.
    acl = ("ip access-list extended T\n"
           " deny ip any 10.10.0.0 0.0.255.255 fragments\n"
           " permit ip 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-ok" not in kinds          # the old false PASS
    assert "segmentation-indeterminate" in kinds   # fail closed, review manually


def test_deny_time_range_above_broad_permit_is_not_a_false_pass():
    # `deny ... time-range NIGHT` blocks only during the window; outside it the
    # broad permit makes CORP->PCI reachable. Never a green PASS.
    acl = ("ip access-list extended T\n"
           " deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445 "
           "time-range NIGHT\n"
           " permit ip 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-ok" not in kinds
    assert "segmentation-indeterminate" in kinds


def test_narrowed_permit_is_indeterminate_not_false_critical():
    # A narrowed PERMIT might never fire (e.g. outside the time window), so a
    # concrete CRITICAL witness can't be asserted — but neither can a PASS.
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445 "
           "time-range WORKHOURS\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" not in kinds
    assert "segmentation-indeterminate" in kinds


def test_all_narrowing_qualifiers_mark_imprecise_and_note():
    for qual in ("fragments", "time-range NIGHT", "dscp ef", "tos 4",
                 "precedence critical", "ttl eq 100", "ttl range 1 10"):
        acl = ("ip access-list extended T\n"
               f" deny ip any 10.10.0.0 0.0.255.255 {qual}\n")
        aces, notes = parse_acls(acl)
        assert aces[0].imprecise, f"{qual} must mark the ACE imprecise"
        assert any("match-narrowing" in n for n in notes), qual


def test_log_and_established_stay_exact():
    # `log`/`log-input` do not narrow the match; `established` is modeled
    # exactly via `stateful`. None of them may degrade precision.
    aces, _ = parse_acls("ip access-list extended T\n"
                         " permit tcp any any eq 443 log\n"
                         " permit tcp any any established\n"
                         " deny ip any any log-input\n")
    assert all(not a.imprecise for a in aces)
    assert aces[1].stateful
    # And a precise earlier deny still yields a genuine PASS (no regression).
    acl = ("ip access-list extended T\n"
           " deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445 log\n"
           " permit ip any any\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds


def test_icmp_type_not_confused_with_keyword_argument():
    # `time-range WORKHOURS` on an icmp ACE used to parse icmp_type="WORKHOURS".
    # The keyword's argument must be consumed, and a real type still captured.
    aces, _ = parse_acls("ip access-list extended I\n"
                         " permit icmp any any time-range WORKHOURS\n"
                         " permit icmp any any echo\n"
                         " permit icmp any any echo time-range WORKHOURS\n")
    assert aces[0].icmp_type is None and aces[0].imprecise
    assert aces[1].icmp_type == "echo" and not aces[1].imprecise
    assert aces[2].icmp_type == "echo" and aces[2].imprecise


# ---------------------------------------------------------------------------
# Portless must_not_reach assertions ("CORP must never reach PCI on tcp" — no
# ports listed). The witness must be CONCRETE in the port dimension: with an
# abstract port=None packet, any port-scoped earlier deny (deny tcp any any eq
# 445) first-matched the abstract witness and produced a FALSE PASS while every
# tcp port except 445 leaked. The engine now concretizes the port from the
# candidate permit's own range plus every earlier matching rule's range
# boundaries — complete for the port dimension — so PASS means provably denied
# at ALL ports for the witness pair, and a violation carries a real port.
# ---------------------------------------------------------------------------

_PORTLESS_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp"}],
}


def test_portless_port_scoped_deny_is_not_a_false_pass():
    # The original bug: `deny tcp any any eq 445` above a broad CORP->PCI permit
    # said PASS for the blanket assertion, although every port but 445 leaks.
    acl = ("ip access-list extended T\n"
           " deny tcp any any eq 445\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    aces, _ = parse_acls(acl)
    f = check_segmentation(aces, _PORTLESS_POLICY)
    kinds = {x.kind for x in f}
    assert "segmentation-ok" not in kinds          # the old false PASS
    assert "segmentation-violation" in kinds
    viol = next(x for x in f if x.kind == "segmentation-violation")
    # The witness is a real packet: concrete port, never the abstract None,
    # and never the denied port 445.
    assert "None" not in viol.witness and "None" not in viol.message
    port = int(viol.witness.split(":")[1].split()[0])
    assert 0 <= port <= 65535 and port != 445


def test_portless_fix_is_portless_covering_the_whole_leak():
    # A deny on just the witness port would NOT fix a blanket assertion; the
    # paste-ready fix must be portless like the policy.
    acl = ("ip access-list extended T\n"
           " deny tcp any any eq 445\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    aces, _ = parse_acls(acl)
    viol = next(x for x in check_segmentation(aces, _PORTLESS_POLICY)
                if x.kind == "segmentation-violation")
    assert " port " not in viol.fix
    assert "deny 10.20.0.0/16 -> 10.10.0.0/16" in viol.fix


def test_portless_full_width_deny_is_a_genuine_pass():
    # A port-UNscoped deny really blocks every port -> honest PASS, no alarm.
    acl = ("ip access-list extended T\n"
           " deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n"
           " permit ip any any\n")
    aces, _ = parse_acls(acl)
    kinds = {x.kind for x in check_segmentation(aces, _PORTLESS_POLICY)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_portless_scoped_denies_fully_covering_permit_range_pass():
    # Earlier scoped denies that provably cover the permit's ENTIRE port range
    # (100-150 U 151-200 covers 100-200) leave no leaking port -> genuine PASS.
    acl = ("ip access-list extended T\n"
           " deny tcp any any range 100 150\n"
           " deny tcp any any range 151 200\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 "
           "range 100 200\n")
    aces, _ = parse_acls(acl)
    kinds = {x.kind for x in check_segmentation(aces, _PORTLESS_POLICY)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_portless_gap_between_scoped_denies_is_found():
    # Denies cover 100-150 and 152-200 of a 100-200 permit; port 151 leaks and
    # must be reported with that exact concrete port.
    acl = ("ip access-list extended T\n"
           " deny tcp any any range 100 150\n"
           " deny tcp any any range 152 200\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 "
           "range 100 200\n")
    aces, _ = parse_acls(acl)
    f = check_segmentation(aces, _PORTLESS_POLICY)
    viol = next(x for x in f if x.kind == "segmentation-violation")
    assert ":151" in viol.witness


def test_portless_imprecise_earlier_deny_fails_closed():
    # An imprecise (match-narrowed) deny above the permit can't prove anything
    # -> indeterminate, never a green PASS.
    acl = ("ip access-list extended T\n"
           " deny tcp any any eq 445 time-range NIGHT\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    aces, _ = parse_acls(acl)
    kinds = {x.kind for x in check_segmentation(aces, _PORTLESS_POLICY)}
    assert "segmentation-ok" not in kinds
    assert "segmentation-indeterminate" in kinds


def test_portless_no_candidate_permit_still_passes():
    # Nothing permits CORP->PCI at all -> PASS unchanged, message shows a clean
    # "on tcp" (any port), not the abstract "tcp/[None]".
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.30.0.0 0.0.255.255\n")
    aces, _ = parse_acls(acl)
    f = check_segmentation(aces, _PORTLESS_POLICY)
    ok = next(x for x in f if x.kind == "segmentation-ok")
    assert "on tcp" in ok.message and "None" not in ok.message


def test_ported_assertion_behavior_unchanged_by_portless_path():
    # A ported assertion still honors an earlier port-matching deny exactly.
    acl = ("ip access-list extended T\n"
           " deny tcp any any eq 445\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    kinds = {k for k, _ in _kinds(acl)}          # _POLICY asserts ports=[445]
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_nxos_inherits_narrowing_guard():
    # parse_nxos wraps parse_acls, so the NX-OS frontend must fail closed too.
    from rulehawk.parse_nxos import parse_nxos
    cfg = ("ip access-list T\n"
           "  10 deny ip any 10.10.0.0/16 fragments\n"
           "  20 permit ip 10.20.0.0/16 10.10.0.0/16\n")
    aces, notes = parse_nxos(cfg)
    from rulehawk.segcheck import check_segmentation as _cs
    kinds = {f.kind for f in _cs(aces, _POLICY)}
    assert "segmentation-ok" not in kinds
    assert "segmentation-indeterminate" in kinds
