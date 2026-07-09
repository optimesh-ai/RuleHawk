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


def test_partial_deny_cannot_hide_the_leak():
    # An earlier deny that blocks ONE host must not defeat the witness search:
    # every other CORP host still leaks. (A single-witness probe that happened
    # to pick the denied host used to FALSE-PASS this.)
    acl = ("ip access-list extended T\n"
           " deny tcp host 10.20.0.1 10.10.0.0 0.0.255.255 eq 445\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" in kinds
    assert "segmentation-ok" not in kinds


def test_proto_specific_deny_does_not_block_wildcard_assertion():
    # A tcp-only deny cannot block the udp/icmp part of a wildcard (`ip`)
    # assertion — the permit ip below it leaks every non-tcp protocol.
    acl = ("ip access-list extended T\n"
           " deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n"
           " permit ip 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    pol = {"zones": _POLICY["zones"],
           "must_not_reach": [{"src": "CORP", "dst": "PCI"}]}
    kinds = {k for k, _ in _kinds(acl, pol)}
    assert "segmentation-violation" in kinds


def test_src_port_restricted_deny_does_not_block():
    # The deny only covers source ports 0-1023; a witness with a high source
    # port is still permitted.
    acl = ("ip access-list extended T\n"
           " deny tcp 10.20.0.0 0.0.255.255 range 0 1023 10.10.0.0 0.0.255.255 eq 445\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-violation" in kinds


def test_icmp_typed_deny_does_not_block_untyped_assertion():
    # `deny icmp ... echo` blocks pings only; echo-reply (and every other type)
    # still leaks through the permit below.
    acl = ("ip access-list extended T\n"
           " deny icmp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 echo\n"
           " permit icmp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    pol = {"zones": _POLICY["zones"],
           "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "icmp"}]}
    kinds = {k for k, _ in _kinds(acl, pol)}
    assert "segmentation-violation" in kinds
    # ...but a full (untyped) icmp deny still yields a clean PASS — no false alarm.
    acl_ok = ("ip access-list extended T\n"
              " deny icmp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n"
              " permit icmp any any\n")
    kinds_ok = {k for k, _ in _kinds(acl_ok, pol)}
    assert "segmentation-violation" not in kinds_ok
    assert "segmentation-ok" in kinds_ok


def test_unknown_zone_name_fails_closed_not_pass():
    # A typo'd zone name must never certify isolation over an empty search space.
    pol = {"zones": _POLICY["zones"],
           "must_not_reach": [{"src": "CROP", "dst": "PCI"}]}   # typo
    kinds = {k for k, _ in _kinds("ip access-list extended T\n permit ip any any\n", pol)}
    assert "segmentation-policy-error" in kinds
    assert "segmentation-ok" not in kinds


def test_invalid_zone_cidr_fails_closed_without_traceback():
    pol = {"zones": {"PCI": ["10.10.0.0/33"], "CORP": ["10.20.0.0/16"]},
           "must_not_reach": [{"src": "CORP", "dst": "PCI"}]}
    kinds = {k for k, _ in _kinds("ip access-list extended T\n deny ip any any\n", pol)}
    assert "segmentation-policy-error" in kinds
    assert "segmentation-ok" not in kinds


def test_string_ports_are_coerced():
    pol = {"zones": _POLICY["zones"],
           "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                               "ports": ["445"]}]}
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n")
    kinds = {k for k, _ in _kinds(acl, pol)}
    assert "segmentation-violation" in kinds


def test_unusable_ports_and_non_dict_policy_fail_closed():
    pol = {"zones": _POLICY["zones"],
           "must_not_reach": [{"src": "CORP", "dst": "PCI", "ports": ["ssh!"]}]}
    kinds = {k for k, _ in _kinds("ip access-list extended T\n permit ip any any\n", pol)}
    assert kinds == {"segmentation-policy-error"}
    assert [f.kind for f in check_segmentation([], ["not a dict"])] == \
        ["segmentation-policy-error"]


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
