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


def test_neq_rule_is_indeterminate_not_false_pass():
    # An imprecise deciding rule must not be silently called PASS.
    acl = ("ip access-list extended T\n"
           " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 neq 80\n")
    kinds = {k for k, _ in _kinds(acl)}
    assert "segmentation-indeterminate" in kinds
