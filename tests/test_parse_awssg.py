"""AWS EC2 Security Group frontend tests.

The AWS SG parser emits the same `(List[ACE], notes)` IR as every other frontend,
so the analysis / segmentation engine consumes it unchanged. These tests pin the
properties the frontend must guarantee:

  1. detection  — the three accepted describe-security-groups shapes (object,
     bare array, single group) route here; arbitrary JSON and a Cisco text
     config do NOT.
  2. hygiene    — an ingress rule opening a sensitive port (3389/rdp) to
     0.0.0.0/0 is flagged by analyze().
  3. soundness  — a CORP->PCI ingress leak is a segmentation VIOLATION (never a
     false PASS), a group with no matching ingress is segmentation-ok, and an
     SG-to-SG reference degrades to imprecise -> indeterminate (never a false
     PASS).
  4. scale/robustness — a multi-account bare-array bundle parses every group as
     its own context; invalid JSON never crashes.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.parse_awssg import detect, parse_awssg  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402


# ── sample security groups ───────────────────────────────────────────────────

# Canonical describe-security-groups object form: a PCI database SG that lets a
# CORP CIDR reach Postgres (5432), plus the AWS default egress allow-all.
_DESCRIBE_OBJ = {
    "SecurityGroups": [
        {
            "GroupId": "sg-0abc", "GroupName": "pci-db",
            "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                 "IpRanges": [{"CidrIp": "10.20.0.0/16"}],
                 "Ipv6Ranges": [], "UserIdGroupPairs": []}
            ],
            "IpPermissionsEgress": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            ],
        }
    ]
}

# A single-group object (no SecurityGroups wrapper): RDP open to the world.
_SINGLE_GROUP = {
    "GroupId": "sg-rdp", "GroupName": "jump-box",
    "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ],
    "IpPermissionsEgress": [
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ],
}

# Segmentation policy: CORP must not reach PCI on Postgres.
_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                        "ports": [5432]}],
}


# ── 1. detection ─────────────────────────────────────────────────────────────

def test_detect_accepts_the_three_sg_shapes():
    # Object form (describe-security-groups).
    assert detect(json.dumps(_DESCRIBE_OBJ)) is True
    # Bare top-level array (Control Tower / multi-account concatenation).
    assert detect(json.dumps(_DESCRIBE_OBJ["SecurityGroups"])) is True
    # Single SecurityGroup object.
    assert detect(json.dumps(_SINGLE_GROUP)) is True


def test_detect_rejects_non_sg_json_and_text_config():
    # Arbitrary JSON with none of the SG-specific keys.
    assert detect(json.dumps({"foo": [1, 2, 3], "version": 1})) is False
    assert detect(json.dumps([{"name": "a"}, {"name": "b"}])) is False
    # An Umbrella-CDFW-shaped export (distinct keys, no SG markers).
    umbrella = {"rules": [{"source": "any", "destination": "any",
                           "action": "allow"}]}
    assert detect(json.dumps(umbrella)) is False
    # A Cisco text config is not JSON at all.
    cisco = "ip access-list extended A\n permit tcp any any eq 443\n"
    assert detect(cisco) is False
    # Empty / whitespace.
    assert detect("") is False
    assert detect("   \n ") is False


# ── 2. hygiene: dangerous exposure ───────────────────────────────────────────

def test_ingress_rdp_from_any_is_flagged_dangerous_exposure():
    aces, notes = parse_awssg(json.dumps(_SINGLE_GROUP))
    findings = analyze(aces)
    kinds = {f.kind for f in findings}
    # The RDP-from-0.0.0.0/0 ingress rule must raise dangerous-exposure (rdp).
    danger = [f for f in findings if f.kind == "dangerous-exposure"]
    assert danger, f"expected a dangerous-exposure finding, got {kinds}"
    assert any("rdp" in f.message for f in danger)

    # The ingress ACE itself: exact source-any, dst widened to ANY, proto tcp/3389.
    ing = next(a for a in aces if a.action == "permit"
               and a.dst_port.lo == 3389 and not a.imprecise)
    assert ing.proto == "tcp" and ing.src_any and ing.dst_any
    assert ing.imprecise is False


# ── 3a. segmentation: a real ingress leak is a VIOLATION (never a false PASS) ─

def test_corp_to_pci_ingress_leak_is_a_violation():
    aces, _ = parse_awssg(json.dumps(_DESCRIBE_OBJ))
    findings = check_segmentation(aces, _POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-violation" in kinds, kinds
    # It must NEVER be certified isolated.
    assert "segmentation-ok" not in kinds
    viol = next(f for f in findings if f.kind == "segmentation-violation")
    # Concrete witness: a CORP host reaching a PCI host on 5432.
    assert "5432" in viol.witness


# ── 3b. segmentation: a group with no matching ingress is OK ──────────────────

def test_group_with_no_matching_ingress_is_segmentation_ok():
    # web-dmz: ingress only on 443, egress restricted to a CIDR disjoint from PCI.
    group = {
        "GroupId": "sg-web", "GroupName": "web-dmz",
        "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
        "IpPermissionsEgress": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "10.30.0.0/16"}]}
        ],
    }
    aces, _ = parse_awssg(json.dumps(group))
    findings = check_segmentation(aces, _POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" in kinds, kinds
    assert "segmentation-violation" not in kinds


# ── 3c. segmentation: an SG-to-SG reference is imprecise (never a false PASS) ─

def test_sg_to_sg_reference_is_imprecise_not_a_false_pass():
    group = {
        "GroupId": "sg-app", "GroupName": "app-tier",
        "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
             "IpRanges": [], "Ipv6Ranges": [],
             "UserIdGroupPairs": [{"GroupId": "sg-peer"}]}
        ],
        "IpPermissionsEgress": [],
    }
    aces, notes = parse_awssg(json.dumps(group))
    # The SG-ref rule is emitted (never dropped) and marked imprecise.
    ref_aces = [a for a in aces if a.action == "permit" and a.imprecise]
    assert ref_aces, "the SG-to-SG reference rule must be emitted, imprecise"
    assert any("references security group sg-peer" in n for n in notes)

    findings = check_segmentation(aces, _POLICY)
    kinds = {f.kind for f in findings}
    # Never a false PASS: it must be indeterminate (or a violation), not OK.
    assert "segmentation-ok" not in kinds
    assert "segmentation-indeterminate" in kinds, kinds


# ── 4a. multi-account bare-array bundle: one context per group ────────────────

def test_multi_account_bare_array_parses_each_group_as_its_own_context():
    bundle = [
        {"GroupId": "sg-a1", "GroupName": "db",
         "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                            "IpRanges": [{"CidrIp": "10.1.0.0/16"}]}],
         "IpPermissionsEgress": []},
        {"GroupId": "sg-b2", "GroupName": "web",
         "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
         "IpPermissionsEgress": []},
        {"GroupId": "sg-c3", "GroupName": "cache",
         "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 6379, "ToPort": 6379,
                            "IpRanges": [{"CidrIp": "10.3.0.0/16"}]}],
         "IpPermissionsEgress": []},
    ]
    aces, notes = parse_awssg(json.dumps(bundle))
    acls = {a.acl for a in aces}
    assert len(acls) == 3, acls
    # Each label carries its unique GroupId, so contexts never merge.
    assert any("sg-a1" in a for a in acls)
    assert any("sg-b2" in a for a in acls)
    assert any("sg-c3" in a for a in acls)
    # Every group ends with its own implicit default-deny (both families).
    for acl in acls:
        denies = [a for a in aces if a.acl == acl and a.action == "deny"]
        assert len(denies) == 2 and all(d.dst_any for d in denies)


# ── 4b. robustness: invalid / edge JSON never crashes ────────────────────────

def test_invalid_json_returns_empty_and_a_note_without_crashing():
    aces, notes = parse_awssg("{not valid json")
    assert aces == []
    assert notes and any("not valid JSON" in n for n in notes)
    # detect must also reject it (so it falls through to other frontends).
    assert detect("{not valid json") is False


def test_empty_and_degenerate_groups_degrade_with_notes():
    # Empty describe output: SG-shaped but no groups -> no rules, a note, no crash.
    aces, notes = parse_awssg(json.dumps({"SecurityGroups": []}))
    assert aces == [] and notes
    # A group with only a GroupId: just the implicit default-deny, no crash.
    aces2, _ = parse_awssg(json.dumps({"GroupId": "sg-empty"}))
    assert all(a.action == "deny" for a in aces2) and len(aces2) == 2
