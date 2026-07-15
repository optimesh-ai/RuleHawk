"""Cisco Umbrella Cloud-Delivered Firewall (CDFW) L3/L4 frontend tests.

The Umbrella parser emits the same `(List[ACE], notes)` IR as the Cisco / Junos /
PAN-OS / iptables frontends, so the existing analysis / segmentation engine
consumes it unchanged. These tests pin the properties the task requires:
  1. detect  — true on the CDFW JSON (object + bare array), false on AWS SG JSON,
     non-JSON, and a Cisco text config;
  2. value   — an ALLOW opening CORP->PCI:445 is a concrete segmentation
     violation with a witness; a BLOCK-before-ALLOW ordering is isolation-ok;
  3. soundness — an unresolved source REFERENCE is imprecise (indeterminate,
     never a false PASS); the trailing fail-closed marker makes an unmatched
     forbidden flow indeterminate, not ok;
  4. connectivity — a must_reach flow that an ALLOW fully permits is proven ok.
All end-to-end verdicts go through rulehawk.segcheck.check_segmentation.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_umbrella import detect, parse_umbrella  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402


# ── sample exports ─────────────────────────────────────────────────────────────

_CDFW_DICT = {
    "rules": [
        {"name": "block-corp-to-pci", "order": 1, "action": "BLOCK",
         "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]},
        {"name": "allow-web", "order": 2, "action": "ALLOW",
         "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "ANY"}],
         "ports": [{"from": 443, "to": 443}]},
    ]
}

_CDFW_BARE_ARRAY = [
    {"name": "allow-web", "order": 1, "action": "ALLOW", "protocol": "TCP",
     "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
     "destinations": [{"type": "ANY"}],
     "ports": [{"from": 443, "to": 443}]},
]

# AWS Security-Group JSON — the parser must NOT match this.
_AWS_SG = {
    "SecurityGroups": [
        {"GroupId": "sg-0abc", "GroupName": "web",
         "IpPermissions": [
             {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
              "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]
}

_CISCO_TEXT = ("ip access-list extended CORP_TO_PCI\n"
               " deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"
               " permit ip any any\n")

_SEG_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                        "ports": [445]}],
}

# GUEST (10.40) is a source NO narrow CORP-scoped rule touches — used to prove a
# flow that falls THROUGH the explicit rules must hit the fail-closed marker
# (indeterminate), never the implicit default-deny (a false segmentation-ok).
_GUEST_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "GUEST": ["10.40.0.0/16"]},
    "must_not_reach": [{"src": "GUEST", "dst": "PCI", "proto": "tcp",
                        "ports": [445]}],
}


def _one(action, proto="TCP", src="10.20.0.0/16", dst="10.10.0.0/16",
         port=445, **extra):
    """Build a one-rule CDFW export (dict form)."""
    rule = {"name": "r", "order": 1, "action": action, "protocol": proto,
            "sources": [{"type": "CIDR", "value": src}],
            "destinations": [{"type": "CIDR", "value": dst}]}
    if port is not None:
        rule["ports"] = [{"from": port, "to": port}]
    rule.update(extra)
    return json.dumps({"rules": [rule]})


# ── 1. detect ──────────────────────────────────────────────────────────────────

def test_detect_true_on_cdfw_dict_and_bare_array():
    assert detect(json.dumps(_CDFW_DICT)) is True
    assert detect(json.dumps(_CDFW_BARE_ARRAY)) is True


def test_detect_false_on_aws_sg_dict_and_bare_array():
    assert detect(json.dumps(_AWS_SG)) is False
    # a bare array of SG objects (GroupId/IpPermissions) must also be rejected
    assert detect(json.dumps(_AWS_SG["SecurityGroups"])) is False


def test_detect_false_on_non_json_and_cisco_and_arbitrary_json():
    assert detect("this is not json {") is False
    assert detect(_CISCO_TEXT) is False
    assert detect(json.dumps({"foo": "bar", "widgets": [1, 2, 3]})) is False
    # valid JSON scalars / rule-less arrays are not CDFW
    assert detect("42") is False
    assert detect(json.dumps([{"name": "x"}])) is False


def test_detect_requires_the_full_triple():
    # sources + action but no destinations -> not the CDFW triple
    half = {"rules": [{"action": "ALLOW", "protocol": "TCP",
                       "sources": [{"type": "ANY"}]}]}
    assert detect(json.dumps(half)) is False


# ── 2. mapping / structure ─────────────────────────────────────────────────────

def test_maps_ordered_rules_to_aces_with_marker():
    aces, notes = parse_umbrella(json.dumps(_CDFW_DICT))
    cdfw = [a for a in aces if a.acl == "cdfw"]
    # 2 explicit rules (each a single src×dst×port ACE) + 2 fail-closed markers
    non_marker = [a for a in cdfw if "fail-closed" not in a.raw]
    assert len(non_marker) == 2
    block = next(a for a in non_marker if a.action == "deny")
    allow = next(a for a in non_marker if a.action == "permit")
    assert block.seq < allow.seq                      # order 1 before order 2
    assert block.proto == "tcp" and block.dst_port.lo == 445
    assert str(block.src) == "10.20.0.0/16" and str(block.dst) == "10.10.0.0/16"
    assert allow.dst_port.lo == 443 and allow.dst_any  # dst ANY -> 0.0.0.0/0
    assert all(a.transit for a in cdfw)
    # the fail-closed markers are imprecise permit ip any any, one per family
    markers = [a for a in cdfw if "fail-closed" in a.raw]
    assert len(markers) == 2 and all(m.imprecise and m.action == "permit"
                                     and m.proto == "ip" for m in markers)
    assert {m.src.version for m in markers} == {4, 6}
    assert any("fail-closed" in n for n in notes)


def test_numeric_protocol_and_single_port_field():
    cfg = json.dumps({"rules": [
        {"name": "r", "order": 1, "action": "PERMIT", "protocol": 6,
         "sources": [{"type": "CIDR", "value": "10.0.0.0/8"}],
         "destinations": [{"type": "IP", "value": "10.10.0.5"}],
         "port": 3389}]})
    aces, _ = parse_umbrella(cfg)
    rule = next(a for a in aces if a.action == "permit" and "fail-closed" not in a.raw)
    assert rule.proto == "tcp"                         # numeric 6 -> tcp
    assert rule.dst_port.lo == rule.dst_port.hi == 3389
    assert str(rule.dst) == "10.10.0.5/32"             # type IP -> /32


def test_ports_list_expands_to_union():
    cfg = json.dumps({"rules": [
        {"name": "multi", "order": 1, "action": "ALLOW", "protocol": "udp",
         "sources": [{"type": "ANY"}], "destinations": [{"type": "ANY"}],
         "ports": [{"from": 53, "to": 53}, {"from": 123, "to": 123}]}]})
    aces, _ = parse_umbrella(cfg)
    udp = [a for a in aces if a.action == "permit" and "fail-closed" not in a.raw
           and a.proto == "udp"]
    # ANY×ANY spans both address families; the destination-port set is the exact
    # union of the two ranges (no imprecise widening).
    assert {a.dst_port.lo for a in udp} == {53, 123}
    assert all(not a.imprecise for a in udp)
    assert {a.src.version for a in udp} == {4, 6}


def test_ports_on_icmp_ignored_not_attached():
    cfg = json.dumps({"rules": [
        {"name": "icmp", "order": 1, "action": "ALLOW", "protocol": "ICMP",
         "sources": [{"type": "ANY"}], "destinations": [{"type": "ANY"}],
         "ports": [{"from": 8, "to": 8}]}]})
    aces, notes = parse_umbrella(cfg)
    icmp = [a for a in aces if a.proto == "icmp"]
    assert icmp and all(a.dst_port.is_any() for a in icmp)   # no port on icmp
    assert any("non-ported" in n for n in notes)


def test_policy_id_separates_contexts():
    cfg = json.dumps({"rules": [
        {"name": "a", "order": 1, "action": "ALLOW", "protocol": "TCP",
         "policyId": "P1", "sources": [{"type": "ANY"}],
         "destinations": [{"type": "ANY"}], "ports": [{"from": 80, "to": 80}]},
        {"name": "b", "order": 1, "action": "BLOCK", "protocol": "TCP",
         "policyId": "P2", "sources": [{"type": "ANY"}],
         "destinations": [{"type": "ANY"}], "ports": [{"from": 80, "to": 80}]}]})
    aces, _ = parse_umbrella(cfg)
    acls = {a.acl for a in aces}
    assert acls == {"cdfw:P1", "cdfw:P2"}


# ── 3. segmentation value + soundness ───────────────────────────────────────────

def test_allow_corp_to_pci_445_is_violation_with_witness():
    aces, _ = parse_umbrella(_one("ALLOW"))
    findings = check_segmentation(aces, _SEG_POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    assert "10.20" in viol[0].message and "10.10" in viol[0].message
    assert ":445" in viol[0].witness


def test_block_before_allow_is_isolation_ok():
    cfg = json.dumps({"rules": [
        {"name": "block", "order": 1, "action": "BLOCK", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]},
        {"name": "allow", "order": 2, "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]}]})
    aces, _ = parse_umbrella(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds


def test_allow_after_block_order_reversed_still_ok_by_order_field():
    # Same two rules but listed allow-first in the array; the `order` field must
    # decide first-match (block=1 wins), so the flow stays isolated.
    cfg = json.dumps({"rules": [
        {"name": "allow", "order": 2, "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]},
        {"name": "block", "order": 1, "action": "BLOCK", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]}]})
    aces, _ = parse_umbrella(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds


def test_unresolved_source_reference_is_imprecise_not_false_pass():
    cfg = json.dumps({"rules": [
        {"name": "tunnel-allow", "order": 1, "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "network-tunnel-group", "value": "grp-42"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]}]})
    aces, notes = parse_umbrella(cfg)
    rule = next(a for a in aces if a.action == "permit" and "fail-closed" not in a.raw)
    assert rule.imprecise is True and rule.src_any     # widened to ANY source
    assert any("unresolved reference" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" not in kinds, "unresolved reference must not FALSE-PASS"
    assert kinds & {"segmentation-indeterminate", "segmentation-violation"}


def test_trailing_fail_closed_marker_makes_unmatched_flow_indeterminate():
    # Only an allow-web (CORP->ANY:443) rule; the forbidden CORP->PCI:445 flow is
    # matched by NO explicit rule, so the fail-closed marker makes it
    # INDETERMINATE — never a clean PASS.
    cfg = json.dumps({"rules": [
        {"name": "allow-web", "order": 1, "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "ANY"}], "ports": [{"from": 443, "to": 443}]}]})
    aces, _ = parse_umbrella(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" not in kinds, \
        "unmatched forbidden flow must not FALSE-PASS via a missing default"
    assert "segmentation-indeterminate" in kinds


def test_explicit_default_deny_gives_pass_no_marker():
    # An explicit trailing catch-all DENY (any/any) is modeled as-is; no marker,
    # and the forbidden flow is isolated (PASS), not indeterminate.
    cfg = json.dumps({"rules": [
        {"name": "allow-web", "order": 1, "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.30.0.0/16"}],
         "ports": [{"from": 443, "to": 443}]},
        {"name": "default-deny", "order": 99, "action": "BLOCK",
         "protocol": "ANY", "sources": [{"type": "ANY"}],
         "destinations": [{"type": "ANY"}]}]})
    aces, notes = parse_umbrella(cfg)
    assert not any("fail-closed" in a.raw for a in aces)   # no synthetic marker
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-indeterminate" not in kinds
    assert any("catch-all/default" in n for n in notes)


# ── 4. must_reach connectivity ──────────────────────────────────────────────────

def test_must_reach_connectivity_ok():
    cfg = json.dumps({"rules": [
        {"name": "allow-corp-pci-443", "order": 1, "action": "ALLOW",
         "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 443, "to": 443}]}]})
    aces, _ = parse_umbrella(cfg)
    policy = {"zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
              "must_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                              "ports": [443]}]}
    findings = check_segmentation(aces, policy)
    kinds = {f.kind for f in findings}
    assert "connectivity-ok" in kinds
    assert "connectivity-broken" not in kinds
    assert "connectivity-indeterminate" not in kinds


def test_must_reach_broken_when_flow_absent():
    # No rule permits CORP->PCI:443; the fail-closed marker is imprecise so the
    # verdict is indeterminate (fail closed), never a false connectivity-ok.
    cfg = json.dumps({"rules": [
        {"name": "allow-dns", "order": 1, "action": "ALLOW", "protocol": "UDP",
         "sources": [{"type": "ANY"}], "destinations": [{"type": "ANY"}],
         "ports": [{"from": 53, "to": 53}]}]})
    aces, _ = parse_umbrella(cfg)
    policy = {"zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
              "must_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                              "ports": [443]}]}
    kinds = {f.kind for f in check_segmentation(aces, policy)}
    assert "connectivity-ok" not in kinds
    assert kinds & {"connectivity-broken", "connectivity-indeterminate"}


# ── robustness ──────────────────────────────────────────────────────────────────

def test_invalid_json_returns_note_not_crash():
    aces, notes = parse_umbrella("{not valid json")
    assert aces == [] and notes and "not valid JSON" in notes[0]


def test_missing_and_odd_fields_degrade_with_notes():
    cfg = json.dumps({"rules": [
        {"name": "no-action", "order": 1,
         "sources": [{"type": "ANY"}], "destinations": [{"type": "ANY"}]},
        {"name": "bad-cidr", "order": 2, "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "not-a-cidr"}],
         "destinations": [{"type": "ANY"}], "ports": [{"from": 443, "to": 443}]}]})
    aces, notes = parse_umbrella(cfg)             # must not raise
    # unrecognized action -> skipped; bad CIDR -> imprecise ANY source
    assert any("unrecognized/absent action" in n for n in notes)
    assert any("unparsable address" in n for n in notes)
    bad = [a for a in aces if a.action == "permit" and "fail-closed" not in a.raw]
    assert bad and all(a.imprecise and a.src_any for a in bad)


# ── 5. regression: self-declared default flag must not suppress the marker ───────

def test_narrow_rule_with_default_flag_does_not_suppress_marker():
    # A NARROW rule (specific src/dst/proto/port) that carries a self-declared
    # default / isDefault / type:"default" flag is NOT the tail-decider. The flag
    # alone must NOT suppress the trailing fail-closed marker: a flow the narrow
    # rule never touches (GUEST->PCI) would otherwise fall to segcheck's implicit
    # default-deny and false-PASS as segmentation-ok. All three spellings.
    for flag in ({"default": True}, {"isDefault": True}, {"type": "default"}):
        aces, notes = parse_umbrella(_one("BLOCK", **flag))
        assert any("fail-closed" in a.raw for a in aces), flag
        assert not any("catch-all/default" in n for n in notes), flag
        kinds = {f.kind for f in check_segmentation(aces, _GUEST_POLICY)}
        assert "segmentation-ok" not in kinds, \
            f"narrow rule with {flag} must not FALSE-PASS via a suppressed marker"
        assert "segmentation-indeterminate" in kinds, flag


def test_genuine_matchall_catchall_decides_tail_no_redundant_marker():
    # ASSURANCE preserved: a GENUINE match-all catch-all (any src, any dst, any
    # proto, no ports) still decides the tail on its own — no redundant marker —
    # whether or not it ALSO carries a self-declared default flag. GUEST->PCI
    # falls through the narrow allow to the catch-all BLOCK: a clean PASS.
    for extra in ({}, {"default": True}, {"isDefault": True}, {"type": "default"}):
        catchall = {"name": "catchall", "order": 99, "action": "BLOCK",
                    "protocol": "ANY", "sources": [{"type": "ANY"}],
                    "destinations": [{"type": "ANY"}]}
        catchall.update(extra)
        cfg = json.dumps({"rules": [
            {"name": "allow-web", "order": 1, "action": "ALLOW", "protocol": "TCP",
             "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
             "destinations": [{"type": "CIDR", "value": "10.30.0.0/16"}],
             "ports": [{"from": 443, "to": 443}]},
            catchall]})
        aces, notes = parse_umbrella(cfg)
        assert not any("fail-closed" in a.raw for a in aces), extra
        assert any("catch-all/default" in n for n in notes), extra
        kinds = {f.kind for f in check_segmentation(aces, _GUEST_POLICY)}
        assert "segmentation-ok" in kinds, extra
        assert "segmentation-indeterminate" not in kinds, extra


# ── 6. regression: mixed present/absent order is order-ambiguous -> indeterminate ─

def test_mixed_present_absent_order_is_indeterminate_not_false_pass():
    # An UNORDERED ALLOW leak listed FIRST, then an order:1 BLOCK of the same
    # flow. Sorting the unordered rule LAST would reposition BLOCK ahead of the
    # ALLOW and mask the leak as segmentation-ok. Because the array MIXES ordered
    # and unordered rules the first-match order is ambiguous, so every ACE is
    # flagged imprecise -> the flow is INDETERMINATE, never a false PASS.
    cfg = json.dumps({"rules": [
        {"name": "allow-leak", "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]},
        {"name": "block", "order": 1, "action": "BLOCK", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]}]})
    aces, notes = parse_umbrella(cfg)
    assert all(a.imprecise for a in aces if "fail-closed" not in a.raw)
    assert any("evaluation order is ambiguous" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" not in kinds, \
        "mixed present/absent order must not FALSE-PASS via silent reordering"
    assert "segmentation-indeterminate" in kinds


def test_pure_document_order_and_all_ordered_stay_exact():
    # NONE of the rules carry an order -> pure document order, unambiguous: the
    # BLOCK precedes the ALLOW, so the flow is isolated EXACTLY (no imprecise
    # widening, a clean PASS) — the fix must not touch this path.
    doc = json.dumps({"rules": [
        {"name": "block", "action": "BLOCK", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]},
        {"name": "allow", "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]}]})
    aces, notes = parse_umbrella(doc)
    assert not any(a.imprecise for a in aces if "fail-closed" not in a.raw)
    assert not any("evaluation order is ambiguous" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-indeterminate" not in kinds

    # ALL rules carry an order -> also unambiguous; no imprecise widening.
    ordered = json.dumps({"rules": [
        {"name": "block", "order": 1, "action": "BLOCK", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]},
        {"name": "allow", "order": 2, "action": "ALLOW", "protocol": "TCP",
         "sources": [{"type": "CIDR", "value": "10.20.0.0/16"}],
         "destinations": [{"type": "CIDR", "value": "10.10.0.0/16"}],
         "ports": [{"from": 445, "to": 445}]}]})
    aces2, notes2 = parse_umbrella(ordered)
    assert not any(a.imprecise for a in aces2 if "fail-closed" not in a.raw)
    assert not any("evaluation order is ambiguous" in n for n in notes2)
    kinds2 = {f.kind for f in check_segmentation(aces2, _SEG_POLICY)}
    assert "segmentation-ok" in kinds2
    assert "segmentation-indeterminate" not in kinds2


# ── 7. regression: bare AWS-SG array is rejected cleanly (parser parity) ─────────

def test_bare_aws_sg_array_returns_note_not_markers():
    # A bare array of AWS Security-Group rule objects slips past the top-level
    # marker guard (it is a list, not a dict), but the per-rule guard must reject
    # it cleanly — ([], [note]) — exactly as the dict form is rejected, NOT emit
    # fail-closed markers over an AWS-shaped input.
    aws = [{"GroupId": "sg-0abc", "IpPermissions": [], "IpRanges": []}]
    aces, notes = parse_umbrella(json.dumps(aws))
    assert aces == []
    assert notes and "AWS Security-Group markers" in notes[0]
    assert not any("fail-closed" in n for n in notes)
    # detect() still (correctly) routes it away — routing is unaffected.
    assert detect(json.dumps(aws)) is False
