"""AWS Security Groups frontend (parse_awssg.py).

Security Groups are ALLOW-ONLY, ORDER-INDEPENDENT and STATEFUL. The first two
make them exactly representable as `permit` ACEs terminated by the engine's
implicit default-deny (first-match over a permit-only list == the union of those
permits), so segmentation is exact here. The tests that matter most are the
soundness ones: a source this export cannot resolve (another security group, a
prefix list) must never be dropped, and must never yield a PASS.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.model import ANY_PORTS  # noqa: E402
from rulehawk.parse_awssg import detect, parse_awssg  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POLICY = {"zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
           "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                               "ports": [3306]}]}


def _sg(*perms, egress=(), gid="sg-test"):
    return json.dumps({"SecurityGroups": [{
        "GroupId": gid, "GroupName": "t", "VpcId": "vpc-1",
        "IpPermissions": list(perms),
        "IpPermissionsEgress": list(egress)}]})


def _kinds(text, policy=_POLICY):
    aces, _ = parse_awssg(text)
    return {f.kind for f in check_segmentation(aces, policy)}


# --------------------------------------------------------------------------- #
# detection
# --------------------------------------------------------------------------- #
def test_detects_the_cli_envelope():
    assert detect(_sg({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                       "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}))


def test_detects_a_bare_array_of_groups():
    doc = json.dumps([{"GroupId": "sg-1", "IpPermissions": [
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}])
    assert detect(doc)


@pytest.mark.parametrize("text", [
    "ip access-list extended T\n permit ip any any\n",   # Cisco
    "not json at all",
    "{}",
    '{"SecurityGroups": []}',
    "[]",
])
def test_does_not_claim_non_security_group_input(text):
    assert not detect(text)


def test_does_not_claim_a_network_acl_export():
    """Network ACLs are ORDERED and have denies. Routing one here would read it
    as allow-only and could turn a deny-protected boundary into a false PASS."""
    nacl = json.dumps({"NetworkAcls": [{"NetworkAclId": "acl-1", "Entries": [
        {"RuleNumber": 100, "Protocol": "6", "RuleAction": "deny",
         "CidrBlock": "0.0.0.0/0"}]}]})
    assert not detect(nacl)


# --------------------------------------------------------------------------- #
# rule modelling
# --------------------------------------------------------------------------- #
def test_ingress_and_egress_are_separate_contexts():
    aces, _ = parse_awssg(_sg(
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        egress=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]))
    assert {a.acl for a in aces} == {"sg-test/ingress", "sg-test/egress"}


def test_ingress_matches_on_source_egress_on_destination():
    """The group's own instances are not in this export, so the far side stays
    ANY — a superset, never a subset."""
    aces, _ = parse_awssg(_sg(
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [{"CidrIp": "10.1.0.0/16"}]},
        egress=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                 "IpRanges": [{"CidrIp": "10.2.0.0/16"}]}]))
    ing = next(a for a in aces if a.acl.endswith("ingress"))
    egr = next(a for a in aces if a.acl.endswith("egress"))
    assert str(ing.src) == "10.1.0.0/16" and ing.dst.prefixlen == 0
    assert str(egr.dst) == "10.2.0.0/16" and egr.src.prefixlen == 0


def test_every_rule_is_a_permit():
    """Security Groups have no deny construct; inventing one would be a lie."""
    aces, _ = parse_awssg(_sg(
        {"IpProtocol": "tcp", "FromPort": 1, "ToPort": 2,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        egress=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]))
    assert {a.action for a in aces} == {"permit"}


def test_protocol_minus_one_is_the_wildcard():
    aces, _ = parse_awssg(_sg({"IpProtocol": "-1",
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}))
    assert aces[0].proto == "ip" and aces[0].dst_port == ANY_PORTS


@pytest.mark.parametrize("raw,expect", [("6", "tcp"), ("17", "udp"),
                                        ("1", "icmp"), ("tcp", "tcp")])
def test_numeric_protocols_fold_to_names(raw, expect):
    """`"6"` and `"tcp"` must be ONE protocol to a policy assertion."""
    aces, _ = parse_awssg(_sg({"IpProtocol": raw, "FromPort": 1, "ToPort": 1,
                               "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}))
    assert aces[0].proto == expect


def test_icmp_fromport_is_a_type_not_a_port():
    """AWS overloads FromPort/ToPort for ICMP: type and code, NOT ports.
    Reading them as ports would model a nonsense space like 'icmp port 8'."""
    aces, _ = parse_awssg(_sg({"IpProtocol": "icmp", "FromPort": 8, "ToPort": -1,
                               "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}))
    assert aces[0].icmp_type == "echo"
    assert aces[0].dst_port == ANY_PORTS


def test_ipv6_ranges_are_modelled():
    aces, _ = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                               "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]}))
    assert str(aces[0].src) == "2001:db8::/32"


def test_port_range_is_preserved():
    aces, _ = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": 8000,
                               "ToPort": 8100,
                               "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}))
    assert (aces[0].dst_port.lo, aces[0].dst_port.hi) == (8000, 8100)


def test_a_permission_with_several_cidrs_expands_to_several_rules():
    aces, _ = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                               "IpRanges": [{"CidrIp": "10.1.0.0/16"},
                                            {"CidrIp": "10.2.0.0/16"}]}))
    assert len(aces) == 2 and {str(a.src) for a in aces} == {"10.1.0.0/16",
                                                             "10.2.0.0/16"}


# --------------------------------------------------------------------------- #
# soundness: an unresolvable source is opaque, never dropped, never a PASS
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("perm,label", [
    ({"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
      "UserIdGroupPairs": [{"GroupId": "sg-app"}]}, "security-group sg-app"),
    ({"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
      "PrefixListIds": [{"PrefixListId": "pl-1"}]}, "prefix-list pl-1"),
])
def test_unresolvable_source_becomes_an_opaque_imprecise_rule(perm, label):
    aces, notes = parse_awssg(_sg(perm))
    assert len(aces) == 1
    assert aces[0].imprecise, "an unresolved source must never be modelled exactly"
    assert aces[0].src.prefixlen == 0, "it must widen to ANY, never narrow"
    assert any(label in n for n in notes), "it must be surfaced, never silent"


def test_unresolvable_source_never_certifies_isolation():
    """The whole soundness line: we cannot see sg-app's addresses, so we cannot
    claim CORP is isolated from PCI."""
    kinds = _kinds(_sg({"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                        "UserIdGroupPairs": [{"GroupId": "sg-app"}]}))
    assert "segmentation-ok" not in kinds
    assert "segmentation-indeterminate" in kinds


def test_unresolvable_source_does_not_fabricate_a_violation():
    """Fail-closed means INDETERMINATE, not a false CRITICAL either."""
    kinds = _kinds(_sg({"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                        "UserIdGroupPairs": [{"GroupId": "sg-app"}]}))
    assert "segmentation-violation" not in kinds


def test_resolved_members_still_prove_a_violation_alongside_an_opaque_one():
    """Partial precision: a resolvable CIDR in the same permission must still be
    able to prove a CRITICAL — the opaque remainder must not mask it."""
    kinds = _kinds(_sg({"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                        "IpRanges": [{"CidrIp": "10.20.0.0/16"}],
                        "UserIdGroupPairs": [{"GroupId": "sg-app"}]}))
    assert "segmentation-violation" in kinds


def test_a_real_leak_is_reported_with_a_concrete_witness():
    aces, _ = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": 3306,
                               "ToPort": 3306,
                               "IpRanges": [{"CidrIp": "10.20.0.0/16"}]}))
    f = next(x for x in check_segmentation(aces, _POLICY)
             if x.kind == "segmentation-violation")
    assert "10.20.0.1" in f.witness and "10.10.0.1:3306" in f.witness


def test_genuinely_isolated_group_is_allowed_to_pass():
    """Fail-closed must not mean fail-always — a clean group still proves."""
    kinds = _kinds(_sg({"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                        "IpRanges": [{"CidrIp": "10.30.0.0/16"}]}))
    assert kinds == {"segmentation-ok"}


# --------------------------------------------------------------------------- #
# the findings that actually sell in cloud
# --------------------------------------------------------------------------- #
def test_ssh_open_to_the_world_is_reported():
    aces, _ = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}))
    assert any(f.kind == "ssh-exposure" for f in analyze(aces))


@pytest.mark.parametrize("port,expect", [(3389, "dangerous-exposure"),
                                         (3306, "dangerous-exposure"),
                                         (445, "dangerous-exposure")])
def test_sensitive_service_open_to_the_world_is_reported(port, expect):
    aces, _ = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": port,
                               "ToPort": port,
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}))
    assert any(f.kind == expect for f in analyze(aces))


def test_wide_open_egress_is_reported():
    aces, _ = parse_awssg(_sg(
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        egress=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]))
    assert any(f.kind == "permit-any-any" for f in analyze(aces))


def test_no_intent_inversion_is_produced():
    """With no deny construct, no rule can invert another's intent. Producing
    nothing here is the correct answer, not a coverage gap."""
    aces, _ = parse_awssg(_sg(
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}))
    assert not any(f.kind.startswith("intent-inversion") for f in analyze(aces))


def test_a_duplicate_rule_is_still_flagged_redundant():
    aces, _ = parse_awssg(_sg(
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}))
    assert any(f.kind in ("redundant", "union-redundant") for f in analyze(aces))


# --------------------------------------------------------------------------- #
# robustness: malformed input degrades, never crashes or certifies
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    '{"SecurityGroups": [null]}',
    '{"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [null]}]}',
    '{"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [{}]}]}',
    '{"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": ['
    '{"IpProtocol": "tcp", "FromPort": 99, "ToPort": 1,'
    ' "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}',
    '{"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": ['
    '{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "not-a-cidr"}]}]}]}',
])
def test_malformed_documents_do_not_crash(text):
    aces, notes = parse_awssg(text)
    assert isinstance(aces, list) and isinstance(notes, list)


def test_inverted_port_range_widens_rather_than_narrowing():
    """lo > hi must widen to ANY (a superset). Narrowing could hide a leak."""
    aces, notes = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": 99,
                                   "ToPort": 1,
                                   "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}))
    assert aces[0].dst_port == ANY_PORTS
    assert any("inverted port range" in n for n in notes)


def test_unparseable_cidr_is_opaque_not_dropped():
    aces, notes = parse_awssg(_sg({"IpProtocol": "tcp", "FromPort": 443,
                                   "ToPort": 443,
                                   "IpRanges": [{"CidrIp": "10.0.0.0/99"}]}))
    assert aces and aces[0].imprecise
    assert any("unparseable CidrIp" in n for n in notes)


def test_non_json_yields_no_rules_and_says_why():
    aces, notes = parse_awssg("ip access-list extended T\n permit ip any any\n")
    assert aces == [] and any("not valid JSON" in n for n in notes)


def test_group_line_is_recorded_for_diff_annotation():
    text = _sg({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]})
    pretty = json.dumps(json.loads(text), indent=2)
    aces, _ = parse_awssg(pretty)
    assert aces[0].line > 0
    assert '"GroupId"' in pretty.splitlines()[aces[0].line - 1]
