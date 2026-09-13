"""Regression tests for the September 2026 audit sweep.

Each test pins one confirmed defect found by auditing every frontend against
the PARSER CONTRACT in model.py (an ACE's modeled space must be a SUPERSET of
the rule's true match space) and the "surface, never silently drop" discipline.

Soundness — a real permit invisible to the witness search => FALSE PASS:
  * IOS `ipv6 access-list` entries carry an explicit `sequence N` keyword in
    `show running-config`; every such entry was dropped as "unparsed".
  * An AWS Security Group rule sourced from another group / prefix list was
    modeled as ONE v4-only opaque marker — invisible to every IPv6 assertion.
  * An iptables `-g` (goto) was resolved with `-j` semantics; a goto's
    fall-through takes the caller's default policy, not the next rule.
  * A file mixing `iptables` and `ip6tables` commands was read as IPv4 only,
    so any IPv6 verdict from it was unfounded.

Precision / audit trail — a sound verdict that was needlessly INDETERMINATE,
or a widening that left no note:
  * `-m comment --comment "..."` (on nearly every rule of a Docker/Kubernetes
    host) read as an unknown narrowing option and poisoned whole rulesets.
  * An unconditional `-j RETURN` (the allow-list-then-RETURN idiom) blocked
    jump resolution although it means exactly "the chain ends here".
  * `permit 58 any any 128` (icmpv6 by number) flagged its type as unknown.
  * `eq <unknown-service>` widened the port dimension with no note.
  * `service-object esp` / `gre` (the ASA VPN idiom) failed the whole group
    closed although a port-less protocol is an exact space.
  * A reflexive-ACL `evaluate NAME` line vanished without a trace.
  * The `-I` / `-R` notes claimed "position not modeled" over a position the
    model honors (pinned in the existing iptables tests).
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.parse_awssg import parse_awssg  # noqa: E402
from rulehawk.parse_iptables import parse_iptables  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_V4 = {"zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
       "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                           "ports": [445]}]}
_V6 = {"zones": {"CORP6": ["2001:db8:20::/48"], "PCI6": ["2001:db8:10::/48"]},
       "must_not_reach": [{"src": "CORP6", "dst": "PCI6", "proto": "tcp",
                           "ports": [445]}]}


def _kinds(aces, policy):
    return {f.kind for f in check_segmentation(aces, policy)}


# --------------------------------------------------------------------------- #
# soundness
# --------------------------------------------------------------------------- #
def test_ios_ipv6_sequence_entries_are_parsed_in_sequence_order():
    cfg = ("ipv6 access-list V6-EDGE\n"
           " sequence 20 deny ipv6 any any\n"
           " sequence 10 permit tcp 2001:db8:20::/48 2001:db8:10::/48 eq 445\n")
    aces, notes = parse_acls(cfg)
    assert [a.action for a in aces] == ["permit", "deny"], \
        "entries must parse AND honor their explicit sequence numbers"
    assert aces[0].src.version == 6 and aces[0].dst_port.lo == 445
    assert aces[0].imprecise is False
    assert not any(n.startswith("unparsed") for n in notes)
    kinds = _kinds(aces, _V6)
    assert "segmentation-violation" in kinds and "segmentation-ok" not in kinds, \
        "FALSE PASS: the v6 permit was invisible while it parsed as 'unparsed'"


def test_ios_ipv6_sequence_remark_is_still_skipped_quietly():
    aces, notes = parse_acls("ipv6 access-list V6\n sequence 5 remark permit web\n"
                             " sequence 10 deny ipv6 any any\n")
    assert [a.action for a in aces] == ["deny"]
    assert not any("unparsed" in n for n in notes)


def test_awssg_unresolved_remainder_is_opaque_for_both_address_families():
    sg = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 445, "ToPort": 445,
         "UserIdGroupPairs": [{"GroupId": "sg-other"}]}]}]}
    aces, notes = parse_awssg(json.dumps(sg))
    assert sorted(a.src.version for a in aces) == [4, 6]
    assert all(a.imprecise for a in aces)
    v6 = _kinds(aces, _V6)
    assert "segmentation-ok" not in v6, \
        "FALSE PASS: a v4-only opaque marker never intersects a v6 witness"
    assert "segmentation-indeterminate" in v6
    assert "segmentation-indeterminate" in _kinds(aces, _V4)
    assert any("per address family" in n for n in notes)


def test_awssg_icmp_remainder_stays_in_its_own_family():
    def one(proto):
        sg = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": proto, "FromPort": -1, "ToPort": -1,
             "UserIdGroupPairs": [{"GroupId": "sg-other"}]}]}]}
        return parse_awssg(json.dumps(sg))[0]
    assert [a.src.version for a in one("icmp")] == [4]
    assert [a.src.version for a in one("icmpv6")] == [6]


def test_iptables_goto_is_kept_indeterminate_not_resolved_as_a_jump():
    # Real semantics: a packet not from 192.168/16 falls off CHK and — because
    # it arrived via `-g` — takes FORWARD's ACCEPT policy, never the later DROP.
    cfg = ("*filter\n:FORWARD ACCEPT [0:0]\n:CHK - [0:0]\n"
           "-A FORWARD -g CHK\n-A FORWARD -j DROP\n"
           "-A CHK -s 192.168.0.0/16 -j DROP\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    kinds = _kinds(aces, _V4)
    assert "segmentation-ok" not in kinds, \
        "FALSE PASS: goto fall-through resolved as if the next FORWARD rule ran"
    assert "segmentation-indeterminate" in kinds
    assert any("goto" in n and "fail-closed" in n for n in notes)
    assert not any("resolved precisely" in n for n in notes)


def test_iptables_plain_jump_still_resolves_precisely():
    cfg = ("*filter\n:FORWARD ACCEPT [0:0]\n:CHK - [0:0]\n"
           "-A FORWARD -j CHK\n-A FORWARD -j DROP\n"
           "-A CHK -s 192.168.0.0/16 -j DROP\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert any("resolved precisely" in n for n in notes)
    assert "segmentation-ok" in _kinds(aces, _V4)


def test_mixed_iptables_ip6tables_file_fails_closed_for_ipv6_only():
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp"
           " --dport 445 -j DROP\n"
           "ip6tables -P FORWARD ACCEPT\n"
           "ip6tables -A FORWARD -p tcp --dport 22 -j DROP\n")
    aces, notes = parse_iptables(cfg)
    assert any("ip6tables" in n and "INDETERMINATE" in n for n in notes)
    assert "segmentation-ok" in _kinds(aces, _V4), "IPv4 verdict must stay exact"
    v6 = _kinds(aces, _V6)
    assert "segmentation-ok" not in v6 and "segmentation-indeterminate" in v6, \
        "FALSE PASS: the ip6tables ACCEPT policy was modeled as 0.0.0.0/0"


def test_single_family_iptables_file_gets_no_mixed_marker():
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j DROP\n")
    aces, notes = parse_iptables(cfg)
    assert all(a.src.version == 4 for a in aces)
    assert not any("ip6tables" in n for n in notes)


# --------------------------------------------------------------------------- #
# precision / audit trail
# --------------------------------------------------------------------------- #
def test_iptables_comment_module_does_not_narrow():
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp -m tcp --dport 445"
           " -m comment --comment \"allow smb corp->pci\" -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = [a for a in aces if a.action == "permit"][0]
    assert rule.imprecise is False
    assert not any("--comment" in n for n in notes)
    viol = [f for f in check_segmentation(aces, _V4)
            if f.kind == "segmentation-violation"]
    assert viol and ":445" in viol[0].witness


def test_unconditional_return_ends_the_chain_and_lets_the_jump_resolve():
    cfg = ("*filter\n:FORWARD DROP [0:0]\n:ALLOW - [0:0]\n"
           "-A FORWARD -j ALLOW\n"
           "-A ALLOW -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
           "-A ALLOW -m comment --comment \"end\" -j RETURN\n"
           "-A ALLOW -j DROP\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert any("resolved precisely" in n and "ALLOW" in n for n in notes)
    assert any("unconditional `-j RETURN`" in n for n in notes)
    assert any("1 rule(s) after an unconditional" in n and "unreachable" in n
               for n in notes)
    assert not any(a.acl == "ALLOW" and a.action == "deny" for a in aces), \
        "the DROP after the RETURN is unreachable and must not be modeled live"
    assert all(not a.imprecise for a in aces if a.acl == "FORWARD")
    viol = [f for f in check_segmentation(aces, _V4)
            if f.kind == "segmentation-violation"]
    assert viol and ":445" in viol[0].witness


def test_conditional_return_still_fails_closed():
    cfg = ("*filter\n:FORWARD DROP [0:0]\n:ALLOW - [0:0]\n"
           "-A FORWARD -j ALLOW\n"
           "-A ALLOW -s 10.20.0.0/16 -j RETURN\n"
           "-A ALLOW -j DROP\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert not any("resolved precisely" in n for n in notes)
    assert "segmentation-indeterminate" in _kinds(aces, _V4)


def test_state_matched_return_is_conditional():
    cfg = ("*filter\n:FORWARD DROP [0:0]\n:ALLOW - [0:0]\n"
           "-A FORWARD -j ALLOW\n"
           "-A ALLOW -m conntrack --ctstate NEW -j RETURN\n"
           "-A ALLOW -j DROP\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert not any("unconditional" in n for n in notes)
    assert any(a.acl == "ALLOW" and a.action == "deny" for a in aces)


def test_unconditional_return_in_a_base_chain_applies_the_policy_exactly():
    cfg = ("*filter\n:FORWARD ACCEPT [0:0]\n"
           "-A FORWARD -j RETURN\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j DROP\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert all(not a.imprecise for a in aces)
    assert [a.action for a in aces if a.acl == "FORWARD"] == ["permit"], \
        "only the ACCEPT policy survives; the DROP behind the RETURN is dead"
    assert "segmentation-violation" in _kinds(aces, _V4)


def test_icmpv6_by_number_keeps_its_type_exact():
    aces, notes = parse_acls("ipv6 access-list V6\n permit 58 any any 128\n")
    assert aces[0].proto == "icmpv6" and aces[0].icmp_type == "128"
    assert aces[0].imprecise is False
    assert not any("unrecognized" in n for n in notes)


def test_unmodeled_port_operator_is_surfaced_not_silently_widened():
    aces, notes = parse_acls("ip access-list extended T\n"
                             " permit tcp any any eq nosuchsvc\n")
    assert aces[0].imprecise and aces[0].dst_port.is_any()
    assert any("port operator not modeled exactly" in n for n in notes)
    # The same trail through the object-group resolution path.
    cfg = ("object-group network N\n network-object host 10.0.0.1\n"
           "access-list OUT extended permit tcp object-group N any eq nosuchsvc\n")
    aces, notes = parse_acls(cfg)
    assert aces and all(a.imprecise for a in aces)
    assert any("port operator not modeled exactly" in n for n in notes)


def test_service_objects_naming_port_less_protocols_resolve_exactly():
    cfg = ("object-group service VPN\n"
           " service-object esp\n"
           " service-object gre\n"
           " service-object udp destination eq isakmp\n"
           "access-list OUT extended permit object-group VPN any any\n")
    aces, notes = parse_acls(cfg)
    assert sorted((a.proto, a.dst_port.lo) for a in aces) == \
        [("esp", 0), ("gre", 0), ("udp", 500)]
    assert not any(a.imprecise for a in aces)


def test_ports_on_a_port_less_protocol_still_fail_closed():
    cfg = ("object-group service BAD\n"
           " service-object gre destination eq 80\n"
           " service-object udp destination eq 500\n"
           "access-list OUT extended permit object-group BAD any any\n")
    aces, notes = parse_acls(cfg)
    assert any(a.proto == "udp" and a.dst_port.lo == 500 and not a.imprecise
               for a in aces)
    assert any(a.imprecise for a in aces), \
        "the refused member must leave an opaque remainder, never vanish"


def test_reflexive_acl_evaluate_is_surfaced_not_dropped():
    cfg = ("ip access-list extended INBOUND\n"
           " evaluate TCP-REFLECT\n"
           " deny ip any any\n")
    aces, notes = parse_acls(cfg)
    assert [a.action for a in aces] == ["deny"]
    assert any("reflexive" in n and "evaluate TCP-REFLECT" in n for n in notes)
