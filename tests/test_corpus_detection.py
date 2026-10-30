"""Junos SRX security policies are never audited as a Cisco ACL.

Found while measuring a public config corpus (Aerleon's SRX reference
output): an SRX `security { policies { ... } }` config auto-routed to the Cisco
frontend, which read the comment line `Deny to bad destinations.` as an ACE
and returned status "ok" with 2 rules — a config that was not analysed at all
could PASS the gate. 28 SRX-policy files in the corpus returned 0 rules with
no note explaining why.

Junos signatures (SRX zone policies, `set security` / `set firewall`) now route
to the Junos frontend, which says the zone policies are not modeled. With no
firewall filter in the file the result is no_rules_parsed (INCOMPLETE).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.gate import _pick_parser  # noqa: E402
from rulehawk.parse_junos import parse_junos  # noqa: E402
from rulehawk.parse_panos import detect as detect_panos  # noqa: E402

SRX = """security {
    policies {
        from-zone trust to-zone untrust {
            /*
            Deny to bad destinations.
            */
            policy deny-to-bad {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
    }
}
"""

SRX_SET = """set security policies from-zone trust to-zone untrust policy p1 match source-address any
set security policies from-zone trust to-zone untrust policy p1 match destination-address any
set security policies from-zone trust to-zone untrust policy p1 match application any
set security policies from-zone trust to-zone untrust policy p1 then permit
"""

FILTER_AND_SRX = """firewall {
    family inet {
        filter EDGE {
            term t1 {
                from { protocol tcp; destination-port 22; }
                then accept;
            }
        }
    }
}
""" + SRX


def test_srx_policies_route_to_junos_and_are_not_analysed():
    vendor, fn = _pick_parser(SRX, "auto")
    assert vendor == "junos"
    aces, notes = fn(SRX)
    assert aces == []
    assert any("security polic" in n for n in notes), notes


def test_srx_set_form_routes_to_junos_with_a_note():
    vendor, fn = _pick_parser(SRX_SET, "auto")
    assert vendor == "junos"
    aces, notes = fn(SRX_SET)
    assert aces == [] and any("security polic" in n for n in notes), notes


def test_filters_still_parse_and_policies_are_surfaced():
    aces, notes = parse_junos(FILTER_AND_SRX)
    assert aces and any("security polic" in n for n in notes)


def test_panos_set_form_is_not_taken_by_junos():
    pan = ("set rulebase security rules r1 from trust to untrust source any "
           "destination any application any service any action allow\n")
    assert _pick_parser(pan, "auto")[0] == "panos" or detect_panos(pan)


def test_iptables_script_non_iptables_dash_t_is_not_a_table():
    # corpus: `ssh -t "su -"` / `mount -t ntfs-3g` in iptables shell scripts
    # produced "iptables 'su -' table rule present" notes.
    from rulehawk.parse_iptables import parse_iptables
    aces, notes = parse_iptables('iptables -P INPUT DROP\nssh -t "su -" host\n'
                                 'mount -t ntfs-3g /dev/sdb1 /mnt\n'
                                 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n'
                                 'iptables -t nat -A POSTROUTING -j MASQUERADE\n')
    assert not any("su -" in n or "ntfs-3g" in n for n in notes), notes
    assert any("'nat'" in n for n in notes)
    assert len(aces) == 2


_SG = ('{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [{"IpProtocol": "tcp", '
       '"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], '
       '"IpPermissionsEgress": []}')


def test_awssg_inside_a_wrapper_document_is_audited():
    # corpus: {"args": ..., "result": {"SecurityGroups": [...]}} and a dump
    # keyed by command gave "no SecurityGroups array found" (INCOMPLETE).
    text = '{"args": ["ec2"], "result": {"SecurityGroups": [' + _SG + ']}}'
    vendor, fn = _pick_parser(text, "auto")
    aces, notes = fn(text)
    assert vendor == "aws-sg" and aces, (vendor, notes)
    assert any("nested" in n for n in notes)


def test_awssg_with_a_text_preamble_is_audited():
    text = ('### cmd: aws ec2 describe-security-groups ---\n'
            '{"SecurityGroups": [' + _SG + ']}\n')
    vendor, fn = _pick_parser(text, "auto")
    aces, notes = fn(text)
    assert vendor == "aws-sg" and aces, (vendor, notes)
    assert any("preamble" in n for n in notes)
