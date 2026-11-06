"""Fail-closed, fourth review of #42 (review-rh42-r3.md): the false PASSes
that survived the round-3 fixes, and the Cisco interface allowlist.

Every config in tests/fixtures/fail_closed/rev42r3 is the reviewer's
synthetic variant (RFC 5737 / RFC 3849 addresses). Each test asserts
UNKNOWN with its reason code on every surface (CLI text, --json,
--evidence, gate at high/critical/low, MCP rulehawk_audit, hosted page).

Structural change: on Cisco IOS / NX-OS / EOS every interface subcommand
must be on an allowlist of lines that cannot change a transit packet's
fate (`interface-feature-unmodeled` otherwise), and global features that
drop, inspect statefully, rewrite or bypass the ACL are UNKNOWN with their
own codes.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_fail_closed import (  # noqa: E402
    _BOUND_IOS, _assertion_findings, _pol, _reason_codes, _run_cli)
from test_fail_closed_review3 import (  # noqa: E402
    _hosted, _unknown_on_every_surface, _write)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REV = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "rev42r3")


def _rev(name: str) -> str:
    return os.path.join(_REV, name)


def _report(path: str, pol: str = "v4_ip.json") -> dict:
    _, out = _run_cli([path, "--json", "--policy", _pol(pol)])
    return json.loads(out)


def _codes(report: dict) -> set:
    out = set()
    for f in _assertion_findings(report):
        out |= _reason_codes(f)
    return out


# --------------------------------------------------------------------------- #
# R1: the FORWARD policy comes from parsed policy lines, never from comments
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["c01_comment_policy.sh",
                                 "c02b_rule_comment_policy_leading_space.sh"])
def test_r1_forward_policy_in_a_comment_is_not_a_policy(cfg):
    _unknown_on_every_surface(_rev(cfg), "iptables-chain-policy-unset")


@pytest.mark.parametrize("rule", [
    'iptables -A INPUT -j LOG --log-prefix " -P FORWARD DROP "',
    'iptables -A GUARD -m comment --comment "x -P FORWARD DROP" -j DROP',
    'iptables -A INPUT -m comment --comment "--policy FORWARD DROP" -j ACCEPT',
    "iptables -A INPUT -s 203.0.113.0/24 -j ACCEPT # -P FORWARD DROP",
])
def test_r1_a_quoted_policy_inside_another_rule_is_not_a_policy(tmp_path, rule):
    text = ("iptables -N GUARD\n"
            "iptables -A GUARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n"
            + rule + "\n")
    _unknown_on_every_surface(_write(tmp_path, "x.sh", text),
                              "iptables-chain-policy-unset")


def test_r1_a_real_forward_policy_still_counts(tmp_path):
    text = ("iptables -P FORWARD DROP\n"
            "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n")
    r = _report(_write(tmp_path, "ok.sh", text))
    assert r["assertion_verdict"] == "PASS", r["findings"]


# --------------------------------------------------------------------------- #
# R2: `default` forms and abbreviations of a binding
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["a01_default_ip_access_group.cfg",
                                 "a05_no_ag_abbrev.cfg"])
def test_r2_default_or_abbreviated_binding_lines_are_unknown(cfg):
    _unknown_on_every_surface(_rev(cfg), "interface-feature-unmodeled")


def test_r2_default_interface_is_a_removed_binding():
    _unknown_on_every_surface(_rev("a02_default_interface.cfg"),
                              "acl-binding-negated")


# --------------------------------------------------------------------------- #
# The allowlist itself
# --------------------------------------------------------------------------- #
_ALLOWED = [" description uplink to core", " ip address 203.0.113.9 255.255.255.0 secondary",
            " ipv6 address 2001:db8::1/64", " ipv6 enable", " no shutdown",
            " speed 1000", " duplex full", " negotiation auto", " load-interval 30",
            " no ip redirects", " no ip unreachables", " no cdp enable",
            " cdp enable"]


@pytest.mark.parametrize("line", _ALLOWED)
def test_allowlisted_interface_lines_keep_the_pass(tmp_path, line):
    text = _BOUND_IOS.replace(" ip access-group EDGE in\n!\ninterface GigabitEthernet0/1",
                              f" ip access-group EDGE in\n{line}\n!\ninterface GigabitEthernet0/1", 1)
    assert text != _BOUND_IOS
    r = _report(_write(tmp_path, "ok.cfg", text))
    assert r["assertion_verdict"] == "PASS", (line, _codes(r))


@pytest.mark.parametrize("line,keyword", [
    (" default ip access-group EDGE in", "default ip access-group"),
    (" no ip access-gr EDGE in", "no ip access-gr"),
    (" ip access-gr EDGE in", "ip access-gr"),
    (" ip verify unicast source reachable-via rx", "ip verify"),
    (" ip tcp adjust-mss 1360", "ip tcp"),
    (" encapsulation dot1Q 10", "encapsulation"),
    (" switchport access vlan 10", "switchport access"),
    (" vrf forwarding RED", "vrf"),
    (" ip unnumbered Loopback0", "ip unnumbered"),
    (" crypto map VPN", "crypto"),
    (" standby 1 ip 192.0.2.254", "standby"),
    (" tunnel destination 203.0.113.7", "tunnel"),
    (" ip helper-address 203.0.113.8", "ip helper-address"),
    (" frobnicate 198.51.100.77", "frobnicate"),
])
def test_any_other_interface_line_is_unknown_and_names_only_its_keyword(
        tmp_path, line, keyword):
    text = _BOUND_IOS.replace(" ip access-group EDGE in\n!\ninterface GigabitEthernet0/1",
                              f" ip access-group EDGE in\n{line}\n!\ninterface GigabitEthernet0/1", 1)
    path = _write(tmp_path, "x.cfg", text)
    _unknown_on_every_surface(path, "interface-feature-unmodeled")
    r = _report(path)
    msgs = [x["message"] for f in _assertion_findings(r) for x in f["reasons"]
            if x["code"] == "interface-feature-unmodeled"]
    assert msgs and all(keyword in m for m in msgs), msgs
    raw_tail = line.strip().split(None, len(keyword.split()))[-1]
    if raw_tail not in keyword:
        assert all(raw_tail not in m for m in msgs), msgs     # never the raw line


@pytest.mark.parametrize("vendor_line,iface", [
    ("version 9.3(10)\n", "Ethernet1/1"),
    ("! device: eos1 (vEOS, EOS-4.30.0F)\n", "Ethernet1"),
])
def test_allowlist_applies_to_nxos_and_eos(tmp_path, vendor_line, iface):
    text = (vendor_line +
            f"interface {iface}\n  no switchport\n  ip address 192.0.2.1/24\n"
            "  ip access-group F in\n  ip verify unicast source reachable-via rx\n"
            "interface Ethernet2\n  no switchport\n  ip address 198.51.100.1/24\n"
            "  ip access-group F in\n"
            "ip access-list F\n  10 deny ip 192.0.2.0/24 198.51.100.0/24\n"
            "  20 permit ip 203.0.113.0/24 any\n")
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text),
                              "interface-feature-unmodeled")


# --------------------------------------------------------------------------- #
# R4, R5, R6, R8: global features that drop, inspect, rewrite or bypass
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg,code", [
    ("a07_mpls_ip.cfg", "mpls-forwarding"),
    ("a07b_mpls_ip_corp_side_only.cfg", "mpls-forwarding"),
    ("a11_xconnect.cfg", "mpls-forwarding"),
    ("a09_reach_zbf_no_zonepair.cfg", "zone-firewall"),
    ("a10_reach_qos_drop.cfg", "qos-policy"),
    ("e04_reach_pbr_null0.cfg", "policy-routing"),
    ("a08_cbac_inspect.cfg", "stateful-inspection"),
    ("a12_ipv6_nat_pt.cfg", "nat-present"),
])
def test_cisco_features_that_bypass_or_drop_are_unknown(cfg, code):
    _unknown_on_every_surface(_rev(cfg), code)


@pytest.mark.parametrize("extra,code", [
    ("zone security INSIDE\n", "zone-firewall"),
    ("zone-pair security IN-OUT source INSIDE destination OUTSIDE\n", "zone-firewall"),
    ("ip inspect name FW tcp\n", "stateful-inspection"),
    ("ipv6 nat prefix 2001:db8:ff::/96\n", "nat-present"),
    ("nat64 prefix stateful 2001:db8:ff::/96\n", "nat-present"),
    ("control-plane\n service-policy input COPP\n", "qos-policy"),
    ("mpls ip\n", "mpls-forwarding"),
    ("mpls label protocol ldp\n", "mpls-forwarding"),
    ("mpls traffic-eng tunnels\n", "mpls-forwarding"),
    ("l2vpn xconnect context PW1\n", "mpls-forwarding"),
])
def test_global_feature_lines_are_unknown(tmp_path, extra, code):
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", _BOUND_IOS + extra), code)


def test_reach_control_stays_connectivity_ok():
    """e05: both interfaces bound in and out with B, which permits both
    directions; nothing else on the interfaces. Connectivity is proven."""
    r = _report(_rev("e05_reach_cisco_control_ok.cfg"), "v4_reach_ip.json")
    ok = [f for f in _assertion_findings(r) if f["kind"] == "connectivity-ok"]
    assert ok and ok[0]["verdict"] == "PASS", r["findings"]


# --------------------------------------------------------------------------- #
# R3: a PAN-OS name is resolved in the rule's own scope, then shared
# --------------------------------------------------------------------------- #
def test_r3_one_name_two_kinds_in_two_scopes_is_unknown():
    _unknown_on_every_surface(_rev("d01_kind_collision_addr_vs_group.set"),
                              "object-scope-ambiguous")


@pytest.mark.parametrize("text", [
    # same scope, two kinds
    "set address CORP ip-netmask 192.0.2.0/24\n"
    "set address-group CORP static [ Y ]\nset address Y ip-netmask 203.0.113.0/24\n",
    # the only definition is in another vsys: not visible from vsys1's rule
    "set vsys vsys2 address CORP ip-netmask 192.0.2.0/24\n",
    # own scope and shared both define it
    "set shared address CORP ip-netmask 203.0.113.0/24\n"
    "set vsys vsys1 address CORP ip-netmask 192.0.2.0/24\n",
])
def test_r3_scope_not_provable_is_unknown(tmp_path, text):
    rules = ("set vsys vsys1 rulebase security rules d from any to any source CORP "
             "destination 198.51.100.0/24 application any service any action deny\n"
             "set vsys vsys1 rulebase security rules a from any to any source "
             "203.0.113.0/24 destination any application any service any action allow\n")
    _unknown_on_every_surface(_write(tmp_path, "x.set", text + rules),
                              "object-scope-ambiguous")


@pytest.mark.parametrize("obj", ["set vsys vsys1 address CORP ip-netmask 192.0.2.0/24\n",
                                 "set shared address CORP ip-netmask 192.0.2.0/24\n"])
def test_r3_a_name_visible_in_own_scope_or_shared_resolves(tmp_path, obj):
    rules = ("set vsys vsys1 rulebase security rules d from any to any source CORP "
             "destination 198.51.100.0/24 application any service any action deny\n")
    r = _report(_write(tmp_path, "ok.set", obj + rules))
    assert r["assertion_verdict"] == "PASS", _codes(r)


# --------------------------------------------------------------------------- #
# R7: the known limits are printed next to every PASS
# --------------------------------------------------------------------------- #
_LIMIT = "Cisco reads ACLs, allowlisted interface lines and the listed global features"


def test_r7_known_limits_on_every_surface(tmp_path):
    from rulehawk import gate as g
    from rulehawk import mcp_server as m
    from test_fail_closed import _load_policy
    path = _write(tmp_path, "ok.cfg", _BOUND_IOS)
    r = _report(path)
    assert r["assertion_verdict"] == "PASS"
    ok = [f for f in _assertion_findings(r) if f["verdict"] == "PASS"]
    assert ok and all(_LIMIT in f["message"] for f in ok)
    assert _LIMIT in r["scope"]["statement"], r.get("scope")
    _, text = _run_cli([path, "--policy", _pol("v4_ip.json")])
    assert _LIMIT in text
    _, ev = _run_cli([path, "--evidence", "--policy", _pol("v4_ip.json")])
    assert any(_LIMIT in lim for lim in json.loads(ev)["scope"]["limits"])
    gate = g.run_gate([path], _load_policy("v4_ip.json"))
    assert _LIMIT in g.to_console(gate) and _LIMIT in g.to_markdown(gate)
    res = m.audit(path, _pol("v4_ip.json"))
    assert _LIMIT in res["scope"]["statement"]
    assert all(_LIMIT in x["message"] for x in res["segmentation_passed"])
    env = _hosted(path, "v4_ip.json")
    assert any(_LIMIT in f["message"] for f in env["report_json"]["findings"]
               if f["kind"] == "segmentation-ok")


def test_r7_readme_carries_the_known_limits():
    from rulehawk.failclosed import KNOWN_LIMITS
    with open(os.path.join(_ROOT, "README.md"), encoding="utf-8") as fh:
        readme = fh.read()
    for lim in KNOWN_LIMITS:
        assert lim in readme, lim


# --------------------------------------------------------------------------- #
# R1 follow-up: verb-first dispatch must not hide a second command, and a
# stray word in a rule (iptables rejects the line) is never skipped silently
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("line", [
    "iptables -N X ; iptables -P FORWARD ACCEPT",
    "iptables -N X && iptables -P FORWARD ACCEPT",
    "iptables -L -n; iptables -P FORWARD ACCEPT",
])
def test_r1_a_second_command_on_the_line_is_not_lost(tmp_path, line):
    text = ("iptables -P FORWARD DROP\n"
            "iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT\n" + line + "\n")
    path = _write(tmp_path, "x.sh", text)
    _unknown_on_every_surface(path, "parse-note")


@pytest.mark.parametrize("rule", [
    "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 bogus -j DROP",
    "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP extra",
])
def test_r1_a_stray_word_in_a_rule_is_not_skipped(tmp_path, rule):
    """iptables rejects a rule with a stray word, so the DROP is not applied
    and the ACCEPT policy decides: a PASS here would be false."""
    text = "iptables -P FORWARD ACCEPT\n" + rule + "\n"
    _unknown_on_every_surface(_write(tmp_path, "x.sh", text), "parse-note")


def test_r1_c03_comment_value_that_looks_like_a_verb():
    """c03: `--comment -A x` — `-A` is the comment, `x` a stray word that
    makes iptables reject the line. UNKNOWN, never a FAIL or PASS built on a
    rule the kernel refused."""
    path = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "rev42r3",
                        "c03_comment_dash_A_hides_insert.sh")
    _unknown_on_every_surface(path, "parse-note")


@pytest.mark.parametrize("line", ["no interface GigabitEthernet0/1",
                                  "default interface GigabitEthernet0/1"])
def test_r9_top_level_interface_removal_is_a_removed_binding(tmp_path, line):
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", _BOUND_IOS + line + "\n"),
                              "acl-binding-negated")


@pytest.mark.parametrize("extra,code", [
    # an abbreviated `interface` header reopening a stanza: its lines are
    # still checked, and the header itself is not modeled
    ("int GigabitEthernet0/1\n default ip access-gr EDGE in\n", "interface-feature-unmodeled"),
    ("inter GigabitEthernet0/1\n description x\n", "interface-feature-unmodeled"),
    ("no int GigabitEthernet0/1\n", "acl-binding-negated"),
    ("default inte GigabitEthernet0/1\n", "acl-binding-negated"),
])
def test_abbreviated_interface_command_is_unknown(tmp_path, extra, code):
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", _BOUND_IOS + extra), code)
