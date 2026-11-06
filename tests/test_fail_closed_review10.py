"""Fail-closed, tenth review of #42 (review-rh42-r9.md).

Round 9 gave every consuming handler a cited grammar, but two root causes
were outside every grammar:

1. **The dialect was a default.** A Cisco file with no NX-OS or EOS marker was
   read as IOS (`ios-asa`) by fallback, and an untyped `ip access-list NAME`
   (the NX-OS / EOS form) was then read by a fourth, made-up dialect. On IOS
   that header is not in the grammar, and an interface bound to a named ACL
   that does not exist passes every packet (R9-1); a bannerless EOS file was
   read by the IOS rules (R9-3). Now a PASS needs the file's dialect to be
   positively identified by a marker that dialect writes (each one cited),
   and a header the identified dialect does not have is noted.
2. **A single-valued field set twice was merged.** PAN-OS `set service S
   protocol tcp port X` twice was read as the union of the ports (R9-2), and
   `any` plus a member kept `any` (R9-5). Now a field that holds one value
   and is set more than once with a different value is noted, unless a
   citation states the replace semantics.

Also: port names per vendor and protocol (R9-4), the IOS IPv6 sequence
citation and the docs (R9-6), and Junos `three-color-policer` (R9-7).

The configs in tests/fixtures/fail_closed/variants/r9 are the reviewer's
synthetic variants (RFC 5737 / RFC 3849 addresses).
"""

from __future__ import annotations

import glob
import io
import json
import os
import re
import sys
from contextlib import redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_fail_closed_review8 import (  # noqa: E402
    _DENY, _IF, _IF6, _LEAK, _NX, _NXDENY, _NXLEAK, _OTHER, _codes, _ios,
    _never_pass, _nx, _report, _stays_pass, _write)

from rulehawk import cli  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FX = os.path.join(_ROOT, "tests", "fixtures", "fail_closed")
_R9 = os.path.join(_FX, "variants", "r9")


def _r9(name: str) -> str:
    p = os.path.join(_R9, name)
    if not os.path.exists(p):
        raise FileNotFoundError(name)
    return p


def _pol9(name: str) -> str:
    """The reviewer's `rev42-r9/pol.sh`: `*_tcpNNN` / `*_udpNNN` ->
    must_not_reach that port, `*_reachtcpNNN` -> must_reach it, `*reach*` ->
    must_reach ip, else must_not_reach ip."""
    base = os.path.basename(name)
    m = re.search(r"_(reach)?(tcp|udp)(\d+)", base)
    if m:
        kind = "must_reach" if m.group(1) else "must_not_reach"
        return f"{kind}_{m.group(2)}{m.group(3)}.json"
    if base.startswith("v6"):
        return "v6_ip.json"
    return "v4_reach_ip.json" if "reach" in base else "v4_ip.json"


def _notes(path: str, pol: str = "") -> list:
    return _report(path, pol or _pol9(path))["parse_notes"]


# --------------------------------------------------------------------------- #
# The reviewer's false PASSes, every surface
# --------------------------------------------------------------------------- #
_R9_1 = ["a01_ios_untyped_header_cidr.cfg", "a02_ios_untyped_header_wildcard.cfg",
         "a03_ios_untyped_header_numbered.cfg"]
_R9_3 = ["e02_eos_wildcard_operands.cfg", "e05_eos_deny_log.cfg",
         "e07_eos_bannerless_upper_deny.cfg", "e08_eos_bannerless_mixed_numbering.cfg"]
_R9_2 = ["p38_service_port_redefined_tcp3306.set",
         "p45_service_port_redefined_allow_reachtcp3306.set"]
_R9_5 = ["p35_service_appended.set", "p43_any_then_member_tcp3306.set",
         "p44_source_any_then_member.set"]
_R9_7 = ["j18_tcp_three_color.conf"]
# Checked by hand by the reviewer, genuine; still PASS.
_GENUINE = [
    "a06_ios_mode_then_flat_append.cfg", "a15_ios_deny_log_input.cfg",
    "a17_ios_reentry_append.cfg", "a19_ios_iface_reentered_out.cfg",
    "a20_ios_trailing_space.cfg", "a24_ios_acl_persistent.cfg",
    "a29_ios_reentry_remark_only.cfg", "a44_ios_only_other_permit.cfg",
    "n01_nxos_stats_per_entry.cfg", "n02_nxos_wildcard_operands.cfg",
    "n03_nxos_deny_log.cfg", "n05_nxos_unused_object_group.cfg",
    "j06_prefix_list.conf", "j10_count_discard.conf", "j11_log_syslog_discard.conf",
    "j12_policer_discard.conf", "j13_sample_mirror_discard.conf",
    "j14_fc_lp_discard.conf", "j15_ipsec_sa_discard.conf",
    "j17_service_accounting_accept.conf", "j19_in_and_out.conf",
    "j20_no_family_block.conf", "j21_dscp_discard.conf", "j22_discard_then_count.conf",
    "j26_harmless_other_stanzas.conf", "j27_routing_instance_iface.conf",
    "j28_lo0_unfiltered.conf", "j30_inet6_unfiltered_v4policy.conf",
    "i14_sh_zero_counters.sh", "p12_source_hip.set", "p13_category_any.set",
    "p14_action_drop.set", "p15_action_reset_both.set", "p16_bracket_lists.set",
    # PAN-OS rule `destination` is a member list: a second `set` adds a
    # member (the api-lab set/merge citation, as for p08 in round 9).
    "p17_rule_field_reset.set",
    "p20_addr_desc_tag.set", "p30_tags.set", "p32_option.set", "p33_log_profile.set",
    "p36_service_deny_tcp3306.set", "p40_service_list_tcp3306.set"]
# Genuine by the reviewer's reading, but a single-valued leaf is set twice
# with two values: the replace reading is not cited, so the answer is noted.
# Over-blocking, listed in the PR body.
_OVERBLOCKED = ["p31_action_overwritten_deny.set",
                "p46_service_port_set_after_rule_tcp3306.set"]


@pytest.mark.parametrize("cfg", _R9_1 + _R9_3 + _R9_2 + _R9_5 + _R9_7)
def test_r9_reviewer_false_passes_never_pass(cfg):
    _never_pass(_r9(cfg), _pol9(cfg))


@pytest.mark.parametrize("cfg", _GENUINE)
def test_r9_genuine_controls_stay_pass(cfg):
    _stays_pass(_r9(cfg), _pol9(cfg))


@pytest.mark.parametrize("cfg", _OVERBLOCKED)
def test_r9_single_valued_leaf_set_twice_is_noted_even_where_both_readings_agree(cfg):
    r = _report(_r9(cfg), _pol9(cfg))
    assert r["assertion_verdict"] == "UNKNOWN", (cfg, _codes(r))
    assert any("set more than once" in n for n in r["parse_notes"]), r["parse_notes"]


def test_r9_every_other_reviewer_variant_is_still_not_pass():
    keep = set(_GENUINE)
    for path in sorted(glob.glob(os.path.join(_R9, "*"))):
        name = os.path.basename(path)
        if name in keep:
            continue
        r = _report(path, _pol9(name))
        assert r["assertion_verdict"] != "PASS", (name, _codes(r))


# --------------------------------------------------------------------------- #
# Structural change 1: positive dialect identification (R9-1, R9-3)
# --------------------------------------------------------------------------- #
# The test's own markers, written from the citations (not from rulehawk's
# detectors):
# - IOS / IOS XE `show running-config`: "Building configuration...",
#   "Current configuration : 986 bytes", "version 12.4" / "version 15.2",
#   "boot-start-marker" (Cisco 800 Series ISR Software Configuration Guide,
#   "Basic Router Configuration"); the IOS ACL grammar `ip access-list
#   {standard | extended} NAME` (Catalyst 9400 IOS XE 16.10 command reference)
#   of which only `extended` is taken (EOS is not cited and may have a
#   `standard` form); numbered `access-list N {permit|deny|remark}`.
# - ASA: ": Saved", "ASA Version 9.1(5)4" (Cisco, "Configure DNS Doctoring
#   for Three NAT Interfaces on ASA"); `access-list NAME extended|standard`
#   (ASA 9.20 firewall configuration guide).
# - NX-OS: "version 9.3(1) Bios:version 05.39" (Nexus 9000 NX-OS 9.3(x)
#   System Management guide, "Configuration Replace") and `feature NAME`.
# - EOS: "! device: r1 (cEOSLab, EOS-4.33.1F-...)" in `show running-config`
#   (third-party: the annet tutorial, annetutil.github.io; Arista's own
#   manual is behind a bot challenge).
_T_IOS = re.compile(
    r"(?m)^(?:Building configuration\.\.\.|Current configuration : \d+ bytes|"
    r"version \d+\.\d+\s*$|boot-start-marker\s*$|"
    r"ip access-list extended \S+\s*$|"
    r"access-list \d+ (?:permit|deny|remark)\b|"
    r": Saved\s*$|ASA Version \d|access-list \S+ (?:extended|standard) )")
_T_NX = re.compile(r"(?m)^(?:version \d+\.\d+\(\d+\)|feature \S)")
_T_EOS = re.compile(r"(?m)^! device: \S+ \(.*EOS-\d")
_T_MARK = {"ios-asa": _T_IOS, "nxos": _T_NX, "eos": _T_EOS}


def _corpus_files():
    out = []
    for d in ("cfg", "rev42", "rev42r2", "rev42r3", "variants"):
        for path in sorted(glob.glob(os.path.join(_FX, d, "**", "*"), recursive=True)):
            if os.path.isfile(path):
                out.append(path)
    return out


def _vendor_and_verdict(path: str, pol: str):
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.main([path, "--json", "--policy", os.path.join(_FX, "pol", pol)])
    r = json.loads(buf.getvalue())
    return r.get("vendor"), r["assertion_verdict"]


def test_every_cisco_pass_rests_on_a_positive_dialect_marker():
    """A PASS needs the file's dialect to be identified by a marker that
    dialect writes, never by default. Checked with the test's own cited
    markers over every config fixture (four policies each)."""
    bad = []
    for path in _corpus_files():
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        if path.endswith(".json") or any(
                det(text) for det in (cli.detect_junos, cli.detect_panos,
                                      cli.detect_iptables, cli.detect_awssg)):
            continue
        pols = ["v4_ip.json", "v4_reach_ip.json", "v4_tcp445.json", "v6_ip.json"]
        if os.sep + "r9" + os.sep in path:
            pols.append(_pol9(path))
        for pol in pols:
            vendor, verdict = _vendor_and_verdict(path, pol)
            if verdict == "PASS" and vendor in _T_MARK and not _T_MARK[vendor].search(text):
                bad.append(f"{os.path.relpath(path, _FX)} {pol} {vendor}")
    assert not bad, "\n".join(bad)


_BANNER_IOS = "Building configuration...\n\nCurrent configuration : 900 bytes\n!\nversion 15.2\n!\n"
_BANNER_EOS = "! Command: show running-config\n! device: r1 (vEOS, EOS-4.30.0F)\n!\n"
_BANNER_NX = "!Command: show running-config\n\nversion 9.3(10) Bios:version 05.45\n"
_EOS_IF = ("interface Ethernet1\n   no switchport\n   ip address 198.51.100.1/24\n"
           "   ip access-group F in\ninterface Ethernet2\n   no switchport\n"
           "   ip address 192.0.2.1/24\n   ip access-group F in\n")
_UNTYPED = "ip access-list F\n 10 " + _DENY + "\n 20 " + _OTHER + "\n"
_UNTYPED_CIDR = "ip access-list F\n 10 " + _NXDENY + "\n 20 permit ip 203.0.113.0/24 any\n"
_EOS_BODY = "ip access-list F\n   10 " + _NXDENY + "\n   20 permit ip 203.0.113.0/24 any\n"


@pytest.mark.parametrize("text", [
    # R9-1: an untyped header in a file identified as IOS (banner, or another
    # typed header): IOS's grammar has `{standard | extended}`, and a bound
    # named ACL that does not exist passes every packet.
    _BANNER_IOS + _IF + _UNTYPED,
    _BANNER_IOS + _IF + _UNTYPED_CIDR,
    _IF + _UNTYPED + "ip access-list extended G\n permit ip any any\n",
    # No marker at all: the dialect is a default (R9-1, R9-3).
    _IF + _UNTYPED,
    _IF + _UNTYPED_CIDR,
    _EOS_IF + _EOS_BODY,
    _EOS_IF + "ip access-list F\n   10 DENY ip 192.0.2.0/24 198.51.100.0/24\n"
    "   20 permit ip 203.0.113.0/24 any\n",
    # A banner that names no dialect on its own (`! Command: show
    # running-config` is written by both NX-OS and EOS): not a marker.
    "! Command: show running-config\n" + _EOS_IF + _EOS_BODY,
    # NX-OS identified only by `interface Ethernet1/1` naming (classic IOS
    # images also use it): not a marker.
    _NX.replace("feature interface-vlan\n", "") + "ip access-list F\n  10 " + _NXDENY
    + "\n  20 permit ip 203.0.113.0/24 any\n",
])
def test_r9_1_dialect_not_positively_identified_never_passes(tmp_path, text):
    _never_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json", hosted=False)


def test_r9_1_bannerless_ios_ipv6_sequence_file_never_passes(tmp_path):
    # The round-8 R7-3 file (test_r7_3_ios_ipv6_sequence_keyword_stays_pass)
    # without its banner: `ipv6 access-list F6` and `sequence N` are written
    # by more than one dialect, so nothing names the dialect.
    text = (_IF6 + "ipv6 access-list F6\n"
            " sequence 10 deny ipv6 2001:db8:20::/48 2001:db8:10::/48\n"
            " sequence 20 permit ipv6 2001:db8:30::/48 any\n")
    _never_pass(_write(tmp_path, "x.cfg", text), "v6_ip.json", hosted=False)


@pytest.mark.parametrize("text", [
    # A typed IOS header in a file identified as NX-OS or EOS: the NX-OS
    # grammar is `ip access-list access-list-name` (no type); the EOS grammar
    # is not cited.
    _NX + "ip access-list extended F\n  10 " + _NXDENY + "\n  20 permit ip 203.0.113.0/24 any\n",
    _BANNER_EOS + _EOS_IF + "ip access-list extended F\n   10 " + _NXDENY
    + "\n   20 permit ip 203.0.113.0/24 any\n",
    _BANNER_NX + _NX + "ip access-list standard F\n  10 deny 192.0.2.0/24\n"
    "  20 permit any\n",
])
def test_r9_1_a_header_the_identified_dialect_lacks_never_passes(tmp_path, text):
    _never_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json", hosted=False)


@pytest.mark.parametrize("text", [
    _ios(_DENY, _OTHER),                                  # typed IOS header
    _BANNER_IOS + _ios(_DENY, _OTHER),
    _nx("10 " + _NXDENY, "20 permit ip 203.0.113.0/24 any"),   # `feature`
    _BANNER_NX + _nx("10 " + _NXDENY, "20 permit ip 203.0.113.0/24 any"),
    _BANNER_EOS + _EOS_IF + _EOS_BODY,                     # EOS `! device:`
])
def test_r9_1_positively_identified_dialects_stay_pass(tmp_path, text):
    _stays_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json")


def test_r9_1_the_note_names_the_cause(tmp_path):
    r = _report(_write(tmp_path, "x.cfg", _IF + _UNTYPED), "v4_ip.json")
    assert any("dialect" in n and "not positively identified" in n
               for n in r["parse_notes"]) or any(
        "dialect" in x["message"] and "not positively identified" in x["message"]
        for f in r["findings"] for x in f.get("reasons", [])), r


def test_r9_1_untyped_header_on_ios_names_the_grammar(tmp_path):
    r = _report(_write(tmp_path, "x.cfg", _BANNER_IOS + _IF + _UNTYPED), "v4_ip.json")
    assert any("not in the IOS grammar" in n for n in r["parse_notes"]), r["parse_notes"]


def test_r9_1_forced_vendor_still_needs_its_marker(tmp_path):
    """A user-forced vendor does not identify the file: the marker check runs
    on the text whatever the label came from."""
    from rulehawk import gate as g
    from test_fail_closed import _load_policy
    p = _write(tmp_path, "x.cfg", _EOS_IF + _EOS_BODY)
    res = g.run_gate([p], _load_policy("v4_ip.json"), vendor="eos")
    assert res.verdict != "PASS", res.verdict


# --------------------------------------------------------------------------- #
# Structural change 2: single-valued fields (R9-2, R9-5)
# --------------------------------------------------------------------------- #
_PA_HEAD = ("set address CORP ip-netmask 192.0.2.0/24\n"
            "set address PCI ip-netmask 198.51.100.0/24\n")
_PA_DENY_S = ("set rulebase security rules d from any to any source CORP destination PCI "
              "application any service S action deny\n")
_PA_ALLOW = ("set rulebase security rules a from any to any source CORP destination any "
             "application any service any action allow\n")
_PA_ALLOW_S = ("set rulebase security rules a from any to any source CORP destination PCI "
               "application any service S action allow\n")


@pytest.mark.parametrize("text,pol", [
    (_PA_HEAD + "set service S protocol tcp port 3306\nset service S protocol tcp port 3307\n"
     + _PA_DENY_S + _PA_ALLOW, "must_not_reach_tcp3306.json"),
    (_PA_HEAD + "set service S protocol tcp port 3306\nset service S protocol tcp port 3307\n"
     + _PA_ALLOW_S, "must_reach_tcp3306.json"),
    (_PA_HEAD + "set service S protocol tcp port 3306\n"
     "set service S protocol tcp source-port 1-65535\nset service S protocol tcp source-port 1024\n"
     + _PA_DENY_S + _PA_ALLOW, "must_not_reach_tcp3306.json"),
    (_PA_HEAD + "set service S protocol tcp port 3306,3307\nset service S protocol tcp port 3306\n"
     + _PA_DENY_S + _PA_ALLOW, "must_not_reach_tcp3306.json"),
    # rule `action` set twice with two values
    (_PA_HEAD + "set rulebase security rules d from any to any source CORP destination PCI "
     "application any service any action allow\nset rulebase security rules d action deny\n"
     + _PA_ALLOW, "v4_ip.json"),
    # address object value set twice
    ("set address CORP ip-netmask 203.0.113.0/24\nset address CORP ip-netmask 192.0.2.0/24\n"
     "set address PCI ip-netmask 198.51.100.0/24\n"
     "set rulebase security rules d from any to any source CORP destination PCI "
     "application any service any action deny\n" + _PA_ALLOW, "v4_ip.json"),
    # R9-5: `any` plus a member in one field
    (_PA_HEAD + "set service S protocol tcp port 22\n"
     "set rulebase security rules d from any to any source CORP destination PCI "
     "application any service any action deny\nset rulebase security rules d service S\n"
     + _PA_ALLOW, "must_not_reach_tcp3306.json"),
    (_PA_HEAD + "set rulebase security rules d from any to any source any destination PCI "
     "application any service any action deny\n"
     "set rulebase security rules d source 203.0.113.0/24\n" + _PA_ALLOW, "v4_ip.json"),
    (_PA_HEAD + "set rulebase security rules d from any to any source [ any 203.0.113.0/24 ] "
     "destination PCI application any service any action deny\n" + _PA_ALLOW, "v4_ip.json"),
])
def test_r9_2_panos_single_valued_field_set_twice_never_passes(tmp_path, text, pol):
    _never_pass(_write(tmp_path, "x.set", text), pol, hosted=False)


@pytest.mark.parametrize("text,pol", [
    # the same value twice: one reading
    (_PA_HEAD + "set service S protocol tcp port 3306\nset service S protocol tcp port 3306\n"
     + _PA_DENY_S + _PA_ALLOW, "must_not_reach_tcp3306.json"),
    (_PA_HEAD + "set rulebase security rules d from any to any source CORP destination PCI "
     "application any service any action deny\nset rulebase security rules d action deny\n"
     + _PA_ALLOW, "v4_ip.json"),
    # a member list (address-group static, rule source) appends (cited)
    (_PA_HEAD + "set rulebase security rules d from any to any source CORP destination PCI "
     "application any service any action deny\n"
     "set rulebase security rules d destination 203.0.113.0/24\n" + _PA_ALLOW, "v4_ip.json"),
])
def test_r9_2_panos_one_reading_stays_pass(tmp_path, text, pol):
    _stays_pass(_write(tmp_path, "x.set", text), pol)


_JIF = ("interfaces {\n"
        "    ge-0/0/0 { unit 0 { family inet { filter { input F; } address 192.0.2.1/24; } } }\n"
        "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n"
        "}\n")
_JFW = ("firewall {\n    family inet {\n"
        "        filter F {\n"
        "            term d { from { source-address { 192.0.2.0/24; } destination-address "
        "{ 198.51.100.0/24; } } then discard; }\n"
        "            term a { from { source-address { 192.0.2.0/24; } } then accept; }\n"
        "        }\n"
        # A second filter that permits nothing: on its own it never
        # turns the answer, so a duplicate `input` naming it is the only
        # change.
        "        filter OPEN { term t { then discard; } }\n"
        "    }\n}\n")


@pytest.mark.parametrize("text", [
    # Juniper: "input filter-name: Name of one filter to evaluate when
    # packets are received on the interface" (filter (Applying to a Logical
    # Interface)). Two `input` values on one unit and family: not one filter.
    _JIF.replace("{ input F; } address 192.0.2.1/24",
                 "{ input OPEN; input F; } address 192.0.2.1/24") + _JFW,
    _JIF.replace("{ input F; } address 192.0.2.1/24",
                 "{ input F; input OPEN; } address 192.0.2.1/24") + _JFW,
    "set interfaces ge-0/0/0 unit 0 family inet filter input OPEN\n"
    "set interfaces ge-0/0/0 unit 0 family inet filter input F\n"
    "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\n"
    "set interfaces ge-0/0/1 unit 0 family inet filter input F\n"
    "set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24\n"
    "set firewall family inet filter F term d from source-address 192.0.2.0/24\n"
    "set firewall family inet filter F term d from destination-address 198.51.100.0/24\n"
    "set firewall family inet filter F term d then discard\n"
    "set firewall family inet filter F term a from source-address 192.0.2.0/24\n"
    "set firewall family inet filter F term a then accept\n"
    "set firewall family inet filter OPEN term t then discard\n",
])
def test_r9_2_junos_one_filter_input_set_twice_never_passes(tmp_path, text):
    _never_pass(_write(tmp_path, "x.conf", text), "v4_ip.json", hosted=False)


@pytest.mark.parametrize("text", [
    # `iptables -s A -s B` is rejected ("multiple -s flags not allowed"):
    # one rule option set twice.
    "iptables -P INPUT DROP\niptables -P OUTPUT DROP\niptables -P FORWARD DROP\n"
    "iptables -A FORWARD -s 192.0.2.0/24 -s 203.0.113.0/24 -j ACCEPT\n",
    "iptables -P INPUT DROP\niptables -P OUTPUT DROP\niptables -P FORWARD DROP\n"
    "iptables -A FORWARD -d 203.0.113.0/24 -d 198.51.100.0/24 -s 192.0.2.0/24 -j ACCEPT\n",
    # iptables-restore: a chain's policy declared twice in one table block
    "*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:FORWARD DROP [0:0]\n"
    ":OUTPUT DROP [0:0]\n-A FORWARD -s 203.0.113.0/24 -j ACCEPT\nCOMMIT\n",
])
def test_r9_2_iptables_single_valued_option_set_twice_never_passes(tmp_path, text):
    ext = ".rules" if text.startswith("*") else ".sh"
    _never_pass(_write(tmp_path, "x" + ext, text), "v4_ip.json", hosted=False)


def test_r9_2_iptables_policy_command_replaces_cited(tmp_path):
    """iptables(8): `-P chain target` "Set the policy for the built-in
    (non-user-defined) chain to the given target": a later `-P` replaces the
    earlier one, so the last one decides (i04 FAIL, its mirror PASS)."""
    r = _report(_r9("i04_sh_policy_twice_last_accept.sh"), "v4_ip.json")
    assert r["assertion_verdict"] == "FAIL", _codes(r)
    p = _write(tmp_path, "x.sh", "iptables -P INPUT DROP\niptables -P OUTPUT DROP\n"
               "iptables -P FORWARD ACCEPT\niptables -P FORWARD DROP\n"
               "iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT\n")
    _stays_pass(p, "v4_ip.json")


# --------------------------------------------------------------------------- #
# R9-4: port names per vendor and protocol
# --------------------------------------------------------------------------- #
def _ports(text, parser="acls"):
    from rulehawk.parse import parse_acls
    from rulehawk.parse_iptables import parse_iptables
    from rulehawk.parse_junos import parse_junos
    fn = {"acls": parse_acls, "ipt": parse_iptables, "junos": parse_junos}[parser]
    aces, notes = fn(text)
    return [(a.proto, a.dst_port.lo, a.dst_port.hi, a.imprecise) for a in aces], notes


def test_r9_4_asa_radius_is_1645():
    """ASA 9.19 general configuration guide, "TCP and UDP Ports": radius,
    UDP, 1645; "The ASA listens for RADIUS on ports 1645 and 1646"."""
    aces, notes = _ports("access-list OUT extended deny udp any any eq radius\n")
    assert aces[0][:3] == ("udp", 1645, 1645), (aces, notes)
    assert not aces[0][3]


@pytest.mark.parametrize("text", [
    # IOS: a name IOS does not define, and a name on the wrong protocol
    # ("TCP port names can only be used when filtering TCP").
    "ip access-list extended F\n deny tcp any any eq mysql\n",
    "ip access-list extended F\n deny tcp any any eq rdp\n",
    "ip access-list extended F\n deny tcp any any eq tftp\n",
    "ip access-list extended F\n deny udp any any eq telnet\n",
    # ASA: a name on the wrong protocol.
    "access-list OUT extended deny tcp any any eq radius\n",
])
def test_r9_4_cisco_name_not_defined_for_the_protocol_is_noted(text):
    aces, notes = _ports(text)
    assert notes and all(a[3] for a in aces), (aces, notes)


@pytest.mark.parametrize("text,parser", [
    # NX-OS / EOS: no cited name table.
    ("feature interface-vlan\ninterface Ethernet1/1\n  ip access-group F in\n"
     "ip access-list F\n  10 deny tcp any any eq www\n", "nx"),
    # iptables: a name resolves through the host's /etc/services
    # (iptables-save writes numbers).
    ("*filter\n:FORWARD DROP [0:0]\n-A FORWARD -p tcp --dport http -j DROP\nCOMMIT\n", "ipt"),
    # Junos: a name not in Juniper's destination-port synonym list.
    ("firewall { family inet { filter F { term d { from { protocol tcp; "
     "destination-port mysql; } then discard; } } } }\n", "junos"),
])
def test_r9_4_port_names_without_a_cited_table_are_noted(text, parser):
    if parser == "nx":
        from rulehawk.parse_nxos import parse_nxos
        aces, notes = parse_nxos(text)
        aces = [(a.proto, a.dst_port.lo, a.dst_port.hi, a.imprecise) for a in aces]
    else:
        aces, notes = _ports(text, parser)
    assert notes and any(a[3] for a in aces), (aces, notes)


def test_r9_4_cited_names_stay_exact():
    """IOS `eq www` on TCP (80), ASA `eq https` (443), Junos `http` (80)."""
    aces, notes = _ports("ip access-list extended F\n deny tcp any any eq www\n")
    assert aces[0][:4] == ("tcp", 80, 80, False) and not notes, (aces, notes)
    aces, notes = _ports("access-list OUT extended deny tcp any any eq https\n")
    assert aces[0][:4] == ("tcp", 443, 443, False) and not notes, (aces, notes)
    aces, notes = _ports("firewall { family inet { filter F { term d { from { protocol tcp; "
                         "destination-port http; } then discard; } } } }\n", "junos")
    assert aces[0][:4] == ("tcp", 80, 80, False) and not notes, (aces, notes)


# --------------------------------------------------------------------------- #
# R9-6 / R9-7
# --------------------------------------------------------------------------- #
def test_r9_7_three_color_policer_is_noted():
    r = _report(_r9("j18_tcp_three_color.conf"), "v4_ip.json")
    assert any("three-color-policer" in n for n in r["parse_notes"]), r["parse_notes"]


def test_r9_6_compatibility_names_the_protect_must_reach_change():
    with open(os.path.join(_ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
        text = fh.read()
    comp = text[text.index("### Compatibility"):]
    assert "protect:" in comp and "must_reach" in comp, comp[:400]


def test_r9_6_known_limits_name_positive_dialect_identification():
    from rulehawk.failclosed import KNOWN_LIMITS
    joined = " ".join(KNOWN_LIMITS)
    assert "positively identified" in joined, joined[:300]
    assert "every line of an object on the evaluated path (a Cisco ACL, ACL header" \
        not in joined


# --------------------------------------------------------------------------- #
# Mutation families (round 10)
# --------------------------------------------------------------------------- #
def test_r9_new_mutation_families_exist():
    from test_fail_closed_mutation_all import mutants
    text = _BANNER_IOS + _ios(_DENY, _OTHER)
    fams = {m[0] for m in mutants(text, "ios-asa")}
    assert {"cisco-marker-strip", "cisco-untyped-header",
            "cisco-dialect-transplant"} <= fams, fams
    pan = _PA_HEAD + "set service S protocol tcp port 3306\n" + _PA_DENY_S + _PA_ALLOW
    fams = {m[0] for m in mutants(pan, "panos")}
    assert {"panos-leaf-dup", "panos-any-plus-member"} <= fams, fams
    fams = {m[0] for m in mutants(_JIF + _JFW, "junos")}
    assert "junos-leaf-dup" in fams, fams
