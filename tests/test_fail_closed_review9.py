"""Fail-closed, ninth review of #42 (review-rh42-r8.md).

Round 8 proved that every line on the path ends consumed or noted. It did
not prove that a handler which consumes a line reads it as the device does.
Round 9 gives every consuming handler a strict grammar written from a cited
document or source file: exact keywords (with the device's case rule),
numeric ranges, operand forms and argument counts. A line that does not fully
match is noted.

Findings: Junos last terminating action wins (R8-1); ACL sequence-number
ranges (R8-2); iptables-restore `COMMIT` is the exact line (R8-3); `-P` with
extra arguments (R8-4); `resequence` naming an ACL (R8-5); IOS CIDR operands
and ASA `log` arguments in IOS mode (R8-6); +10 numbering only where cited,
numbered remarks in the duplicate check (R8-7); mutation families that inject
accepted-with-the-wrong-meaning forms (R8-8); PAN-OS address object with an
extra token (R8-9); unknown statement in a Junos term (R8-10); Junos
`protect:` is UNKNOWN, not FAIL (R8-12).

The configs in tests/fixtures/fail_closed/variants/r8 are the reviewer's
synthetic variants (RFC 5737 / RFC 3849 addresses).
"""

from __future__ import annotations

import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_fail_closed_review8 import (  # noqa: E402
    _DENY, _IF, _IF6, _LEAK, _NX, _NXDENY, _NXLEAK, _NXOTHER, _OTHER, _codes,
    _ios, _never_pass, _nx, _pol_for, _report, _stays_pass, _write)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_R8 = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "r8")


def _r8(name: str) -> str:
    p = os.path.join(_R8, name)
    if not os.path.exists(p):
        raise FileNotFoundError(name)
    return p


_JHEAD = ("interfaces {\n"
          "    ge-0/0/0 { unit 0 { family inet { filter { input F; } address 192.0.2.1/24; } } }\n"
          "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n"
          "}\nfirewall {\n    family inet {\n        filter F {\n")
_JTAIL = "        }\n    }\n}\n"
_JFROM = ("from { source-address { 192.0.2.0/24; } "
          "destination-address { 198.51.100.0/24; } }")
_JA = "term a { from { source-address { 192.0.2.0/24; } } then accept; }"


def _junos(*terms: str) -> str:
    return _JHEAD + "".join(f"            {t}\n" for t in terms) + _JTAIL


# --------------------------------------------------------------------------- #
# The reviewer's false PASSes, every surface
# --------------------------------------------------------------------------- #
_R8_1 = ["j01_two_then_discard_accept.conf", "j02_then_block_discard_accept.conf",
         "j05_term_defined_twice.conf", "j08_reach_then_accept_then_discard.conf",
         "j09_then_block_reject_accept.conf", "j10_then_count_discard_then_accept.conf"]
_R8_2 = ["c01_ios_seq_over_max_deny.cfg", "c02_nxos_seq_over_max_deny.cfg",
         "c03_reach_ios_seq_near_max_then_unnumbered.cfg", "c09_seq_zero.cfg",
         "c12_ios_std_seq_over_max.cfg", "c13_reach_ios_seq_zero_permit.cfg"]
_R8_3 = ["i01_lowercase_commit.rules", "i01b_lowercase_commit_drop_policies.rules",
         "i09_commit_trailing_space.rules", "i09b_commit_trailing_space_drop_policies.rules"]
_R8_4 = ["i05_sh_policy_trailing.sh", "i05b_sh_policy_trailing_drop_policies.sh",
         "i10_sh_policy_drop_two_chains.sh"]
_R8_5 = ["c11b_nxos_resequence_after_hostname.cfg"]
_R8_6 = ["a18_cidr_in_ios_extended.cfg", "a19_cidr_in_ios_standard.cfg",
         "b06_deny_log_interval.cfg"]
_R8_7 = ["c05_eos_unnumbered_between_seq.cfg", "v6c04_ios_v6_unnumbered_between_seq.cfg",
         "b09_remark_numbered_dup_of_entry.cfg", "b09n_nxos_numbered_remark_dup.cfg"]
_R8_9 = ["p03_addr_trailing_word.set"]
_R8_10 = ["j04_term_unknown_stmt.conf"]
# Read by a cited grammar to a second value the device may take: noted.
# b05 `log 5` and b07 `log disable` are ASA log arguments, not an IOS cookie
# the cited grammar names; c08 `010` is a leading-zero number whose reading
# is not cited.
_STRICT = ["b05_deny_log_then_word.cfg", "b07_deny_log_disable.cfg",
           "c08_leading_zero_seq.cfg"]
# Checked by hand by the reviewer, genuine.
_GENUINE = ["a10_reenter_acl_unnumbered_after_numbered.cfg",
            "b11_flat_remark_then_entry.cfg", "b13_permit_proto_51.cfg",
            "b14_deny_ip_host_kw_case.cfg",
            "c06_ios_v4_unnumbered_between_seq_control.cfg",
            "i03_policy_line_trailing.rules", "j03_two_from_blocks.conf",
            "j06_filter_level_stmt.conf", "j07_then_policer_discard.conf",
            "p04_addr_defined_after_rule.set", "p07_network_tap_iface.set",
            # PAN-OS `set` on a member list merges (cited at
            # parse_panos._collect_objects): the group holds CORP and OTH.
            "p08_addrgroup_redefine.set"]


@pytest.mark.parametrize("cfg", _R8_1 + _R8_2 + _R8_3 + _R8_4 + _R8_5 + _R8_6
                         + _R8_7 + _R8_9 + _R8_10 + _STRICT)
def test_r8_reviewer_false_passes_never_pass(cfg):
    _never_pass(_r8(cfg))


@pytest.mark.parametrize("cfg", _GENUINE)
def test_r8_genuine_controls_stay_pass(cfg):
    _stays_pass(_r8(cfg))


def test_r8_every_other_reviewer_variant_is_still_not_pass():
    keep = set(_GENUINE)
    for path in sorted(glob.glob(os.path.join(_R8, "*"))):
        name = os.path.basename(path)
        if name in keep:
            continue
        r = _report(path)
        assert r["assertion_verdict"] != "PASS", (name, _codes(r))


# --------------------------------------------------------------------------- #
# R8-1 / R8-10 / R8-12: Junos terms
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["j01_two_then_discard_accept.conf",
                                 "j02_then_block_discard_accept.conf",
                                 "j09_then_block_reject_accept.conf",
                                 "j10_then_count_discard_then_accept.conf",
                                 "j08_reach_then_accept_then_discard.conf"])
def test_r8_1_the_latest_terminating_action_wins(cfg):
    """Juniper: "the latest terminating action will replace the existing
    terminating action". With accept last the leak is proven; with discard
    last (j08, must_reach) the break is proven. FAIL, with a note."""
    r = _report(_r8(cfg))
    assert r["assertion_verdict"] == "FAIL", (cfg, _codes(r))
    assert any("more than one terminating action" in n for n in r["notes"]), r["notes"]


@pytest.mark.parametrize("terms", [
    (f"term d {{ {_JFROM} then {{ discard; accept; }} }}", _JA),
    (f"term d {{ {_JFROM} then {{ accept; discard; }} }}", _JA),
    (f"term d {{ {_JFROM} then {{ discard; next term; }} }}", _JA),
    (f"term d {{ {_JFROM} then {{ accept extra; }} }}", _JA),
    (f"term d {{ {_JFROM} then {{ discard extra; }} }}", _JA),
    (f"term d {{ {_JFROM} then {{ count; discard; }} }}", _JA),
    (f"term d {{ {_JFROM} then discard; }}", f"term d {{ {_JFROM} then discard; }}", _JA),
    (f"term d {{ {_JFROM} then discard; description x; }}", _JA),
    (f"term d {{ {_JFROM} then discard; bogus; }}", _JA),
    (f"term d {{ {_JFROM} then discard; filter G; }}", _JA),
])
def test_r8_1_and_r8_10_junos_term_grammar_never_passes(tmp_path, terms):
    _never_pass(_write(tmp_path, "x.conf", _junos(*terms)), "v4_ip.json", hosted=False)


@pytest.mark.parametrize("terms", [
    (f"term d {{ {_JFROM} then discard; }}", _JA),
    (f"term d {{ {_JFROM} then {{ count c; discard; }} }}", _JA),
    (f"term d {{ {_JFROM} then {{ log; syslog; discard; }} }}", _JA),
    (f"term d {{ {_JFROM} then {{ policer P; discard; }} }}", _JA),
    (f"term d {{ {_JFROM} then reject; }}", _JA),
])
def test_r8_1_junos_cited_term_forms_stay_pass(tmp_path, terms):
    _stays_pass(_write(tmp_path, "x.conf", _junos(*terms)), "v4_ip.json")


def test_r8_12_protect_on_a_term_is_unknown_not_fail():
    """`protect:` only blocks edits (uncited here): the term is read and the
    answer is UNKNOWN, never a FAIL from dropping the term."""
    r = _report(_r8("k04_junos_protect_term_d.conf"))
    assert r["assertion_verdict"] == "UNKNOWN", (r["assertion_verdict"], _codes(r))


# --------------------------------------------------------------------------- #
# R8-2: sequence-number ranges
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    _ios("2147483648 " + _DENY, _LEAK),
    _ios("0 " + _DENY, _LEAK),
    _ios("2147483647 " + _OTHER, _DENY),
    _nx("4294967296 " + _NXDENY, _NXLEAK),
    _nx("0 " + _NXDENY, _NXLEAK),
    _nx("4294967290 " + _NXOTHER, _NXDENY),
    _ios("010 " + _DENY, "020 " + _LEAK),
    _IF6 + "ipv6 access-list F6\n sequence 4294967296 deny ipv6 2001:db8:20::/48 "
    "2001:db8:10::/48\n permit ipv6 2001:db8:20::/48 any\n",
])
def test_r8_2_out_of_range_numbers_never_pass(tmp_path, text):
    pol = "v6_ip.json" if "ipv6" in text else "v4_ip.json"
    _never_pass(_write(tmp_path, "x.cfg", text), pol, hosted=False)


@pytest.mark.parametrize("text", [
    _ios("10 " + _DENY, "2147483647 " + _OTHER),
    _ios("1 " + _DENY, "20 " + _OTHER),
    _nx("10 " + _NXDENY, "4294967295 " + _NXOTHER),
])
def test_r8_2_numbers_in_range_stay_pass(tmp_path, text):
    _stays_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json")


# --------------------------------------------------------------------------- #
# R8-3 / R8-4: iptables
# --------------------------------------------------------------------------- #
_SAVE = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n" \
        "-A FORWARD -s 203.0.113.0/24 -j ACCEPT\n"


@pytest.mark.parametrize("commit", ["commit", "COMMIT ", "Commit", " COMMIT",
                                    "COMMIT\t", "COMMIT\r"])
def test_r8_3_commit_must_be_the_exact_line(tmp_path, commit):
    _never_pass(_write(tmp_path, "x.rules", _SAVE + commit + "\n"), "v4_ip.json",
                hosted=False)


def test_r8_3_exact_commit_stays_pass(tmp_path):
    _stays_pass(_write(tmp_path, "x.rules", _SAVE + "COMMIT\n"), "v4_ip.json")


@pytest.mark.parametrize("line", [
    "iptables -P FORWARD DROP extra", "iptables -P FORWARD DROP INPUT",
    "iptables -P FORWARD DROP -w", "iptables -P MYCHAIN DROP",
])
def test_r8_4_policy_with_extra_arguments_never_passes(tmp_path, line):
    text = ("iptables -P INPUT DROP\niptables -P OUTPUT DROP\n" + line
            + "\niptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT\n")
    _never_pass(_write(tmp_path, "x.sh", text), "v4_ip.json", hosted=False)


@pytest.mark.parametrize("line", ["iptables -N BLOCK extra", "iptables -F FORWARD extra",
                                  "iptables -X BLOCK extra"])
def test_r8_4_chain_commands_with_extra_arguments_never_pass(tmp_path, line):
    text = ("iptables -P INPUT DROP\niptables -P OUTPUT DROP\niptables -P FORWARD DROP\n"
            + line + "\niptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT\n")
    _never_pass(_write(tmp_path, "x.sh", text), "v4_ip.json", hosted=False)


def test_r8_4_exact_policy_stays_pass(tmp_path):
    text = ("iptables -P INPUT DROP\niptables -P OUTPUT DROP\niptables -P FORWARD DROP\n"
            "iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT\n")
    _stays_pass(_write(tmp_path, "x.sh", text), "v4_ip.json")


# --------------------------------------------------------------------------- #
# R8-5: resequence
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    _ios("10 " + _DENY, "20 " + _OTHER) + "hostname r1\nip access-list resequence F 100 10\n",
    _nx("10 " + _NXDENY, "20 " + _NXOTHER) + "hostname n1\nresequence ip access-list F 100 10\n",
    _nx("10 " + _NXDENY, "20 " + _NXOTHER, "resequence 100 10"),
])
def test_r8_5_resequence_naming_the_acl_never_passes(tmp_path, text):
    _never_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json", hosted=False)


# --------------------------------------------------------------------------- #
# R8-6: operand and trailer grammar per dialect
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    _ios("deny ip 192.0.2.0/24 198.51.100.0 0.0.0.255", _LEAK),
    _ios("deny ip 192.0.2.0 0.0.0.255 198.51.100.0/24", _LEAK),
    _ios(_DENY + " log interval 5", _LEAK),
    _ios(_DENY + " log 5", _LEAK),
    _ios(_DENY + " log default", _LEAK),
    _IF.replace("access-group F", "access-group 101")
    + "access-list 101 deny ip 192.0.2.0/24 198.51.100.0 0.0.0.255\n"
    "access-list 101 permit ip 192.0.2.0 0.0.0.255 any\n",
])
def test_r8_6_other_dialect_forms_in_ios_never_pass(tmp_path, text):
    _never_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json", hosted=False)


@pytest.mark.parametrize("text", [
    _ios(_DENY + " log", _OTHER),
    _ios(_DENY + " log-input", _OTHER),
    _ios(_DENY + " log CORP-DENY", _OTHER),
    _nx(_NXDENY, _NXOTHER),
])
def test_r8_6_cited_forms_stay_pass(tmp_path, text):
    _stays_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json")


# --------------------------------------------------------------------------- #
# R8-7: +10 only where cited; numbered remarks
# --------------------------------------------------------------------------- #
_EOS = ("! device: eos1 (vEOS, EOS-4.30.0F)\ninterface Ethernet1\n   no switchport\n"
        "   ip address 192.0.2.1/24\n   ip access-group F in\ninterface Ethernet2\n"
        "   no switchport\n   ip address 198.51.100.1/24\n   ip access-group F in\n"
        "ip access-list F\n")


@pytest.mark.parametrize("text", [
    _EOS + "   10 " + _NXDENY + "\n   " + _NXOTHER + "\n",
    _EOS + "   " + _NXDENY + "\n   20 " + _NXOTHER + "\n",
    _IF6 + "ipv6 access-list F6\n sequence 10 deny ipv6 2001:db8:20::/48 2001:db8:10::/48\n"
    " permit ipv6 2001:db8:30::/48 any\n",
    _ios("10 " + _OTHER, "20 remark x", "20 " + _DENY, "30 " + _LEAK),
    _nx("10 " + _NXOTHER, "20 remark x", "20 " + _NXDENY, "30 " + _NXLEAK),
])
def test_r8_7_uncited_numbering_never_passes(tmp_path, text):
    pol = "v6_ip.json" if "ipv6" in text else "v4_ip.json"
    _never_pass(_write(tmp_path, "x.cfg", text), pol, hosted=False)


@pytest.mark.parametrize("text", [
    _EOS + "   10 " + _NXDENY + "\n   20 " + _NXOTHER + "\n",
    _EOS + "   " + _NXDENY + "\n   " + _NXOTHER + "\n",
    _ios("10 " + _DENY, _OTHER),
    _nx("10 " + _NXDENY, _NXOTHER),
    _ios("10 remark x", "20 " + _DENY, "30 " + _OTHER),
])
def test_r8_7_cited_or_unmixed_numbering_stays_pass(tmp_path, text):
    _stays_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json")


# --------------------------------------------------------------------------- #
# R8-9: PAN-OS object grammar
# --------------------------------------------------------------------------- #
_PAN_RULES = ("set rulebase security rules d from any to any source CORP destination "
              "198.51.100.0/24 application any service any action deny\n"
              "set rulebase security rules a from any to any source any destination any "
              "application any service any action allow\n")


@pytest.mark.parametrize("obj", [
    "set address CORP ip-netmask 192.0.2.0/24 extra",
    "set address CORP ip-range 192.0.2.0-192.0.2.255 extra",
    "set address CORP ip-netmask 192.0.2.0/24 192.0.2.0/25",
])
def test_r8_9_address_object_with_extra_token_never_passes(tmp_path, obj):
    _never_pass(_write(tmp_path, "x.set", obj + "\n" + _PAN_RULES), "v4_ip.json",
                hosted=False)


def test_r8_9_exact_address_object_stays_pass(tmp_path):
    _stays_pass(_write(tmp_path, "x.set", "set address CORP ip-netmask 192.0.2.0/24\n"
                       + _PAN_RULES), "v4_ip.json")


# --------------------------------------------------------------------------- #
# Case rules: IOS keywords are case-insensitive (cited); NX-OS and EOS are not
# cited, so a non-lower-case keyword there is noted.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    _nx("10 DENY ip 192.0.2.0/24 198.51.100.0/24", "20 " + _NXOTHER),
    _nx("10 deny IP 192.0.2.0/24 198.51.100.0/24", "20 " + _NXOTHER),
    _EOS + "   10 deny ip 192.0.2.0/24 198.51.100.0/24 LOG\n   20 " + _NXOTHER + "\n",
])
def test_case_uncited_vendor_keyword_case_never_passes(tmp_path, text):
    _never_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json", hosted=False)


def test_case_ios_keyword_case_stays_pass(tmp_path):
    _stays_pass(_write(tmp_path, "x.cfg", _ios("DENY IP 192.0.2.0 0.0.0.255 "
                                               "198.51.100.0 0.0.0.255", _OTHER)),
                "v4_ip.json")


# --------------------------------------------------------------------------- #
# R8-8: the new mutation families exist and carry realistic tokens
# --------------------------------------------------------------------------- #
def test_r8_8_new_mutation_families_exist():
    from test_fail_closed_mutation_all import _corpus, _vendor, mutants
    fams, tokens = set(), set()
    for path, _ in _corpus():
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        for fam, tag, _m, _k, _r in mutants(text, _vendor(text)):
            fams.add(fam)
            if fam == "cisco-acl-trailing-token":
                tokens.add(tag.split(":", 1)[-1])
    for fam in ("junos-two-terminating", "junos-duplicate-term", "junos-term-unknown-stmt",
                "cisco-acl-seq-range", "cisco-acl-resequence", "cisco-acl-cidr-operand",
                "cisco-acl-log-args", "cisco-acl-keyword-case",
                "ipt-policy-extra-arg", "ipt-commit-spelling",
                "panos-object-extra-token"):
        assert fam in fams, fam
    assert tokens - {"xyzzy"} >= {"interval", "accept", "count", "fragments", "established"}, \
        tokens
