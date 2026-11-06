"""Fail-closed, seventh review of #42 (review-rh42-r6.md): ACL mode by entry
grammar, not by a list of breaks (R6-1); a global `exit` (R6-2); Junos brace
balance and a `#` inside a word (R6-3); the mutation labels (R6-4); PAN-OS
quoted names with whitespace (R6-5).

The configs in tests/fixtures/fail_closed/variants/r6 are the reviewer's
synthetic variants (RFC 5737 addresses; `u_no_ntp.cfg` had 1.1.1.1, now
203.0.113.1). Every false PASS must be non-PASS on the CLI, the gate at
every level, MCP rulehawk_audit and the hosted page.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_fail_closed import (  # noqa: E402
    _PASS_KINDS, _assertion_findings, _load_policy, _pol, _reason_codes, _run_cli)
from test_fail_closed_review3 import _hosted  # noqa: E402

from rulehawk import gate as g  # noqa: E402
from rulehawk import mcp_server as m  # noqa: E402
from rulehawk.failclosed import cisco_lex  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_R6 = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "r6")


def _r6(name: str) -> str:
    for d in ("n", "u", "b"):
        p = os.path.join(_R6, d, name)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(name)


def _report(path: str, pol: str = "v4_ip.json") -> dict:
    _, out = _run_cli([path, "--json", "--policy", _pol(pol)])
    return json.loads(out)


def _codes(report: dict) -> set:
    out = set()
    for f in _assertion_findings(report):
        out |= _reason_codes(f)
    return out


def _never_pass(path: str, pol: str = "v4_ip.json", hosted: bool = True) -> str:
    r = _report(path, pol)
    v = r["assertion_verdict"]
    assert v in ("UNKNOWN", "FAIL"), (os.path.basename(path), v, _codes(r))
    for level in ("high", "critical", "low"):
        gate = g.run_gate([path], _load_policy(pol), fail_on=level)
        assert gate.verdict in ("UNKNOWN", "FAIL"), (path, level, gate.verdict)
        assert gate.exit_code() != 0, (path, level)
    res = m.audit(path, _pol(pol))
    assert res["verdict"] != "PASS", (path, res["verdict"])
    assert not res["segmentation_passed"], res["segmentation_passed"]
    if hosted:
        env = _hosted(path, pol)
        assert env["report_json"]["assertion_verdict"] != "PASS", path
        assert not any(f["kind"] in _PASS_KINDS
                       for f in env["report_json"]["findings"]), path
    return v


def _stays_pass(path: str, pol: str = "v4_ip.json") -> None:
    r = _report(path, pol)
    assert r["assertion_verdict"] == "PASS", (os.path.basename(path), _codes(r))


def _write(tmp_path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return str(p)


# --------------------------------------------------------------------------- #
# R6-1: inside an ACL, only ACL-entry grammar stays in the ACL
# --------------------------------------------------------------------------- #
_Y = ["y_aaa.cfg", "y_clock.cfg", "y_domain.cfg", "y_en.cfg", "y_enable.cfg",
      "y_ex.cfg", "y_exi.cfg", "y_hostn.cfg", "y_logging.cfg", "y_no_lookup.cfg",
      "y_ntp_tab.cfg", "y_ntp.cfg", "y_service.cfg", "y_ssh.cfg", "y_stp.cfg",
      "y_username.cfg"]
_U = ["u_EX.cfg", "u_ex_sp.cfg", "u_no_ntp.cfg", "u_tab_ex.cfg"]


@pytest.mark.parametrize("cfg", _Y + _U)
def test_r6_1_reviewer_variants_never_pass(cfg):
    _never_pass(_r6(cfg))


@pytest.mark.parametrize("cfg", _Y + _U)
def test_r6_1_the_lexer_flags_the_line_after_the_header(cfg):
    with open(_r6(cfg), encoding="utf-8") as fh:
        text = fh.read()
    lex = cisco_lex(text)
    hdr = next(ln.no for ln in lex.lines if ln.norm.lower().startswith("ip access-list"))
    assert any(no == hdr + 1 for no, _, _ in lex.ambiguous), (cfg, lex.ambiguous)


@pytest.mark.parametrize("cfg", ["y_ex_unind.cfg", "y_ntp_unind.cfg", "u_tab_exit.cfg",
                                 "u_nbsp_exit.cfg", "u_emsp_hostname.cfg",
                                 "y_interface_abbr.cfg", "y_og_ex.cfg", "y_og_ntp.cfg"])
def test_r6_1_forms_already_caught_stay_caught(cfg):
    _never_pass(_r6(cfg), hosted=False)


_HEAD = ("interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n"
         " ip access-group F in\ninterface GigabitEthernet0/1\n"
         " ip address 192.0.2.1 255.255.255.0\n ip access-group F in\n"
         "ip access-list extended F\n")
_BODY = (" deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255\n"
         " permit ip 203.0.113.0 0.0.0.255 any\n")

# None of these is a `_TOP_LEVEL` command or an interface-allowlist line: they
# are written independently of the lexer's lists (global commands from the
# IOS configuration guides, abbreviations, other indentation).
_UNLISTED = [
    "ntp server 203.0.113.1", "logging host 203.0.113.9", "username u secret x",
    "aaa new-model", "service timestamps debug uptime", "ip ssh version 2",
    "no ip domain-lookup", "clock timezone UTC 0", "enable secret x",
    "spanning-tree mode rapid-pvst", "ip domain name example.net",
    "ip name-server 203.0.113.53", "ip http server", "no service pad",
    "cdp run", "lldp run", "vtp mode transparent", "key chain K",
    "ip dhcp pool P", "ip sla 1", "track 1 interface GigabitEthernet0/0 line-protocol",
    "crypto key generate rsa modulus 2048", "archive", "errdisable recovery interval 30",
    "no ntp server 203.0.113.1", "ip scp server enable", "login block-for 60 attempts 3 within 60",
    "ex", "exi", "EX", "Ex", "en", "hostn R1", "host R1", "ntp ser 203.0.113.1",
    "logg host 203.0.113.9", "xyzzy",
]


@pytest.mark.parametrize("indent", [" ", "  ", "\t"])
@pytest.mark.parametrize("brk", _UNLISTED)
def test_r6_1_any_non_entry_line_inside_an_acl(tmp_path, brk, indent):
    p = _write(tmp_path, "x.cfg", _HEAD + indent + brk + "\n" + _BODY)
    _never_pass(p, hosted=False)
    assert cisco_lex(open(p, encoding="utf-8").read()).ambiguous, brk


@pytest.mark.parametrize("brk", _UNLISTED[:6] + ["ex", "hostn R1"])
def test_r6_1_the_same_after_the_first_entry(tmp_path, brk):
    body = _BODY.split("\n")
    p = _write(tmp_path, "x.cfg", _HEAD + body[0] + "\n " + brk + "\n" + body[1] + "\n")
    _never_pass(p, hosted=False)


@pytest.mark.parametrize("lead", [" ", " ", "　"])
@pytest.mark.parametrize("brk", ["ntp server 203.0.113.1", "ex", "exit"])
def test_r6_1_unicode_indentation(tmp_path, lead, brk):
    _never_pass(_write(tmp_path, "x.cfg", _HEAD + lead + brk + "\n" + _BODY), hosted=False)


@pytest.mark.parametrize("word", ["ex", "exi", "EX", "Exi", "en", "EN"])
def test_r6_1_an_abbreviated_exit_or_end_is_read_as_that_word(word):
    lex = cisco_lex(_HEAD + " " + word + "\n" + _BODY)
    after = [ln for ln in lex.lines if ln.norm.startswith(("deny", "permit"))]
    assert after and all(ln.mode != "acl" or ln.post_end for ln in after), \
        [(ln.no, ln.mode, ln.post_end) for ln in after]


@pytest.mark.parametrize("body", [
    _BODY,
    " remark keep CORP out of PCI\n" + _BODY,
    " 10 deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255\n"
    " 20 permit ip 203.0.113.0 0.0.0.255 any\n",
    _BODY + " remark end of list\n",
    " 10 remark x\n" + _BODY,
])
def test_r6_1_real_acl_bodies_stay_pass(tmp_path, body):
    p = _write(tmp_path, "x.cfg", _HEAD + body)
    _stays_pass(p)
    assert not cisco_lex(_HEAD + body).ambiguous


def test_r6_1_nxos_statistics_per_entry_is_an_acl_line():
    """NX-OS `statistics per-entry` (IP access-list configuration mode) only
    counts matches; it is an ACL-mode line, not a break."""
    text = ("feature interface-vlan\nip access-list F\n  statistics per-entry\n"
            "  10 deny ip 192.0.2.0/24 198.51.100.0/24\n  20 permit ip 203.0.113.0/24 any\n")
    assert not cisco_lex(text).ambiguous


@pytest.mark.parametrize("cfg", ["t11_bang.cfg", "t10_control_same_stanza.cfg",
                                 "u08_no_ip_address_control.cfg"])
def test_r6_1_round5_controls_stay_pass(cfg):
    base = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "r5")
    for d in ("n", "n2", ""):
        p = os.path.join(base, d, cfg)
        if os.path.exists(p):
            _stays_pass(p)
            return
    raise FileNotFoundError(cfg)


# --------------------------------------------------------------------------- #
# R6-2: an `exit` straight after a one-line global command
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["x01_hostname_exit_then_acl.cfg",
                                 "x01c_iproute_exit_then_acl.cfg"])
def test_r6_2_reviewer_variants_never_pass(cfg):
    _never_pass(_r6(cfg))


@pytest.mark.parametrize("one", ["hostname R1", "ip route 0.0.0.0 0.0.0.0 203.0.113.254",
                                 "ntp server 203.0.113.1", "service timestamps",
                                 "ip routing", "snmp-server community x RO"])
def test_r6_2_exit_after_a_one_line_command(tmp_path, one):
    head, acl = _HEAD.split("ip access-list")
    p = _write(tmp_path, "x.cfg", head + one + "\nexit\nip access-list" + acl + _BODY)
    _never_pass(p, hosted=False)


@pytest.mark.parametrize("body", [" ntp server 203.0.113.1", " hostname R1", " xyzzy"])
def test_r6_2_exit_after_a_sub_mode_body_that_is_not_checked(tmp_path, body):
    """A body line of a mode RuleHawk does not model may be a global command
    the device ran at the global level; the `exit` after it may then leave
    configuration mode."""
    head, acl = _HEAD.split("ip access-list")
    p = _write(tmp_path, "x.cfg", head + "router ospf 1\n" + body + "\nexit\nip access-list"
               + acl + _BODY)
    _never_pass(p, hosted=False)


@pytest.mark.parametrize("sub", ["router ospf 1\n", "line vty 0 4\n",
                                 "interface Loopback0\n"])
def test_r6_2_exit_from_an_empty_sub_mode_stays_pass(tmp_path, sub):
    head, acl = _HEAD.split("ip access-list")
    _stays_pass(_write(tmp_path, "x.cfg", head + sub + "exit\nip access-list" + acl + _BODY))


def test_r6_2_exit_from_an_acl_stays_pass(tmp_path):
    _stays_pass(_write(tmp_path, "x.cfg", _HEAD + _BODY + "exit\nhostname R1\n"))


# --------------------------------------------------------------------------- #
# R6-3: Junos brace balance and a `#` inside a word
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["j10_unquoted_hash_in_word.conf", "jb4_missing_brace.conf",
                                 "jb5_extra_brace.conf"])
def test_r6_3_reviewer_variants_never_pass(cfg):
    _never_pass(_r6(cfg))
    assert "parse-note" in _codes(_report(_r6(cfg))) or \
        _report(_r6(cfg))["assertion_verdict"] == "FAIL"


@pytest.mark.parametrize("cfg", ["j11_midline_hash_after_stmt.conf",
                                 "j12_hash_comment_line_control.conf",
                                 "j13_block_comment_multiline.conf"])
def test_r6_3_genuine_junos_controls_stay_pass(cfg):
    _stays_pass(_r6(cfg))


_J = ("interfaces {\n"
      "    ge-0/0/0 { unit 0 { family inet { filter { input F; } address 192.0.2.1/24; } } }\n"
      "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n"
      "}\nfirewall { family inet { filter F {\n"
      "    term d { from { source-address { 192.0.2.0/24; } destination-address "
      "{ 198.51.100.0/24; } } then discard; }\n"
      "    term a { from { source-address { 203.0.113.0/24; } } then accept; }\n"
      "} } }\n")


def test_r6_3_the_junos_base_passes(tmp_path):
    _stays_pass(_write(tmp_path, "j.conf", _J))


@pytest.mark.parametrize("old,new", [
    ("term d {", "term d# {"),
    ("then discard;", "then discard;x#y"),
    ("term a {", "term a#b {"),
    ("203.0.113.0/24;", "203.0.113.0/24#x;"),
])
def test_r6_3_a_hash_glued_to_a_word(tmp_path, old, new):
    _never_pass(_write(tmp_path, "j.conf", _J.replace(old, new, 1)), hosted=False)


@pytest.mark.parametrize("edit", ["drop-last", "add-last", "drop-first-close"])
def test_r6_3_unbalanced_braces(tmp_path, edit):
    t = _J.rstrip("\n")
    if edit == "drop-last":
        t = t[:-1]
    elif edit == "add-last":
        t = t + " }"
    else:
        k = t.index("}")
        t = t[:k] + t[k + 1:]
    _never_pass(_write(tmp_path, "j.conf", t + "\n"), hosted=False)


@pytest.mark.parametrize("old,new", [
    ("then discard; }", "then discard; } # note"),
    ("then discard; }", "then discard; } ## SECRET-DATA"),
    ("firewall {", "# header\nfirewall {"),
    ("firewall {", "system { host-name r1;# x\n}\nfirewall {"),
    ("then accept; }", "then accept; }# x"),
])
def test_r6_3_comments_after_a_statement_stay_pass(tmp_path, old, new):
    # (`then accept;# x` was here in the red commit: on that line the comment
    # also hides the term's closing `}`, so UNKNOWN is the right answer; the
    # `;#` case now sits on a line that ends with the statement.)
    _stays_pass(_write(tmp_path, "j.conf", _J.replace(old, new, 1)))


# --------------------------------------------------------------------------- #
# R6-4: two mutation labels
# --------------------------------------------------------------------------- #
def test_r6_4_no_annotation_inside_a_block_comment():
    """Round 8 (R7-8) restored these mutants: inside a block the annotation's
    `*/` ends the block early, so the label is `never`, not `preserve`."""
    from test_fail_closed_mutation_all import _junos
    lines = ["firewall {", "/* a", "b", "*/", "}"]
    kinds = {t: k for f, t, _, k, _ in _junos(lines) if f == "junos-annotation"}
    assert kinds.get("3") == "never" and kinds.get("4") == "never", kinds
    assert kinds.get("1") == "preserve" and kinds.get("2") == "preserve", kinds


def test_r6_4_trailing_comment_on_a_continued_line_is_never():
    from test_fail_closed_mutation_all import _iptables
    lines = ["iptables -P FORWARD DROP \\", "  ", "iptables -A FORWARD -j ACCEPT"]
    kinds = {t: k for f, t, _, k, _ in _iptables(lines) if f == "ipt-trailing-comment"}
    assert kinds.get("1") == "never", kinds


def test_r6_4_the_acl_breaks_are_independent_of_the_lexer():
    """The mode breaks the self-check injects must not all come from the
    lexer's own list: at least the unlisted ones must be present."""
    from test_fail_closed_mutation_all import _INDEPENDENT_BREAKS
    from rulehawk.failclosed import _TOP_LEVEL, _IF_ALLOW_RX
    assert len(_INDEPENDENT_BREAKS) >= 10
    for b in _INDEPENDENT_BREAKS:
        s = b.strip(" \t  ")
        assert not _TOP_LEVEL.match(s) and not _IF_ALLOW_RX.match(s), b


# --------------------------------------------------------------------------- #
# R6-5: PAN-OS quoted names with leading or trailing whitespace
# --------------------------------------------------------------------------- #
def test_r6_5_reviewer_variant_never_passes():
    _never_pass(_r6("p16_rule_named_d_twice_quoted_unquoted.set"))
    assert "parse-note" in _codes(_report(_r6("p16_rule_named_d_twice_quoted_unquoted.set")))


def test_r6_5_quoted_same_name_stays_pass():
    _stays_pass(_r6("p15_name_with_quote_dup.set"))


_P = ("set rulebase security rules d from any to any source 192.0.2.0/24 "
      "destination 198.51.100.0/24 application any service any action deny\n"
      "set rulebase security rules a from any to any source 203.0.113.0/24 "
      "destination 198.51.100.0/24 application any service any action allow\n")


@pytest.mark.parametrize("name", ['" d"', '"d "', "' d'", '"d\t"', '"  a  "'])
def test_r6_5_names_with_whitespace(tmp_path, name):
    text = _P + f"set rulebase security rules {name} action allow\n"
    p = _write(tmp_path, "p.set", text)
    _never_pass(p, hosted=False)
    assert "parse-note" in _codes(_report(p))


def test_r6_5_the_panos_base_passes(tmp_path):
    _stays_pass(_write(tmp_path, "p.set", _P))
