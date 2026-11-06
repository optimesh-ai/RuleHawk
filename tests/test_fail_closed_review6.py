"""Fail-closed, sixth review of #42 (review-rh42-r5.md): ACL mode (N1), line
splitting and characters outside Cisco (N2), Junos quoting (N3), the docs
(N4) and allowlist hygiene.

The configs in tests/fixtures/fail_closed/variants/r5 are the reviewer's
synthetic variants (RFC 5737 addresses). Each `_unknown_on_every_surface`
asserts UNKNOWN with its reason code on the CLI text, --json, --evidence,
gate at high/critical/low, MCP rulehawk_audit and the hosted page.
"""

from __future__ import annotations

import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_fail_closed import (  # noqa: E402
    _BOUND_IOS, _assertion_findings, _load_policy, _pol, _reason_codes, _run_cli)
from test_fail_closed_review3 import _unknown_on_every_surface, _write  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_R5 = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "r5")
_R1 = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "r1")


def _r5(name: str) -> str:
    return os.path.join(_R5, name)


def _report(path: str, pol: str = "v4_ip.json") -> dict:
    _, out = _run_cli([path, "--json", "--policy", _pol(pol)])
    return json.loads(out)


def _codes(report: dict) -> set:
    out = set()
    for f in _assertion_findings(report):
        out |= _reason_codes(f)
    return out


def _bytes_unknown(tmp_path, name: str, data: bytes, reason: str = "parse-note"):
    """UNKNOWN on the byte-reading surfaces (CLI, gate, MCP). The hosted page
    reads a browser textarea, which normalises line ends, so it is not used
    for inputs whose point is a CR."""
    from rulehawk import gate as g
    from rulehawk import mcp_server as m
    p = tmp_path / name
    p.write_bytes(data)
    r = _report(str(p))
    assert r["assertion_verdict"] == "UNKNOWN", (name, _codes(r))
    assert reason in _codes(r), (name, _codes(r))
    assert g.run_gate([str(p)], _load_policy("v4_ip.json")).exit_code() == 3
    assert m.audit(str(p), _pol("v4_ip.json"))["verdict"] == "UNKNOWN"


# --------------------------------------------------------------------------- #
# N1: ACL entries come only from ACL mode, as the device reads it
# --------------------------------------------------------------------------- #
_T11 = sorted(f for f in os.listdir(_R5) if f.startswith("t11_") and f != "t11_bang.cfg")


def test_the_t11_set_is_complete():
    assert len(_T11) == 22, _T11


@pytest.mark.parametrize("cfg", _T11 + ["t01_end_then_acl.cfg"])
def test_n1_entries_after_a_mode_change_are_not_acl_entries(cfg):
    _unknown_on_every_surface(_r5(cfg), "parse-note")


@pytest.mark.parametrize("cfg", ["t11_bang.cfg", "t10_control_same_stanza.cfg",
                                 "u08_no_ip_address_control.cfg"])
def test_n1_controls_stay_pass(cfg):
    r = _report(_r5(cfg))
    assert r["assertion_verdict"] == "PASS", (cfg, _codes(r))


_BREAKS = ["exit", " exit", "end", " end", "hostname R1", " hostname R1",
           "router ospf 1", " router ospf 1", "line vty 0 4", " line vty 0 4",
           "interface Loopback0", " interface Loopback0", "control-plane",
           " control-plane", "ip routing", " ip routing", "version 15.2",
           " boot system flash:x.bin", "snmp-server community x RO",
           " ip route 0.0.0.0 0.0.0.0 203.0.113.254", " vrf definition RED",
           " policy-map P", " class-map match-any C", " object-group network G",
           " management ssh", " banner motd ^C x ^C", "banner motd ^C x ^C"]


@pytest.mark.parametrize("brk", _BREAKS)
def test_n1_any_mode_change_inside_an_acl(tmp_path, brk):
    """On the device the command leaves ACL mode, indented or not; the
    entries after it are rejected, so EDGE is shorter than the text shows."""
    text = _BOUND_IOS.replace("ip access-list extended EDGE\n",
                              f"ip access-list extended EDGE\n{brk}\n", 1)
    assert text != _BOUND_IOS
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text), "parse-note")


@pytest.mark.parametrize("brk", ["exit", " hostname R1", " router ospf 1", "end"])
def test_n1_object_group_members_after_a_mode_change(tmp_path, brk):
    """The same for object-group mode: a member after the mode change is not
    a member, so a deny naming the group covers less than the text shows."""
    text = ("interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
            " ip access-group EDGE in\n!\n"
            "interface GigabitEthernet0/1\n ip address 198.51.100.1 255.255.255.0\n"
            " ip access-group EDGE in\n!\n"
            "object-group network CORPG\n network-object 203.0.113.0 255.255.255.0\n"
            f"{brk}\n network-object 192.0.2.0 255.255.255.0\n!\n"
            "ip access-list extended EDGE\n"
            " deny ip object-group CORPG 198.51.100.0 0.0.0.255\n"
            " permit ip any any\n")
    r = _report(_write(tmp_path, "x.cfg", text))
    assert r["assertion_verdict"] != "PASS", (brk, _codes(r))


def test_n1_anything_after_end_is_a_parse_note(tmp_path):
    text = _BOUND_IOS + "hostname R2\n"
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text), "parse-note")


def test_n1_end_with_only_comments_after_it_is_fine(tmp_path):
    r = _report(_write(tmp_path, "ok.cfg", _BOUND_IOS + "!\n\n!\n"))
    assert r["assertion_verdict"] == "PASS", _codes(r)


@pytest.mark.parametrize("brk", [" hostname R1", " router ospf 1", " end"])
def test_n1_indented_top_level_in_interface_mode(tmp_path, brk):
    """An indented top-level command leaves interface mode too: a binding
    after it is not on the interface."""
    text = _BOUND_IOS.replace(
        "interface GigabitEthernet0/1\n ip address 198.51.100.1 255.255.255.0\n"
        " ip access-group EDGE in\n",
        f"interface GigabitEthernet0/1\n ip address 198.51.100.1 255.255.255.0\n"
        f"{brk}\n ip access-group EDGE in\n", 1)
    assert text != _BOUND_IOS
    r = _report(_write(tmp_path, "x.cfg", text))
    assert r["assertion_verdict"] == "UNKNOWN", (brk, _codes(r))


def test_one_cisco_lexer_covers_parse_py():
    """parse.py takes stanza membership from cisco_lex, never from
    indentation or from "the last header seen"."""
    import inspect
    from rulehawk import parse
    src = inspect.getsource(parse)
    rest = src.replace(inspect.getsource(parse.strip_banners), "")
    assert "raw[:1]" not in rest
    assert "in_other" not in rest
    assert "cisco_lex(" in inspect.getsource(parse._parse_acls)
    assert "cisco_lex(" in inspect.getsource(parse._collect_defs) or \
        "lex" in inspect.signature(parse._collect_defs).parameters


# --------------------------------------------------------------------------- #
# N2: every frontend splits at "\n" only and checks characters
# --------------------------------------------------------------------------- #
_I10 = sorted(f for f in os.listdir(_R5) if f.startswith("i10_"))


def test_the_i10_set_is_complete():
    assert len(_I10) == 6, _I10


@pytest.mark.parametrize("cfg", _I10 + ["i12_save_u2028_hides_policy.rules",
                                        "p01_u2028_unquoted_description.set"])
def test_n2_a_separator_hides_a_line_outside_cisco(cfg):
    _unknown_on_every_surface(_r5(cfg), "parse-note")


def test_n2_i11_the_hidden_drop_is_not_read():
    """i11: `-P FORWARD ACCEPT`, then a `-j DROP` hidden in a comment. Bash
    never runs the DROP, so FORWARD accepts CORP -> PCI: a proven violation,
    FAIL on every surface (the red version of this test asked for UNKNOWN)."""
    from rulehawk import gate as g
    from rulehawk import mcp_server as m
    from test_fail_closed_review3 import _hosted
    path = _r5("i11_u2028_hides_append_drop.sh")
    assert _report(path)["assertion_verdict"] == "FAIL"
    assert g.run_gate([path], _load_policy("v4_ip.json")).verdict == "FAIL"
    assert m.audit(path, _pol("v4_ip.json"))["verdict"] == "FAIL"
    assert _hosted(path, "v4_ip.json")["report_json"]["assertion_verdict"] == "FAIL"


@pytest.mark.parametrize("cfg", ["i13_control_policy_visible.sh"])
def test_n2_control_stays_pass(cfg):
    r = _report(_r5(cfg))
    assert r["assertion_verdict"] == "PASS", (cfg, _codes(r))


_CHARS = [" ", " ", "\x85", "\x0c", "\x0b", "\x1c", "\x1d", "\x1e",
          "\x00", "\x1b", " ", " ", "﻿"]

_IPT = "iptables -P FORWARD DROP\niptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT\n"
_IPT_SAVE = "*filter\n:FORWARD DROP [0:0]\n-A FORWARD -s 203.0.113.0/24 -j ACCEPT\nCOMMIT\n"
_PANOS = ("set rulebase security rules d from any to any source 192.0.2.0/24 "
          "destination 198.51.100.0/24 application any service any action deny\n")
_JUNOS = ("interfaces {\n"
          "    ge-0/0/0 { unit 0 { family inet { filter { input F; } address 192.0.2.1/24; } } }\n"
          "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n"
          "}\nfirewall {\n    family inet {\n        filter F {\n            term d {\n"
          "                from { source-address { 192.0.2.0/24; } destination-address "
          "{ 198.51.100.0/24; } }\n                then discard;\n            }\n"
          "            term a { from { source-address { 203.0.113.0/24; } } then accept; }\n"
          "        }\n    }\n}\n")
_JUNOS_SET = ("set interfaces ge-0/0/0 unit 0 family inet filter input F\n"
              "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\n"
              "set firewall family inet filter F term d from source-address 192.0.2.0/24\n"
              "set firewall family inet filter F term d then discard\n")
_AWS = ('{"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "pci", '
        '"Description": "pci tier", "IpPermissions": [{"IpProtocol": "tcp", '
        '"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "203.0.113.0/24", '
        '"Description": "web"}]}], "IpPermissionsEgress": []}]}\n')


def test_the_bases_are_pass():
    """The two transit bases that can PASS do (Junos and PAN-OS are checked by
    their own fixtures; AWS SG is always UNKNOWN on bindings)."""
    import tempfile
    for name, text in (("b.sh", _IPT), ("b.rules", _IPT_SAVE), ("b.conf", _JUNOS),
                       ("b.set", _PANOS)):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, name)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
            assert _report(p)["assertion_verdict"] == "PASS", name


_EXT = {"ipt": "sh", "ipt-save": "rules", "panos": "set", "junos": "conf",
        "junos-set": "set", "aws": "json"}


def _with_char(kind: str, ch: str) -> str:
    if kind == "ipt":
        return _IPT.replace("\niptables -A", f"\n# note{ch}x\niptables -A", 1)
    if kind == "ipt-save":
        return _IPT_SAVE.replace("\n-A FORWARD", f"\n# note{ch}x\n-A FORWARD", 1)
    if kind == "panos":
        return ("set address X ip-netmask 203.0.113.9/32\n"
                f"set address X description a{ch}b\n" + _PANOS)
    if kind == "junos":
        return _JUNOS.replace("firewall {\n", f"firewall {{\n    /* a{ch}b */\n", 1)
    if kind == "junos-set":
        return f"# a{ch}b\n" + _JUNOS_SET
    if kind == "aws":
        return _AWS.replace('"pci tier"', f'"pci{ch}tier"', 1)
    raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["ipt", "ipt-save", "panos", "junos", "junos-set", "aws"])
@pytest.mark.parametrize("ch", _CHARS)
def test_n2_any_control_or_separator_character_is_a_parse_note(tmp_path, kind, ch):
    data = _with_char(kind, ch).encode("utf-8")
    p = tmp_path / ("x." + _EXT[kind])
    p.write_bytes(data)
    r = _report(str(p))
    assert r["assertion_verdict"] != "PASS", (kind, hex(ord(ch)))
    assert "parse-note" in _codes(r), (kind, hex(ord(ch)), _codes(r))


@pytest.mark.parametrize("kind,text", [("ipt", _IPT), ("ipt-save", _IPT_SAVE),
                                       ("junos", _JUNOS), ("panos", _PANOS)])
def test_n2_a_carriage_return_outside_cisco_is_a_parse_note(tmp_path, kind, text):
    """bash and iptables-restore keep a CR as part of the last word (`DROP\\r`
    is not a target), so a CRLF script does not set what it shows. PAN-OS and
    Junos line ends are not modelled either: UNKNOWN."""
    _bytes_unknown(tmp_path, f"x.{kind}", text.replace("\n", "\r\n").encode())


def test_n2_crlf_aws_json_is_fine(tmp_path):
    """RFC 8259 section 2: CR is insignificant whitespace in JSON."""
    p = tmp_path / "ok.json"
    p.write_bytes(_AWS.replace("\n", "\r\n").encode())
    r = _report(str(p))
    assert "parse-note" not in _codes(r), _codes(r)


def test_n2_no_splitlines_in_the_package():
    """Python's str.splitlines() also ends a line at \\v, \\f, FS/GS/RS, NEL,
    U+2028 and U+2029, which no supported device does."""
    pkg = os.path.join(_ROOT, "rulehawk")
    hits = []
    for name in sorted(os.listdir(pkg)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(pkg, name), encoding="utf-8") as fh:
            for i, ln in enumerate(fh, 1):
                if "splitlines(" in ln:
                    hits.append(f"{name}:{i}: {ln.strip()}")
    assert not hits, hits


# --------------------------------------------------------------------------- #
# N3: Junos comment markers inside quoted strings
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["j03_comment_markers_in_strings.conf",
                                 "j03b_hash_in_string.conf"])
def test_n3_comment_markers_in_strings(cfg):
    _unknown_on_every_surface(_r5(cfg), "parse-note")


def test_n3_control_is_fail():
    assert _report(_r5("j03c_control_no_markers.conf"))["assertion_verdict"] == "FAIL"


_J_LEAK = _JUNOS.replace(
    "            term d {",
    "            term n1 { DESC from { source-address { 203.0.113.9/32; } } then accept; }\n"
    "            term leak { from { source-address { 192.0.2.0/24; } destination-address "
    "{ 198.51.100.0/24; } } then accept; }\n"
    "            term n2 { DESC2 from { source-address { 203.0.113.10/32; } } then accept; }\n"
    "            term d {", 1)


@pytest.mark.parametrize("d1,d2", [
    ('description "/*";', 'description "*/";'),
    ('description "x # y";', ""),
    ('description "{";', 'description "}";'),
    ('description "a;b";', ""),
    ('description "[";', 'description "]";'),
])
def test_n3_structure_characters_in_strings(tmp_path, d1, d2):
    """The leak term sits between the two descriptions. Whatever the device
    makes of the strings, RuleHawk must not drop the term."""
    text = _J_LEAK.replace("DESC2", d2).replace("DESC", d1)
    r = _report(_write(tmp_path, "x.conf", text))
    assert r["assertion_verdict"] != "PASS", (d1, _codes(r))
    assert "parse-note" in _codes(r) or r["assertion_verdict"] == "FAIL", _codes(r)


def test_n3_leak_control_is_fail(tmp_path):
    text = _J_LEAK.replace("DESC2", "").replace("DESC", "")
    assert _report(_write(tmp_path, "c.conf", text))["assertion_verdict"] == "FAIL"


@pytest.mark.parametrize("c1,c2", [("# a /*", "# b */"), ("# a /* b", "# */"),
                                   ("x; # /*", "# */")])
def test_n3_block_markers_inside_hash_comments(tmp_path, c1, c2):
    """`# ... /*` is a line comment: the `/*` in it opens nothing."""
    text = _J_LEAK.replace("DESC2", "").replace("DESC", "").replace(
        "            term leak", f"            {c1}\n            term leak", 1).replace(
        "            term n2", f"            {c2}\n            term n2", 1)
    r = _report(_write(tmp_path, "x.conf", text))
    assert r["assertion_verdict"] != "PASS", (c1, _codes(r))


def test_n3_plain_annotations_still_pass(tmp_path):
    text = _JUNOS.replace("firewall {\n", "/* edge filter */\nfirewall {\n", 1)
    text = "## Last commit: 2026-11-06\n" + text
    r = _report(_write(tmp_path, "ok.conf", text))
    assert r["assertion_verdict"] == "PASS", _codes(r)


# --------------------------------------------------------------------------- #
# N4: the docs say what the code does
# --------------------------------------------------------------------------- #
def _read(rel: str) -> str:
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def test_n4_docs_wording():
    from rulehawk.failclosed import KNOWN_LIMITS
    limits = " ".join(KNOWN_LIMITS)
    for rel in ("README.md", "CHANGELOG.md"):
        doc = _read(rel)
        assert "splits lines the same way" not in doc, rel
        assert "indented or not" in doc, rel
        assert "every frontend" in doc.lower(), rel
    assert "indented or not" in limits
    assert "after `end`" in limits
    assert "control or separator character" in limits and "every vendor" in limits


# --------------------------------------------------------------------------- #
# Hygiene: ASCII digits in the allowlist
# --------------------------------------------------------------------------- #
def test_allowlist_uses_ascii_digits():
    from rulehawk import failclosed as fc
    assert fc._IF_ALLOW
    assert not [p for p in fc._IF_ALLOW if "\\d" in p]
    assert fc._IF_ALLOW_RX.flags & re.ASCII


@pytest.mark.parametrize("line", [" speed １００", " load-interval ٣٠"])
def test_allowlist_rejects_non_ascii_digits(tmp_path, line):
    text = _BOUND_IOS.replace(" ip access-group EDGE in\n!\ninterface GigabitEthernet0/1",
                              f" ip access-group EDGE in\n{line}\n!\ninterface GigabitEthernet0/1", 1)
    r = _report(_write(tmp_path, "x.cfg", text))
    assert r["assertion_verdict"] == "UNKNOWN", _codes(r)
