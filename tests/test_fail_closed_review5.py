"""Fail-closed, fifth review of #42 (review-rh42-r4.md): iptables policy
names (S1), Cisco stanza boundaries (S2), line ends (S3), interface names
(S4), VLAN filters (S5), the docs (S6) and the two allowlist additions.

The configs in tests/fixtures/fail_closed/variants/r4 are the reviewer's
synthetic variants (RFC 5737 / RFC 3849 addresses). Each test asserts
UNKNOWN with its reason code on every surface (CLI text, --json,
--evidence, gate at high/critical/low, MCP rulehawk_audit, hosted page).
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_fail_closed import (  # noqa: E402
    _BOUND_IOS, _assertion_findings, _pol, _reason_codes, _run_cli)
from test_fail_closed_review3 import _unknown_on_every_surface, _write  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_R4 = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "r4")


def _r4(name: str) -> str:
    return os.path.join(_R4, name)


def _report(path: str, pol: str = "v4_ip.json") -> dict:
    _, out = _run_cli([path, "--json", "--policy", _pol(pol)])
    return json.loads(out)


def _codes(report: dict) -> set:
    out = set()
    for f in _assertion_findings(report):
        out |= _reason_codes(f)
    return out


# --------------------------------------------------------------------------- #
# S1: a chain policy is ACCEPT or DROP, exact case (iptables(8): "The policy
# target must be either ACCEPT or DROP"; libiptc compares with strcmp)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["h01_policy_reject.sh",
                                 "h02_policy_lowercase_drop.sh",
                                 "h03_save_policy_reject.rules",
                                 "h07_save_lowercase_policy.rules"])
def test_s1_an_invalid_forward_policy_is_not_a_policy(cfg):
    _unknown_on_every_surface(_r4(cfg), "iptables-chain-policy-unset")


@pytest.mark.parametrize("pol", ["REJECT", "drop", "Drop", "accept", "QUEUE", "RETURN"])
def test_s1_invalid_policy_names_get_a_note(tmp_path, pol):
    text = (f"iptables -P FORWARD {pol}\n"
            "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n")
    _unknown_on_every_surface(_write(tmp_path, "x.sh", text), "parse-note")


def test_s1_exact_case_drop_still_counts(tmp_path):
    text = ("iptables -P FORWARD DROP\n"
            "iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT\n")
    r = _report(_write(tmp_path, "ok.sh", text))
    assert r["assertion_verdict"] == "PASS", r["findings"]


# --------------------------------------------------------------------------- #
# S2: an interface stanza ends at a recognised top-level command, not at the
# first unindented line
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", [
    "f01_unindented_replace_binding_undefined.cfg",
    "f02_unindented_no_abbrev.cfg",
    "f03_unindented_abbrev_binding_undefined.cfg",
    "f04_nbsp_line_then_no_abbrev.cfg",
    "f04b_invalid_toplevel_then_no_abbrev.cfg",
    "f19b_nxos_unindented_abbrev_binding.cfg",
    "f23b_eos_unindented_replace_undefined.cfg",
    "f29_crlf_unindented_no_abbrev.cfg",
])
def test_s2_unindented_line_in_interface_mode_is_unknown(cfg):
    _unknown_on_every_surface(_r4(cfg), "stanza-boundary-ambiguous")


@pytest.mark.parametrize("line", ["no ip access-gr EDGE in", "xyzzy",
                                  "ip forward-protocol nd", "\u00a0description x",
                                  "\u2003no ip access-gr EDGE in"])
def test_s2_any_unrecognised_unindented_line_after_an_interface(tmp_path, line):
    text = _BOUND_IOS.replace("!\ninterface GigabitEthernet0/1",
                              f"!\n{line}\ninterface GigabitEthernet0/1", 1)
    assert text != _BOUND_IOS
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text),
                              "stanza-boundary-ambiguous")


def test_s2_an_indented_line_after_a_bang_still_belongs_to_the_interface(tmp_path):
    """`!` is a comment: the device stays in interface mode."""
    text = _BOUND_IOS.replace("!\ninterface GigabitEthernet0/1",
                              "!\n ip verify unicast source reachable-via rx\n"
                              "interface GigabitEthernet0/1", 1)
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text),
                              "interface-feature-unmodeled")


def test_s2_recognised_top_level_commands_end_the_stanza(tmp_path):
    text = _BOUND_IOS.replace(
        "!\nend\n", "router ospf 1\n network 192.0.2.0 0.0.0.255 area 0\n"
        "ip route 0.0.0.0 0.0.0.0 198.51.100.254\nline vty 0 4\n"
        " transport input ssh\n!\nend\n")
    assert text != _BOUND_IOS
    r = _report(_write(tmp_path, "ok.cfg", text))
    assert r["assertion_verdict"] == "PASS", _codes(r)


# --------------------------------------------------------------------------- #
# S3: a line ends at \n only; other control or separator characters block
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["f05_u2028_in_description.cfg",
                                 "f05b_nel_in_description.cfg",
                                 "f05c_fs_in_description.cfg",
                                 "f05d_ff_in_description.cfg"])
def test_s3_separator_in_description_is_unknown(cfg):
    _unknown_on_every_surface(_r4(cfg), "parse-note")


@pytest.mark.parametrize("ch", ["\v", "\x0c", "\x1c", "\x1d", "\x1e", "\x85",
                                "\u2028", "\u2029", "\x00", "\x1b"])
def test_s3_any_control_character_blocks(tmp_path, ch):
    text = _BOUND_IOS.replace(" ip access-group EDGE in\n!\ninterface GigabitEthernet0/1",
                              f" ip access-group EDGE in\n description a{ch}b\n!\n"
                              "interface GigabitEthernet0/1", 1)
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text), "parse-note")


def test_s3_a_lone_cr_inside_a_line_blocks(tmp_path):
    """The CLI, gate and MCP read bytes and see one line with a CR inside
    (parse-note); a browser textarea turns the CR into a line break, so the
    hosted page sees an unindented line in interface mode. UNKNOWN on both."""
    from test_fail_closed_review3 import _hosted
    from test_fail_closed import _load_policy
    from rulehawk import gate as g
    from rulehawk import mcp_server as m
    p = tmp_path / "x.cfg"
    p.write_bytes(_BOUND_IOS.replace(" ip access-group EDGE in\n!\ninterface GigabitEthernet0/1",
                                     " ip access-group EDGE in\n description a\rb\n!\n"
                                     "interface GigabitEthernet0/1", 1).encode())
    r = _report(str(p))
    assert r["assertion_verdict"] == "UNKNOWN" and "parse-note" in _codes(r)
    assert g.run_gate([str(p)], _load_policy("v4_ip.json")).exit_code() == 3
    assert m.audit(str(p), _pol("v4_ip.json"))["verdict"] == "UNKNOWN"
    env = _hosted(str(p), "v4_ip.json")
    assert env["report_json"]["assertion_verdict"] == "UNKNOWN"


def test_s3_crlf_alone_is_fine(tmp_path):
    p = tmp_path / "ok.cfg"
    p.write_bytes(_BOUND_IOS.replace("\n", "\r\n").encode())
    r = _report(str(p))
    assert r["assertion_verdict"] == "PASS", _codes(r)


# --------------------------------------------------------------------------- #
# S4: interface names are normalised; `GigabitEthernet 0/2` is its own port
# --------------------------------------------------------------------------- #
def test_s4_spaced_names_do_not_merge():
    _unknown_on_every_surface(_r4("f08b_space_names_merge_unfiltered.cfg"),
                              "unfiltered-path")


def test_s4_spaced_and_joined_name_are_one_interface(tmp_path):
    """IOS reads `GigabitEthernet 0/1` and `gigabitethernet0/1` as one port,
    so a later stanza for either spelling merges with the first: still two
    filtered ports, a PASS. A spaced name for a third port is unfiltered."""
    same = _BOUND_IOS.replace("!\nend\n",
                              "!\ninterface gigabitethernet 0/1\n description x\n!\nend\n")
    assert same != _BOUND_IOS
    r = _report(_write(tmp_path, "same.cfg", same))
    assert r["assertion_verdict"] == "PASS", _codes(r)
    third = same.replace("gigabitethernet 0/1", "GigabitEthernet 0/2")
    _unknown_on_every_surface(_write(tmp_path, "third.cfg", third), "unfiltered-path")


# --------------------------------------------------------------------------- #
# S5: VLAN ACLs
# --------------------------------------------------------------------------- #
def test_s5_vlan_filter_is_unknown():
    _unknown_on_every_surface(_r4("g11_reach_vacl_drop.cfg"), "vlan-filter",
                              pol="v4_reach_ip.json")


@pytest.mark.parametrize("extra", ["vlan access-map M 10\n action drop\n",
                                   "vlan filter M vlan-list 10\n"])
def test_s5_vlan_filter_lines(tmp_path, extra):
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", extra + _BOUND_IOS),
                              "vlan-filter")


# --------------------------------------------------------------------------- #
# Step 3 (coordinator): `no ip address` and `media-type` are allowlisted
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("line", [" no ip address",
                                  " no ip address 203.0.113.9 255.255.255.0 secondary",
                                  " no ip address 203.0.113.9 255.255.255.0",
                                  " media-type rj45", " media-type auto-select"])
def test_step3_additions_keep_the_pass(tmp_path, line):
    text = _BOUND_IOS.replace(" ip access-group EDGE in\n!\ninterface GigabitEthernet0/1",
                              f" ip access-group EDGE in\n{line}\n!\ninterface GigabitEthernet0/1", 1)
    assert text != _BOUND_IOS
    r = _report(_write(tmp_path, "ok.cfg", text))
    assert r["assertion_verdict"] == "PASS", (line, _codes(r))


@pytest.mark.parametrize("line", [" media-type rj45 extra", " no ip address dhcp"])
def test_step3_additions_are_exact(tmp_path, line):
    text = _BOUND_IOS.replace(" ip access-group EDGE in\n!\ninterface GigabitEthernet0/1",
                              f" ip access-group EDGE in\n{line}\n!\ninterface GigabitEthernet0/1", 1)
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text),
                              "interface-feature-unmodeled")


# --------------------------------------------------------------------------- #
# S6: the known limits say what the code does
# --------------------------------------------------------------------------- #
def test_s6_known_limits_wording():
    from rulehawk.failclosed import KNOWN_LIMITS
    text = " ".join(KNOWN_LIMITS)
    assert "ACCEPT or DROP" in text
    assert "any other interface line is UNKNOWN" not in text
    assert "recognised top-level command" in text


# --------------------------------------------------------------------------- #
# One lexer: no Cisco check re-derives lines or stanzas on its own
# --------------------------------------------------------------------------- #
def test_one_cisco_lexer():
    import inspect
    from rulehawk import failclosed as fc
    src = inspect.getsource(fc)
    rest = src.replace(inspect.getsource(fc.cisco_lex), "").replace(
        inspect.getsource(fc.split_lines), "")
    assert "splitlines(" not in rest
    assert 'split("\\n")' not in rest
    assert "^interface" not in rest and "^\\s+shutdown" not in rest
