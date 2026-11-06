"""Fail-closed, third review of #42: false PASSes the second reviewer found.

Every config in tests/fixtures/fail_closed/rev42r2 is the reviewer's
synthetic counterexample (RFC 5737 addresses). Before this fix each one
printed PASS (or connectivity OK) and evidence VERIFIED while the device
forwards the flow (or, for must_reach, drops it). Fixed by class, not by
config, and each class has its own reason code:

  no silent drop (H6, H7, H8, M2)  every PAN-OS / iptables line is consumed
                                   by a modelled handler or gets a parse note;
                                   nftables text is `nftables-present`
  H1, H2   `acl-binding-negated`   (`no ip access-group`, Junos `inactive:`)
  H3       `iptables-chain-policy-unset` with no FORWARD policy at all
  H4       `reach-not-every-context`
  H5       `object-scope-ambiguous`
  M1, H8   `nat-present`

Every test asserts UNKNOWN with the reason code on every surface: CLI text,
--json, --evidence, gate (high, critical, low), MCP rulehawk_audit and the
hosted Pages entry point.
"""

from __future__ import annotations

import json
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

from test_fail_closed import (  # noqa: E402
    _BOUND_IOS, _PASS_KINDS, _assert_unknown_everywhere, _assertion_findings,
    _load_policy, _pol, _reason_codes, _run_cli)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REV = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "rev42r2")


def _rev(name: str) -> str:
    return os.path.join(_REV, name)


def _pol_for(cfg: str) -> str:
    return "v4_reach_ip.json" if "reach" in os.path.basename(cfg) else "v4_ip.json"


def _hosted(cfg_path: str, pol: str) -> dict:
    from tests.test_hosted_parity import _WORKER, _analyze_py, _read, _run_hosted
    with open(cfg_path, encoding="utf-8") as fh:
        cfg = fh.read()
    with open(_pol(pol), encoding="utf-8") as fh:
        p = fh.read()
    return _run_hosted(_analyze_py(_read(_WORKER)), cfg, p)


def _unknown_on_every_surface(path: str, reason: str, pol: str = "") -> None:
    pol = pol or _pol_for(path)
    _assert_unknown_everywhere(path, pol, reason)
    for level in ("critical", "low"):
        gate = g.run_gate([path], _load_policy(pol), fail_on=level)
        assert gate.exit_code() != 0, (path, level)
        assert gate.verdict in ("UNKNOWN", "FAIL"), (path, level, gate.verdict)
    from rulehawk import mcp_server as m
    res = m.audit(path, _pol(pol))
    assert res["verdict"] != "PASS", res["verdict"]
    assert not res["segmentation_passed"], res["segmentation_passed"]
    codes = {r["code"] for u in res["segmentation_unknown"] for r in u["reasons"]}
    assert reason in codes, sorted(codes)
    env = _hosted(path, pol)
    findings = env["report_json"]["findings"]
    assert not any(f["kind"] in _PASS_KINDS for f in findings), findings
    hosted_codes = set()
    for f in findings:
        if f.get("verdict") == "UNKNOWN":
            hosted_codes |= _reason_codes(f)
    assert reason in hosted_codes, sorted(hosted_codes)


def _write(tmp_path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _assertion(path: str, pol: str = "v4_ip.json") -> dict:
    _, out = _run_cli([path, "--json", "--policy", _pol(pol)])
    return json.loads(out)


# --------------------------------------------------------------------------- #
# The no-silent-drop rule: PAN-OS `delete` / `edit` / NAT, nft next to
# iptables (H6, M2, H8, H7)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["u11_delete_rule.set", "u11b_delete_rule_exit0.set",
                                 "u12_edit_relative.set"])
def test_panos_lines_the_parser_does_not_model_are_parse_notes(cfg):
    _unknown_on_every_surface(_rev(cfg), "parse-note")


@pytest.mark.parametrize("line", [
    "delete address CORP",
    "rename rulebase security rules d to e",
    "edit rulebase security",
    "up",
    "top",
    "set rules x from any to any source any destination any application any "
    "service any action allow",
    "set rulebase pbf rules p from any source any destination any action forward",
    "set rulebase decryption rules x action no-decrypt",
    "load config partial from x.xml",
])
def test_panos_any_unmodelled_line_is_a_parse_note(tmp_path, line):
    base = open(_rev("u11b_delete_rule_exit0.set")).read().replace(
        "delete rulebase security rules d\n", "")
    clean = _write(tmp_path, "clean.set", base)
    assert _assertion(clean)["assertion_verdict"] == "PASS"
    _unknown_on_every_surface(_write(tmp_path, "x.set", base + line + "\n"),
                              "parse-note")


@pytest.mark.parametrize("cfg", ["t15_nft_netdev_fwd.rules",
                                 "t15b_nft_forward_accept_only.rules",
                                 "i13_nft_mixed.rules"])
def test_nftables_text_next_to_iptables_is_unknown(cfg):
    _unknown_on_every_surface(_rev(cfg), "nftables-present")


@pytest.mark.parametrize("extra", [
    "nft add rule inet filter forward ip saddr 192.0.2.0/24 accept\n",
    "nft -f /etc/nftables.conf\n",
    "table ip filter {\n chain forward { type filter hook forward priority 0; }\n}\n",
])
def test_nft_commands_in_an_iptables_script_are_unknown(tmp_path, extra):
    base = ("iptables -P FORWARD DROP\n"
            "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n")
    clean = _write(tmp_path, "clean.sh", base)
    assert _assertion(clean)["assertion_verdict"] == "PASS"
    _unknown_on_every_surface(_write(tmp_path, "x.sh", base + extra),
                              "nftables-present")


@pytest.mark.parametrize("line", [
    "echo 1 > /proc/sys/net/ipv4/ip_forward",
    "iptables -X GUARD",
    "iptables -E GUARD OTHER",
    "ip route add 198.51.100.0/24 via 203.0.113.9",
    "ebtables -A FORWARD -j ACCEPT",
])
def test_iptables_any_unmodelled_line_is_a_parse_note(tmp_path, line):
    base = ("iptables -P FORWARD DROP\n"
            "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n")
    assert _assertion(_write(tmp_path, "clean.sh", base))["assertion_verdict"] == "PASS"
    _unknown_on_every_surface(_write(tmp_path, "x.sh", base + line + "\n"),
                              "parse-note")


# The guard: no frontend has a skip path without a note. A junk line
# appended to a clean config must produce a note citing its line number,
# whatever its shape. The lines are seeded random words that are not any
# vendor's modelled syntax, plus the shapes that used to be skipped.
_JUNK_WORDS = ["frob", "nicate", "x1", "zone9", "{", "}", ";", "42", "-q",
               "--zap", "foo=bar", "*", "[", "]", "198.51.100.0/24",
               "192.0.2.0/24", "any", "deny", "allow", "rules", "nat",
               "security", "table", "chain", "hook", "delete", "edit"]


def _junk_lines(seed: int, n: int):
    rng = random.Random(seed)
    for _ in range(n):
        k = rng.randint(1, 6)
        yield " ".join(rng.choice(_JUNK_WORDS) for _ in range(k))


_CLEAN = {
    "panos": ("set rulebase security rules d from any to any source "
              "192.0.2.0/24 destination 198.51.100.0/24 application any "
              "service any action deny\n"),
    "iptables-cmd": ("iptables -P FORWARD DROP\n"
                     "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 "
                     "-j DROP\n"),
    "iptables-save": ("*filter\n:FORWARD DROP [0:0]\n"
                      "-A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n"
                      "COMMIT\n"),
}


def _parse(kind: str, text: str):
    if kind == "panos":
        from rulehawk.parse_panos import parse_panos
        return parse_panos(text)
    from rulehawk.parse_iptables import parse_iptables
    return parse_iptables(text)


@pytest.mark.parametrize("kind", sorted(_CLEAN))
def test_no_frontend_drops_a_line_without_a_note(kind):
    base = _CLEAN[kind]
    _, base_notes = _parse(kind, base)
    assert base_notes == [], base_notes
    n = base.count("\n") + 1
    misses = []
    for line in list(_junk_lines(20261106, 300)) + [
            "delete x", "edit x", "rename a to b", "move x top", "up", "top",
            "exit", "}", "{", ";", "table netdev t {", "chain c {",
            "COMMITX", ":", "-X", "-E A B", "set", "set x"]:
        _, notes = _parse(kind, base + line + "\n")
        new = [x for x in notes if x not in base_notes]
        if not any(f"line {n}" in x for x in new):
            misses.append((line, new))
    assert not misses, misses[:10]


# --------------------------------------------------------------------------- #
# H1, H2: a negated or inactive binding is unknown
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["r01_no_access_group.cfg",
                                 "r02_reopen_iface_no_ag.cfg",
                                 "s01_junos_inactive_binding.conf",
                                 "s02_junos_deactivate_binding.set",
                                 "s07_junos_inactive_iface.conf"])
def test_negated_or_inactive_binding_is_unknown(cfg):
    _unknown_on_every_surface(_rev(cfg), "acl-binding-negated")


_NO_BIND_FORMS = [
    " no ip access-group EDGE out",
    " no ip access-group EDGE in",
    " no ipv6 traffic-filter EDGE6 in",
    " no ip port access-group EDGE in",
]


@pytest.mark.parametrize("form", _NO_BIND_FORMS)
def test_cisco_no_binding_forms_are_unknown(tmp_path, form):
    assert _assertion(_write(tmp_path, "c.cfg", _BOUND_IOS))["assertion_verdict"] == "PASS"
    text = _BOUND_IOS.replace("\nip access-list extended EDGE\n",
                              f"\ninterface GigabitEthernet0/1\n{form}\n!\n"
                              "ip access-list extended EDGE\n", 1)
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text), "acl-binding-negated")


@pytest.mark.parametrize("vendor_line", ["", "version 9.3(10)\n", "! device: eos\n"])
def test_no_access_class_and_nxos_eos_forms_are_unknown(tmp_path, vendor_line):
    text = vendor_line + _BOUND_IOS + "line vty 0 4\n access-class EDGE in\n no access-class EDGE in\n"
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text), "acl-binding-negated")


@pytest.mark.parametrize("old,new", [
    ("ge-0/0/1 { unit 0 {", "inactive: ge-0/0/1 { unit 0 {"),
    ("ge-0/0/1 { unit 0 {", "ge-0/0/1 { inactive: unit 0 {"),
    ("ge-0/0/1 { unit 0 { family inet { inactive: filter",
     "ge-0/0/1 { unit 0 { inactive: family inet { filter"),
    ("interfaces {", "inactive: interfaces {"),
])
def test_junos_inactive_anywhere_on_the_binding_is_unknown(tmp_path, old, new):
    base = open(_rev("s01_junos_inactive_binding.conf")).read()
    # the s01 config with both bindings active is a real PASS
    active = base.replace("inactive: filter", "filter")
    assert _assertion(_write(tmp_path, "a.conf", active))["assertion_verdict"] == "PASS"
    text = active.replace(old.replace("inactive: filter", "filter"), new, 1)
    assert text != active
    _unknown_on_every_surface(_write(tmp_path, "x.conf", text), "acl-binding-negated")


# --------------------------------------------------------------------------- #
# H3: no FORWARD policy at all is the kernel default ACCEPT
# --------------------------------------------------------------------------- #
def test_user_chain_with_no_forward_policy_is_unknown():
    _unknown_on_every_surface(_rev("t01_userchain_unref_nopolicy.sh"),
                              "iptables-chain-policy-unset")


@pytest.mark.parametrize("text", [
    "*filter\n:GUARD - [0:0]\n-A GUARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\nCOMMIT\n",
    "iptables -P INPUT DROP\niptables -N GUARD\n"
    "iptables -A GUARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n",
])
def test_forward_policy_unset_kin(tmp_path, text):
    _unknown_on_every_surface(_write(tmp_path, "x.rules", text),
                              "iptables-chain-policy-unset")


# --------------------------------------------------------------------------- #
# H4: connectivity needs every audited context to permit
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["r25_reach_egress_deny_allfiltered.cfg",
                                 "r25b_reach_egress_deny_exit0.cfg"])
def test_reach_with_another_context_denying_is_unknown(cfg):
    path = _rev(cfg)
    r = _assertion(path, "v4_reach_ip.json")
    kinds = [f["kind"] for f in r["findings"]]
    assert "connectivity-ok" not in kinds, kinds
    _unknown_on_every_surface(path, "reach-not-every-context")


def test_reach_with_every_context_permitting_is_still_ok():
    """r13: both bound ACLs permit everything, so connectivity is proven."""
    r = _assertion(_rev("r13_reach_two_ctx_any.cfg"), "v4_reach_ip.json")
    ok = [f for f in _assertion_findings(r) if f["kind"] == "connectivity-ok"]
    assert ok and ok[0]["verdict"] == "PASS", r["findings"]
    assert "every audited ruleset permits the whole flow" in ok[0]["message"]


# --------------------------------------------------------------------------- #
# H5: PAN-OS objects are scoped to their vsys / device-group
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["u02_panorama_obj_override.set",
                                 "u02b_dg_obj_collision_exit0.set",
                                 "u03_vsys_obj_collision.set",
                                 "u03b_vsys_obj_collision_exit0.set"])
def test_panos_object_name_in_two_scopes_is_unknown(cfg):
    _unknown_on_every_surface(_rev(cfg), "object-scope-ambiguous")


def test_panos_address_group_name_in_two_scopes_is_unknown(tmp_path):
    text = ("set vsys vsys1 address-group CORP static [ 203.0.113.0/24 ]\n"
            "set vsys vsys2 address-group CORP static [ 192.0.2.0/24 ]\n"
            "set vsys vsys1 rulebase security rules d from any to any source CORP "
            "destination 198.51.100.0/24 application any service any action deny\n"
            "set vsys vsys1 rulebase security rules a from any to any source "
            "192.0.2.0/24 destination any application any service any action allow\n")
    _unknown_on_every_surface(_write(tmp_path, "x.set", text), "object-scope-ambiguous")


# --------------------------------------------------------------------------- #
# M1, H8: NAT in the config
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["r03_static_nat.cfg", "r03b_static_nat_exit0.cfg",
                                 "u04_nat_dnat.set"])
def test_nat_present_is_unknown(cfg):
    _unknown_on_every_surface(_rev(cfg), "nat-present")


@pytest.mark.parametrize("extra", [
    "ip nat inside source static 198.51.100.5 203.0.113.5\n",
    "ip nat source static 198.51.100.5 203.0.113.5\n",
    "interface GigabitEthernet0/1\n ip nat outside\n!\n",
])
def test_cisco_nat_forms_are_unknown(tmp_path, extra):
    text = _BOUND_IOS + extra
    _unknown_on_every_surface(_write(tmp_path, "x.cfg", text), "nat-present")
