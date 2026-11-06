"""Fail-closed verdicts: RuleHawk never prints PASS or VERIFIED on an answer
it cannot support.

One test per counterexample from the 2026-11-06 soundness audit. Every config
in tests/fixtures/fail_closed/cfg is synthetic (RFC 5737 / RFC 3849
addresses) and, before this fix, printed `segmentation-ok PASS` and an
evidence attestation of VERIFIED. Each must now come back UNKNOWN with a
machine-readable reason code, on every output surface: the CLI text and
`--json`, the `--evidence` attestation, `rulehawk gate`, and the MCP audit
tool. The controls in cfg/ok keep their verdicts, except where a fail-closed
rule moves them (see the control tests below).

Vedu (2026-11-06): "RuleHawk never returns PASS/VERIFIED when: the search is
empty; any parse note exists on an object on the evaluated path; the ACL's
binding or role is unknown or is not a packet filter (vty, SNMP, route-map);
a vendor default it doesn't model applies (PAN-OS default-security-rules,
iptables chain policy); or an IOS numbered-ACL wildcard is ambiguous. Those
return UNKNOWN with the reason."
"""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import cli  # noqa: E402
from rulehawk.gate import run_gate, to_console, to_json as gate_json  # noqa: E402
from rulehawk.gate import to_markdown  # noqa: E402

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                    "fail_closed")
_CFG = os.path.join(_FIX, "cfg")
_POL = os.path.join(_FIX, "pol")

_PASS_KINDS = ("segmentation-ok", "connectivity-ok")
_ASSERTION_PREFIXES = ("segmentation-", "connectivity-")


def _cfg(name: str) -> str:
    return os.path.join(_CFG, name)


def _pol(name: str) -> str:
    return os.path.join(_POL, name)


def _load_policy(name: str) -> dict:
    with open(_pol(name), encoding="utf-8") as fh:
        return json.load(fh)


def _run_cli(args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.main(list(args))
    return rc, buf.getvalue()


def _assertion_findings(report: dict):
    return [f for f in report["findings"]
            if f["kind"].startswith(_ASSERTION_PREFIXES)
            and f["kind"] != "segmentation-error"]


def _reason_codes(finding: dict):
    return {r["code"] for r in (finding.get("reasons") or [])}


def _assert_unknown_everywhere(cfg: str, pol: str, reason: str):
    """The full contract for one counterexample: no surface says PASS or
    VERIFIED, the assertion's verdict is UNKNOWN, and `reason` is among its
    machine-readable reason codes."""
    path, ppath = _cfg(cfg), _pol(pol)

    # 1. CLI --json
    rc, out = _run_cli([path, "--json", "--policy", ppath])
    report = json.loads(out)
    kinds = [f["kind"] for f in report["findings"]]
    assert not any(k in _PASS_KINDS for k in kinds), (cfg, kinds)
    seg = _assertion_findings(report)
    assert seg, (cfg, kinds)
    for f in seg:
        assert f.get("verdict") in ("UNKNOWN", "FAIL"), (cfg, f)
    unknown = [f for f in seg if f.get("verdict") == "UNKNOWN"]
    assert unknown, (cfg, seg)
    codes = set().union(*(_reason_codes(f) for f in unknown))
    assert reason in codes, (cfg, sorted(codes))
    for f in unknown:
        for r in f["reasons"]:
            assert r["code"] and r["message"], (cfg, r)
    # the UNKNOWN exit code is never the PASS exit code
    assert rc != 0, (cfg, rc)

    # 2. CLI text
    rc_t, text = _run_cli([path, "--policy", ppath])
    assert rc_t == rc
    assert "PASS:" not in text, (cfg, text)
    assert "UNKNOWN" in text, (cfg, text)
    assert reason in text, (cfg, text)

    # 3. --evidence: never VERIFIED
    _, ev = _run_cli([path, "--evidence", "--policy", ppath])
    art = json.loads(ev)
    statuses = [a["status"] for a in art["attestations"]]
    assert statuses, cfg
    assert "VERIFIED" not in statuses, (cfg, statuses)
    assert art["result"]["attestations_verified"] == 0, (cfg, art["result"])
    ev_codes = set()
    for a in art["attestations"]:
        ev_codes |= {r["code"] for r in a.get("reasons", [])}
        for ent in a.get("indeterminate_on", []):
            ev_codes |= {r["code"] for r in ent.get("reasons", [])}
    assert reason in ev_codes or any(
        a["status"] == "FAILED" for a in art["attestations"]), (cfg, art["attestations"])

    # 4. rulehawk gate
    gate = run_gate([path], _load_policy(pol), fail_on="high")
    assert gate.exit_code() != 0, cfg
    assert not gate.passed, cfg
    console = to_console(gate)
    assert "VERDICT: PASS" not in console, (cfg, console)
    gj = json.loads(gate_json(gate))
    assert gj["verdict"] in ("UNKNOWN", "FAIL"), (cfg, gj["verdict"])
    assert gj["passed"] is False
    md = to_markdown(gate)
    assert "**PASS**" not in md, (cfg, md)
    assert "Segmentation proven" not in md, (cfg, md)
    return report, rc


# --------------------------------------------------------------------------- #
# (a) empty search
# --------------------------------------------------------------------------- #
def test_01_iptables_input_only_is_unknown_not_pass():
    """No transit filter on the path: INPUT is a host hook, so the FORWARD
    search is empty and an empty search proves nothing."""
    _assert_unknown_everywhere("01_ipt_input_only.sh", "v4_host22.json",
                               "no-transit-filter")
    _assert_unknown_everywhere("01_ipt_input_only.sh", "v4_host22.json",
                               "iptables-host-chain-only")


def test_18_nftables_zero_rules_is_unknown_not_pass():
    """nftables has no frontend: zero rules parsed. The findings list used to
    still carry `segmentation-ok PASS`."""
    report, rc = _assert_unknown_everywhere("18_nft.conf", "v4_ip.json",
                                            "no-rules-parsed")
    assert rc == 2          # zero rules keeps the parse-failure exit code
    _assert_unknown_everywhere("18_nft.conf", "v4_ip.json",
                               "nftables-unsupported")


# --------------------------------------------------------------------------- #
# (b) parse notes
# --------------------------------------------------------------------------- #
def test_02_iptables_no_chain_policy_is_unknown_not_pass():
    """No `-P FORWARD`: the kernel default is ACCEPT, and the parser's own
    note says the default is not modeled."""
    _assert_unknown_everywhere("02_ipt_no_policy.sh", "v4_tcp445.json",
                               "iptables-chain-policy-unset")
    _assert_unknown_everywhere("02_ipt_no_policy.sh", "v4_tcp445.json",
                               "parse-note")


def test_05_iptables_delete_is_unknown_not_pass():
    _assert_unknown_everywhere("05_ipt_delete.sh", "v4_ip.json",
                               "iptables-delete")
    _assert_unknown_everywhere("05_ipt_delete.sh", "v4_ip.json", "parse-note")


def test_09_junos_srx_policies_are_unknown_not_pass():
    """SRX zone policies are not modeled, and the PASS rested on a lo0 filter
    that never sees transit traffic."""
    _assert_unknown_everywhere("09_junos_srx.conf", "v4_tcp445.json",
                               "junos-srx-policies")
    _assert_unknown_everywhere("09_junos_srx.conf", "v4_tcp445.json",
                               "parse-note")
    _assert_unknown_everywhere("09_junos_srx.conf", "v4_tcp445.json",
                               "acl-not-packet-filter")


def test_15_ios_dynamic_entry_is_unknown_not_pass():
    """An IOS lock-and-key `dynamic` entry was dropped with only a note."""
    _assert_unknown_everywhere("15_ios_dynamic.cfg", "v4_ip.json",
                               "ios-dynamic-entry")
    _assert_unknown_everywhere("15_ios_dynamic.cfg", "v4_ip.json",
                               "parse-note")


# --------------------------------------------------------------------------- #
# (c) binding and role
# --------------------------------------------------------------------------- #
def test_10_ios_vty_access_class_is_unknown_not_pass():
    """The only ACL is a `line vty` access-class: not a transit packet filter.
    The routed interfaces have no filter, so IOS forwards CORP to PCI."""
    _assert_unknown_everywhere("10_ios_vty_acl.cfg", "v4_tcp445.json",
                               "acl-not-packet-filter")
    report, rc = _assert_unknown_everywhere(
        "10_ios_vty_acl.cfg", "v4_tcp445.json", "no-transit-filter")
    assert rc == 3          # no critical/high finding: the UNKNOWN exit code


def test_11_asa_security_levels_are_unknown_not_pass():
    _assert_unknown_everywhere("11_asa_seclevel.cfg", "v4_ip.json",
                               "asa-security-levels")


def test_08_junos_logical_systems_are_unknown_not_pass():
    """Two logical systems' filters named EDGE were merged into one context."""
    _assert_unknown_everywhere("08_junos_ls.conf", "v4_ip.json",
                               "junos-logical-systems")


# --------------------------------------------------------------------------- #
# (d) vendor defaults RuleHawk does not model
# --------------------------------------------------------------------------- #
def test_03_iptables_proto_zero_is_unknown_not_pass():
    _assert_unknown_everywhere("03_ipt_proto0.sh", "v4_tcp445.json",
                               "iptables-proto-zero")


def test_04_ip6tables_family_is_unknown_not_pass():
    _assert_unknown_everywhere("04_ip6t_save.rules", "v6_tcp445.json",
                               "ip6tables-family")


def test_06_panos_default_security_rules_are_unknown_not_pass():
    _assert_unknown_everywhere("06_panos_default.set", "v4_tcp445.json",
                               "panos-default-security-rules")
    _assert_unknown_everywhere("06_panos_default.set", "v4_tcp445.json",
                               "panos-implicit-default")


def test_06_panos_default_rules_gate_is_not_pass():
    gate = run_gate([_cfg("06_panos_default.set")],
                    _load_policy("v4_tcp445.json"))
    assert gate.exit_code() == 3
    assert "VERDICT: UNKNOWN" in to_console(gate)


def test_07_panos_source_user_and_schedule_are_unknown_not_pass():
    _assert_unknown_everywhere("07_panos_user.set", "v4_tcp445.json",
                               "panos-unmodeled-rule-field")


def test_12_ios_ipv6_icmp_is_unknown_not_pass():
    """`icmp` inside an `ipv6 access-list` means ICMPv6."""
    _assert_unknown_everywhere("12_ios_v6_icmp.cfg", "v6_icmpv6.json",
                               "icmpv6-canonicalisation")


def test_13_asa_icmp6_is_unknown_not_pass():
    _assert_unknown_everywhere("13_asa_icmp6.cfg", "v6_icmpv6.json",
                               "icmpv6-canonicalisation")


def test_12b_ios_ipv6_implicit_nd_is_unknown_not_pass():
    _assert_unknown_everywhere("12b_ios_v6_nd.cfg", "v6_icmpv6.json",
                               "ipv6-implicit-nd")


def test_19_nxos_ipv6_implicit_nd_is_unknown_not_pass():
    _assert_unknown_everywhere("19_nxos_v6_nd.cfg", "v6_icmpv6.json",
                               "ipv6-implicit-nd")


def test_16_ios_established_is_unknown_not_pass():
    """`established` is a stateless ACK/RST bit test on IOS, not state."""
    _assert_unknown_everywhere("16_ios_established.cfg", "v4_tcp445.json",
                               "tcp-established")


def test_17_ios_non_initial_fragments_are_unknown_not_pass():
    _assert_unknown_everywhere("17_ios_fragments.cfg", "v4_tcp445.json",
                               "l4-fragments")


# --------------------------------------------------------------------------- #
# (e) IOS numbered-ACL masks are wildcards
# --------------------------------------------------------------------------- #
def test_14_ios_numbered_acl_mask_is_a_wildcard_not_a_netmask():
    """`access-list 101 deny ip 192.0.2.0 255.255.255.0 ...`: in a numbered
    IOS ACL 255.255.255.0 is a wildcard, so 192.0.2.5 is not denied and
    reaches the `eq 445` permit. It used to be read as a /24 netmask."""
    report, _ = _assert_unknown_everywhere(
        "14_ios_mask.cfg", "v4_tcp445.json", "imprecise-rule")
    kinds = [f["kind"] for f in report["findings"]]
    # the false `intent-inversion-permit-dead` came from the /24 misread
    assert "intent-inversion-permit-dead" not in kinds, kinds


def test_numbered_ios_acl_never_auto_detects_a_netmask():
    from rulehawk.parse import parse_acls
    aces, _ = parse_acls(
        "access-list 101 deny ip 192.0.2.0 255.255.255.0 any\n"
        "access-list 101 permit ip any any\n"
        "interface GigabitEthernet0/1\n ip access-group 101 in\n")
    first = aces[0]
    assert not (str(first.src) == "192.0.2.0/24" and not first.imprecise), first
    assert first.imprecise
    # a contiguous wildcard still parses exactly
    aces, _ = parse_acls("access-list 101 deny ip 192.0.2.0 0.0.0.255 any\n")
    assert str(aces[0].src) == "192.0.2.0/24" and not aces[0].imprecise
    # numbered standard ACLs are wildcards too
    aces, _ = parse_acls("access-list 10 permit 192.0.2.0 255.255.255.0\n")
    assert aces[0].imprecise
    # an ASA `extended` line keeps its netmask reading
    aces, _ = parse_acls(
        "access-list 101 extended permit ip 192.0.2.0 255.255.255.0 any\n")
    assert str(aces[0].src) == "192.0.2.0/24" and not aces[0].imprecise


def test_ios_wildcard_all_ones_is_never_a_host(tmp_path):
    """In an IOS wildcard context `A 255.255.255.255` ignores every bit: it is
    not host A. The parser keeps the host reading (test_parse_cisco pins it),
    so no PASS may rest on it: UNKNOWN, ios-wildcard-all-ones."""
    pol = _pol("v4_tcp445.json")
    # Host reading: the permit is from 203.0.113.5 only (not CORP), a
    # would-be PASS. Wildcard reading: any source, so CORP reaches PCI.
    for body in ("ip access-list extended A\n"
                 " permit ip 203.0.113.5 255.255.255.255 198.51.100.0 0.0.0.255\n"
                 "interface GigabitEthernet0/1\n ip access-group A in\n",
                 "access-list 110 permit ip 203.0.113.5 255.255.255.255 198.51.100.0 0.0.0.255\n"
                 "interface GigabitEthernet0/1\n ip access-group 110 in\n"):
        cfg = tmp_path / "ones.cfg"
        cfg.write_text(body)
        _assert_unknown_everywhere(str(cfg), pol, "ios-wildcard-all-ones")


def test_numbered_acl_mask_with_pix_dialect_is_ambiguous_unknown(tmp_path):
    """No `extended` keyword plus a PIX/ASA dialect marker: the mask could be
    a PIX netmask or an IOS wildcard. Truly ambiguous -> UNKNOWN."""
    cfg = tmp_path / "pix.cfg"
    # Read as a PIX netmask the deny covers CORP -> PCI and the search finds
    # no witness (a would-be PASS); read as an IOS wildcard it denies only
    # the .0 addresses and the permit leaks.
    cfg.write_text("PIX Version 6.3(5)\n"
                   "access-list 101 deny ip 192.0.2.0 255.255.255.0 198.51.100.0 255.255.255.0\n"
                   "access-list 101 permit ip any any\n"
                   "access-group 101 in interface inside\n")
    rc, out = _run_cli([str(cfg), "--json", "--policy", _pol("v4_tcp445.json")])
    report = json.loads(out)
    seg = _assertion_findings(report)
    assert not any(f["kind"] in _PASS_KINDS for f in report["findings"])
    codes = set().union(*(_reason_codes(f) for f in seg))
    assert "numbered-acl-mask-ambiguous" in codes, codes
    assert rc != 0


# --------------------------------------------------------------------------- #
# must_reach: a CONNECTIVITY OK is a positive claim too
# --------------------------------------------------------------------------- #
def test_snmp_acl_never_proves_connectivity():
    """c6 under must_reach gave a false CONNECTIVITY OK: an SNMP ACL is not a
    transit filter."""
    rc, out = _run_cli([_cfg("ok/c6_snmp_acl.cfg"), "--json", "--policy",
                        _pol("v4_reach_tcp445.json")])
    report = json.loads(out)
    kinds = [f["kind"] for f in report["findings"]]
    assert "connectivity-ok" not in kinds, kinds
    unknown = [f for f in report["findings"] if f.get("verdict") == "UNKNOWN"]
    assert unknown, kinds
    assert "acl-not-packet-filter" in set().union(
        *(_reason_codes(f) for f in unknown))
    assert rc != 0


# --------------------------------------------------------------------------- #
# the vendor label: classic IOS is not NX-OS
# --------------------------------------------------------------------------- #
_IOS152_ETHERNET = """\
!
version 15.2
service timestamps debug datetime msec
hostname r1
boot-start-marker
boot-end-marker
!
interface Ethernet0/0
 no ip address
 shutdown
!
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
 ip access-group EDGE in
!
ip access-list extended EDGE
 permit tcp 203.0.113.0 0.0.0.255 host 192.0.2.10 eq 443
 deny ip any any
!
end
"""


def test_classic_ios_with_ethernet0_0_is_not_labelled_nxos(tmp_path):
    from rulehawk.gate import _pick_parser
    from rulehawk.parse_nxos import detect
    assert detect(_IOS152_ETHERNET) is False
    label, _ = _pick_parser(_IOS152_ETHERNET, "auto")
    assert label == "ios-asa"
    p = tmp_path / "r1.cfg"
    p.write_text(_IOS152_ETHERNET)
    _, out = _run_cli([str(p), "--json"])
    assert json.loads(out)["vendor"] == "ios-asa"


def test_real_nxos_shape_is_still_nxos():
    from rulehawk.parse_nxos import detect
    assert detect("version 9.3(10)\ninterface Ethernet1/1\n"
                  "ip access-list A\n  10 permit ip any any\n") is True
    assert detect("feature interface-vlan\ninterface Ethernet1/1\n"
                  "ip access-list A\n  10 permit ip any any\n") is True


# --------------------------------------------------------------------------- #
# the controls in cfg/ok
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", [
    "c1_timerange.cfg", "c2_emptygrp.cfg", "c3_panos_fqdn.set",
    "c4_panos_appdef.set", "c5_ipt_iface.sh",
])
def test_controls_stay_indeterminate(cfg):
    rc, out = _run_cli([_cfg("ok/" + cfg), "--json", "--policy",
                        _pol("v4_tcp445.json")])
    report = json.loads(out)
    seg = _assertion_findings(report)
    assert [f["kind"] for f in seg] == ["segmentation-indeterminate"], seg
    assert seg[0]["verdict"] == "UNKNOWN"
    assert "imprecise-rule" in _reason_codes(seg[0])


def test_control_c6_snmp_acl_keeps_its_violation():
    rc, out = _run_cli([_cfg("ok/c6_snmp_acl.cfg"), "--json", "--policy",
                        _pol("v4_tcp445.json")])
    report = json.loads(out)
    seg = _assertion_findings(report)
    assert [f["kind"] for f in seg] == ["segmentation-violation"], seg
    assert seg[0]["verdict"] == "FAIL"
    assert rc == 1


def test_control_c7_empty_panos_address_group_no_longer_widens_to_any():
    """An empty static address-group was widened to an EXACT any, so a deny
    on it shadowed the real allow and printed PASS (parse_panos.py:515)."""
    from rulehawk.parse_panos import parse_panos
    with open(_cfg("ok/c7_panos_emptygrp.set"), encoding="utf-8") as fh:
        aces, _ = parse_panos(fh.read())
    deny = [a for a in aces if a.action == "deny"]
    assert deny
    for a in deny:
        assert a.imprecise or a.src.prefixlen != 0, a
    rc, out = _run_cli([_cfg("ok/c7_panos_emptygrp.set"), "--json", "--policy",
                        _pol("v4_tcp445.json")])
    report = json.loads(out)
    kinds = [f["kind"] for f in report["findings"]]
    assert "segmentation-ok" not in kinds, kinds
    assert "intent-inversion-permit-dead" not in kinds, kinds
    seg = _assertion_findings(report)
    assert all(f["verdict"] in ("UNKNOWN", "FAIL") for f in seg), seg


def test_control_c8_unbound_ipv6_acl_with_a_note_is_unknown():
    """c8 printed PASS for an IPv4 question over an unbound IPv6 ACL that
    carries a parse note. Rules (b) and (c) both move it to UNKNOWN."""
    rc, out = _run_cli([_cfg("ok/c8_v6nd_named.cfg"), "--json", "--policy",
                        _pol("v4_tcp445.json")])
    report = json.loads(out)
    kinds = [f["kind"] for f in report["findings"]]
    assert "segmentation-ok" not in kinds, kinds
    seg = _assertion_findings(report)
    codes = set().union(*(_reason_codes(f) for f in seg))
    assert "acl-role-unknown" in codes, codes


# --------------------------------------------------------------------------- #
# the UNKNOWN verdict on the remaining surfaces
# --------------------------------------------------------------------------- #
def test_bound_clean_ios_acl_still_passes(tmp_path):
    """The fail-closed rules leave a provable answer alone: an interface-bound
    IOS ACL with no L4 match, no notes and no unmodeled default."""
    p = tmp_path / "r1.cfg"
    p.write_text("hostname r1\n"
                 "interface GigabitEthernet0/1\n"
                 " ip address 198.51.100.1 255.255.255.0\n"
                 " ip access-group EDGE in\n"
                 "ip access-list extended EDGE\n"
                 " deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255\n"
                 " permit ip 203.0.113.0 0.0.0.255 198.51.100.0 0.0.0.255\n"
                 " deny ip any any\n")
    rc, out = _run_cli([str(p), "--json", "--policy", _pol("v4_tcp445.json")])
    report = json.loads(out)
    seg = _assertion_findings(report)
    assert [f["kind"] for f in seg] == ["segmentation-ok"], seg
    assert seg[0]["verdict"] == "PASS"
    assert seg[0]["reasons"] == []
    assert rc == 0


def test_mcp_audit_says_unknown_never_pass():
    from rulehawk import mcp_server as m
    res = m.audit(_cfg("10_ios_vty_acl.cfg"), _pol("v4_tcp445.json"))
    assert res["verdict"] == "UNKNOWN", res["verdict"]
    assert res["segmentation_passed"] == []
    codes = {r["code"] for u in res["segmentation_unknown"] for r in u["reasons"]}
    assert "acl-not-packet-filter" in codes


def test_combine_reads_an_unknown_gate_as_unknown(tmp_path):
    from rulehawk import gate as g
    from rulehawk.combine import collect
    gate = run_gate([_cfg("10_ios_vty_acl.cfg")], _load_policy("v4_tcp445.json"))
    rec = tmp_path / "r.json"
    rec.write_text(g.to_result(gate, "vty"))
    checks = collect([str(rec)])
    assert [c.verdict for c in checks] == ["UNKNOWN"], checks
    assert "inconsistent" not in checks[0].detail


def test_no_production_surface_calls_the_raw_search():
    """The raw search (`check_segmentation` without a context) returns a
    search result, not a verdict. Every output surface must go through the
    fail-closed context, or a PASS could reach a user unchecked."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("rulehawk/cli.py", "rulehawk/gate.py", "rulehawk/evidence.py",
                "rulehawk/mcp_server.py", "docs/worker.js", "docs/index.html"):
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            src = fh.read()
        for line in src.splitlines():
            if ("check_segmentation(" in line
                    and "def check_segmentation" not in line
                    and "`check_segmentation(" not in line):
                assert "context=" in line, (rel, line)


def test_an_unrecognised_vendor_label_never_passes():
    """build_context with a label it has no checks for must block a PASS,
    not silently skip every vendor-specific check."""
    from rulehawk.failclosed import build_context
    from rulehawk.parse import parse_acls
    from rulehawk.segcheck import check_segmentation
    text = ("ip access-list extended A\n permit ip host 203.0.113.9 any\n"
            "interface GigabitEthernet0/1\n ip access-group A in\n")
    aces, notes = parse_acls(text)
    pol = json.load(open(_pol("v4_tcp445.json")))
    ctx = build_context(text, aces, notes, "cisco")
    fs = check_segmentation(aces, pol, context=ctx)
    assert not any(f.kind in _PASS_KINDS for f in fs)
    assert any("vendor-unknown" in [r["code"] for r in (f.reasons or [])]
               for f in fs)
