"""Fail-closed, second review of #42: the reviewer's false PASSes.

Every config in tests/fixtures/fail_closed/rev42 is the reviewer's synthetic
counterexample (RFC 5737 addresses). Before this fix each one printed PASS
(and evidence VERIFIED) on at least one surface while the real device
forwards the flow, or printed PASS under `--fail-on none` for a run whose
verdict was not PASS. F-numbers follow the review.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import cli  # noqa: E402
from rulehawk import gate as g  # noqa: E402
from rulehawk.combine import collect, main as combine_main, render  # noqa: E402

from test_fail_closed import (  # noqa: E402
    _BOUND_IOS, _assert_unknown_everywhere, _assertion_findings, _cfg,
    _load_policy, _pol, _run_cli)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REV = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "rev42")


def _rev(name: str) -> str:
    return os.path.join(_REV, name)


def _report(path: str, pol: str = "v4_ip.json") -> dict:
    _, out = _run_cli([path, "--json", "--policy", _pol(pol)])
    return json.loads(out)


# --------------------------------------------------------------------------- #
# F1: one unfiltered interface carrying both zones is a bypass on its own
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["d03_hairpin.cfg", "c03_hairpin.cfg",
                                 "c18_shut.cfg", "k01_hairpin.conf"])
def test_f1_same_interface_hairpin_is_unfiltered_path(cfg):
    """IOS routes 192.0.2.x to the secondary 198.51.100.x subnet back out
    the same unfiltered interface (Junos: two `family inet` addresses on one
    unit). No audited rule sees it."""
    _assert_unknown_everywhere(_rev(cfg), "v4_ip.json", "unfiltered-path")


def test_f1_an_interface_with_no_filter_in_either_direction_is_a_bypass(tmp_path):
    p = tmp_path / "one.cfg"
    p.write_text(_BOUND_IOS.replace(
        "\nip access-list extended EDGE\n",
        "\ninterface GigabitEthernet0/2\n ip address 203.0.113.1 255.255.255.0\n!\n"
        "ip access-list extended EDGE\n"))
    _assert_unknown_everywhere(str(p), "v4_tcp445.json", "unfiltered-path")


def test_f1_a_shutdown_filtered_interface_does_not_cover_traffic(tmp_path):
    """Gi0/1's filter is on a shutdown interface: it filters nothing."""
    p = tmp_path / "shut.cfg"
    p.write_text("interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
                 " ip access-group F in\n ip access-group F out\n"
                 "interface GigabitEthernet0/1\n ip address 198.51.100.1 255.255.255.0\n"
                 " ip access-group F out\n shutdown\n"
                 "interface GigabitEthernet0/2\n ip address 203.0.113.1 255.255.255.0\n"
                 " ip access-group F in\n"
                 "ip access-list extended F\n"
                 " deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255\n"
                 " permit ip 203.0.113.0 0.0.0.255 any\n")
    _assert_unknown_everywhere(str(p), "v4_ip.json", "unfiltered-path")


def test_f1_every_interface_filtered_one_way_still_passes(tmp_path):
    """The control: each interface has an inbound filter, so every path
    enters through EDGE. Still PASS."""
    p = tmp_path / "ok.cfg"
    p.write_text("interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
                 " ip access-group F in\n"
                 "interface GigabitEthernet0/1\n ip address 192.0.2.129 255.255.255.128\n"
                 " ip address 198.51.100.1 255.255.255.0 secondary\n"
                 " ip access-group F in\n"
                 "ip access-list extended F\n"
                 " deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255\n"
                 " permit ip 203.0.113.0 0.0.0.255 any\n")
    r = _report(str(p))
    assert r["assertion_verdict"] == "PASS", _assertion_findings(r)


# --------------------------------------------------------------------------- #
# F2: a PAN-OS rule field RuleHawk does not model blocks the PASS
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["q_source-imsi.set", "q_source-imei.set",
                                 "q_source-nw-slice.set"])
def test_f2_unknown_panos_rule_field_is_a_parse_note(cfg):
    report, _ = _assert_unknown_everywhere(_rev(cfg), "v4_ip.json", "parse-note")
    field = cfg[2:-4]
    assert any(field in n for n in report["parse_notes"]), report["parse_notes"]


@pytest.mark.parametrize("line", [
    # an unknown field after a known one on the same line
    "set rulebase security rules d from any to any source 192.0.2.0/24 "
    "destination 198.51.100.0/24 application any service any action deny "
    "source-imsi 001010123456789",
    # ...after a tag (a field whose values RuleHawk ignores)
    "set rulebase security rules d from any to any source 192.0.2.0/24 "
    "destination 198.51.100.0/24 application any service any tag t "
    "source-imei 490154203237518 action deny",
    # ...after a source-user value of `any`
    "set rulebase security rules d from any to any source 192.0.2.0/24 "
    "destination 198.51.100.0/24 source-user any source-nw-slice s1 "
    "application any service any action deny",
    # ...inside a container that is otherwise harmless
    "set rulebase security rules d from any to any source 192.0.2.0/24 "
    "destination 198.51.100.0/24 application any service any action deny "
    "option disable-server-response-inspection yes source-imsi 1",
    # a field name RuleHawk has never heard of
    "set rulebase security rules d from any to any source 192.0.2.0/24 "
    "destination 198.51.100.0/24 application any service any action deny "
    "frobnicate on",
])
def test_f2_an_unknown_field_is_never_swallowed_as_a_value(tmp_path, line):
    p = tmp_path / "u.set"
    p.write_text(line + "\nset rulebase security rules a from any to any source "
                 "192.0.2.0/24 destination 198.51.100.0/24 application any "
                 "service any action allow\n")
    _assert_unknown_everywhere(str(p), "v4_ip.json", "parse-note")


@pytest.mark.parametrize("cfg", ["q_log-setting.set", "q_uuid.set", "q_group-tag.set",
                                 "q_qos.set", "q_option.set",
                                 "q_icmp-unreachable.set"])
def test_f2_known_harmless_fields_do_not_block(cfg):
    """The allowlist's harmless entries change neither which packets a rule
    matches nor its action, so the deny still decides the flow."""
    r = _report(_rev(cfg))
    assert r["parse_notes"] == [], r["parse_notes"]
    assert r["assertion_verdict"] == "PASS", _assertion_findings(r)


def test_f2_security_profiles_block_a_connectivity_ok(tmp_path):
    """A security profile can drop traffic the rule allows, so it never
    blocks an isolation PASS but does block a connectivity OK."""
    p = tmp_path / "prof.set"
    p.write_text("set rulebase security rules a from any to any source 192.0.2.0/24 "
                 "destination 198.51.100.0/24 application any service any action allow\n"
                 "set rulebase security rules a profile-setting group strict\n")
    r = _report(str(p), "v4_reach_tcp445.json")
    seg = _assertion_findings(r)
    assert [f["verdict"] for f in seg] == ["UNKNOWN"], seg
    assert "panos-security-profile" in {x["code"] for f in seg for x in f["reasons"]}


# --------------------------------------------------------------------------- #
# F3: `--fail-on none` shows the real verdict; `passed` only on PASS
# --------------------------------------------------------------------------- #
def _none_gate(path, pol):
    return g.run_gate([path], _load_policy(pol) if pol else None, fail_on="none")


def test_f3_fail_on_none_unknown_is_not_shown_as_pass():
    gate = _none_gate(_cfg("10_ios_vty_acl.cfg"), "v4_tcp445.json")
    assert gate.exit_code() == 0                      # still never blocks
    assert gate.passed is False
    assert gate.verdict == "UNKNOWN"
    console = g.to_console(gate)
    assert "VERDICT: PASS" not in console, console
    assert "VERDICT: UNKNOWN (not enforced" in console, console
    md = g.to_markdown(gate)
    assert not md.startswith("## ✅"), md
    assert "**PASS**" not in md and "✅" not in md.split("\n", 1)[0], md
    assert "**UNKNOWN (not enforced)**" in md, md
    j = json.loads(g.to_json(gate))
    assert (j["verdict"], j["passed"], j["exit_code"], j["enforced"]) == \
        ("UNKNOWN", False, 0, False), j


def test_f3_fail_on_none_failure_and_advisory_are_named(tmp_path):
    # a broken isolation: FAIL, not enforced
    p = tmp_path / "leak.cfg"
    p.write_text(_BOUND_IOS.replace(
        " deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255\n", ""))
    gate = _none_gate(str(p), "v4_ip.json")
    assert (gate.verdict, gate.passed, gate.exit_code()) == ("FAIL", False, 0)
    assert "VERDICT: FAIL (not enforced" in g.to_console(gate)
    assert "**FAIL (not enforced)**" in g.to_markdown(gate)
    # findings but no assertion: ADVISORY, not enforced
    gate = _none_gate(os.path.join(_ROOT, "samples", "ios_acl.txt"), None)
    assert (gate.verdict, gate.passed, gate.exit_code()) == ("ADVISORY", False, 0)
    assert "VERDICT: ADVISORY (not enforced" in g.to_console(gate)
    assert "**ADVISORY (not enforced)**" in g.to_markdown(gate)
    # a parse failure: FAIL, not enforced
    e = tmp_path / "empty.cfg"
    e.write_text("hostname x\n")
    gate = _none_gate(str(e), "v4_ip.json")
    assert (gate.verdict, gate.passed, gate.exit_code()) == ("FAIL", False, 0)


def test_f3_fail_on_none_clean_run_is_still_pass(tmp_path):
    p = tmp_path / "ok.cfg"
    p.write_text(_BOUND_IOS)
    gate = _none_gate(str(p), "v4_tcp445.json")
    assert (gate.verdict, gate.passed, gate.exit_code()) == ("PASS", True, 0)
    assert "VERDICT: PASS" in g.to_console(gate)


def test_f3_fail_on_none_combine_shows_the_real_verdict(tmp_path):
    gate = _none_gate(_cfg("10_ios_vty_acl.cfg"), "v4_tcp445.json")
    rec = tmp_path / "r.json"
    rec.write_text(g.to_result(gate, "advisory"))
    d = json.loads(rec.read_text())
    assert d["passed"] is False and d["verdict"] == "UNKNOWN" and d["enforced"] is False
    [c] = collect([str(rec)])
    assert c.verdict == "UNKNOWN" and c.enforced is False, c
    body, worst = render([str(rec)])
    assert worst == "UNKNOWN"
    assert "✅" not in body and "**PASS**" not in body, body
    assert "not enforced" in body, body
    # ...and the exit code still follows the threshold: not enforced, exit 0
    out = tmp_path / "c.md"
    assert combine_main([str(rec), "--comment", str(out), "-q"]) == 0
    head = out.read_text().splitlines()[1]
    assert "PASS" not in head and "not enforced" in head, head


def test_f3_combine_with_an_enforced_and_an_advisory_check(tmp_path):
    ok = tmp_path / "ok.cfg"
    ok.write_text(_BOUND_IOS)
    a = tmp_path / "a.json"
    a.write_text(g.to_result(g.run_gate([str(ok)], _load_policy("v4_tcp445.json")),
                             "enforced"))
    b = tmp_path / "b.json"
    b.write_text(g.to_result(_none_gate(_cfg("10_ios_vty_acl.cfg"), "v4_tcp445.json"),
                             "advisory"))
    out = tmp_path / "c.md"
    assert combine_main([str(a), str(b), "--comment", str(out), "-q"]) == 0
    body = out.read_text()
    assert "RuleHawk firewall gate: PASS" not in body, body
    assert "UNKNOWN (not enforced)" in body, body


def test_f3_a_legacy_advisory_record_is_not_a_pass(tmp_path):
    """A record from before this change: passed=true under `fail-on none`
    with no real verdict. Its PASS is not proof."""
    gate = _none_gate(_cfg("10_ios_vty_acl.cfg"), "v4_tcp445.json")
    d = json.loads(g.to_result(gate, "old"))
    d["passed"], d["verdict"] = True, "ADVISORY"
    d.pop("enforced", None)
    rec = tmp_path / "old.json"
    rec.write_text(json.dumps(d))
    assert render([str(rec)])[1] != "PASS"


_yaml = pytest.importorskip("yaml", reason="PyYAML not installed")


def _enforce_step() -> str:
    with open(os.path.join(_ROOT, "action.yml"), encoding="utf-8") as fh:
        steps = _yaml.safe_load(fh)["runs"]["steps"]
    [s] = [s for s in steps if s.get("name") == "Enforce gate verdict"]
    return s["run"]


@pytest.mark.skipif(not os.path.exists("/bin/bash"), reason="no /bin/bash")
@pytest.mark.parametrize("verdict", ["UNKNOWN", "FAIL", "ADVISORY"])
def test_f3_action_does_not_say_passed_when_not_enforced(tmp_path, verdict):
    (tmp_path / "rulehawk.rc").write_text("0\n")
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), RH_FAIL_ON="none",
               RH_WORST="medium", RH_VERDICT=verdict)
    r = subprocess.run(["/bin/bash", "-c", _enforce_step()], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r          # the threshold decides the exit code
    assert "gate passed" not in r.stdout, r.stdout
    assert verdict in r.stdout and "not enforced" in r.stdout, r.stdout


@pytest.mark.skipif(not os.path.exists("/bin/bash"), reason="no /bin/bash")
def test_f3_action_still_says_passed_on_pass(tmp_path):
    (tmp_path / "rulehawk.rc").write_text("0\n")
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), RH_FAIL_ON="none",
               RH_WORST="none", RH_VERDICT="PASS")
    r = subprocess.run(["/bin/bash", "-c", _enforce_step()], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0 and "gate passed" in r.stdout, r


def test_f3_action_passed_output_follows_the_json():
    with open(os.path.join(_ROOT, "action.yml"), encoding="utf-8") as fh:
        a = _yaml.safe_load(fh)
    assert "steps.gate.outputs.verdict" in str(
        [s.get("env") for s in a["runs"]["steps"] if s.get("name") == "Enforce gate verdict"])
    desc = a["outputs"]["passed"]["description"]
    assert "fail-on none" in desc or "fail-on: none" in desc, desc


# --------------------------------------------------------------------------- #
# F4: Cisco `no access-list N` and banner text
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", ["d14_noacl.cfg", "c14_noacl.cfg"])
def test_f4_no_access_list_fails_closed(cfg):
    report, _ = _assert_unknown_everywhere(_rev(cfg), "v4_ip.json", "parse-note")
    assert any("no access-list" in n for n in report["parse_notes"])


@pytest.mark.parametrize("cfg", ["d16_banner.cfg", "c16_banner.cfg"])
def test_f4_banner_text_is_not_an_acl_line(cfg):
    """The deny inside the banner is text: ACL 101 only permits, so CORP
    reaches PCI. FAIL with a witness, never PASS."""
    r = _report(_rev(cfg))
    assert r["assertion_verdict"] == "FAIL", _assertion_findings(r)
    assert all("banner" not in (f.get("rule") or "") for f in r["findings"])
    assert r["rules_analyzed"] == 1


@pytest.mark.parametrize("delim", ["^C", "#", "%", "\x03"])
def test_f4_banner_delimiters(tmp_path, delim):
    p = tmp_path / "b.cfg"
    p.write_text(f"banner login {delim}\n"
                 "access-list 101 deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255\n"
                 f"authorized only{delim}\n" + _BOUND_IOS)
    r = _report(str(p), "v4_tcp445.json")
    assert not any(f.get("rule", "").startswith("access-list 101") for f in r["findings"])
    assert r["assertion_verdict"] == "PASS", (_assertion_findings(r), r["parse_notes"])


def test_f4_banner_on_one_line_skips_only_that_line(tmp_path):
    p = tmp_path / "b1.cfg"
    p.write_text("banner exec ^Cwelcome^C\n" + _BOUND_IOS)
    r = _report(str(p), "v4_tcp445.json")
    assert r["assertion_verdict"] == "PASS", (_assertion_findings(r), r["parse_notes"])


def test_f4_unterminated_banner_is_a_note(tmp_path):
    p = tmp_path / "b2.cfg"
    p.write_text(_BOUND_IOS + "banner motd ^C\nno end in sight\n")
    report, _ = _assert_unknown_everywhere(str(p), "v4_tcp445.json", "parse-note")
    assert any("banner" in n for n in report["parse_notes"])


def test_f4_banner_without_a_delimiter_is_a_note(tmp_path):
    p = tmp_path / "b3.cfg"
    p.write_text("banner motd\n" + _BOUND_IOS)
    report, _ = _assert_unknown_everywhere(str(p), "v4_tcp445.json", "parse-note")
    assert any("banner" in n for n in report["parse_notes"])


# --------------------------------------------------------------------------- #
# F5-F7
# --------------------------------------------------------------------------- #
def test_f5_asa_access_group_global_is_an_asa_marker():
    _assert_unknown_everywhere(_rev("a01_asa_global.cfg"), "v4_ip.json",
                               "unfiltered-path")


def test_f6_junos_non_ip_family_counts_as_unfiltered():
    """ge-0/0/2 carries only mpls/iso: labelled traffic popped there and IP
    forwarded out never meets an inet input filter."""
    _assert_unknown_everywhere(_rev("k08_fam_mpls.conf"), "v4_ip.json",
                               "unfiltered-path")


def test_f7_two_filter_blocks_in_restore_input_are_unknown():
    report, _ = _assert_unknown_everywhere(_rev("i11_save_twice.rules"), "v4_ip.json",
                                           "parse-note")
    assert any("*filter" in n for n in report["parse_notes"])


# --------------------------------------------------------------------------- #
# F8: every PASS states its scope
# --------------------------------------------------------------------------- #
_SCOPE = ("no audited ruleset permits this flow; assumes every interface is in "
          "the file; routing, NAT and topology not evaluated")


def test_f8_pass_states_its_scope_on_every_surface(tmp_path):
    from rulehawk import mcp_server as m
    for path in (_rev("c19_partial.cfg"),):
        r = _report(path)
        assert r["assertion_verdict"] == "PASS"
        ok = [f for f in _assertion_findings(r) if f["verdict"] == "PASS"]
        assert ok and all(_SCOPE in f["message"] for f in ok), ok
        _, text = _run_cli([path, "--policy", _pol("v4_ip.json")])
        assert _SCOPE in text, text
        gate = g.run_gate([path], _load_policy("v4_ip.json"))
        assert gate.verdict == "PASS"
        assert _SCOPE in g.to_console(gate)
        assert _SCOPE in g.to_markdown(gate)
        assert _SCOPE in g.to_json(gate)
        res = m.audit(path, _pol("v4_ip.json"))
        assert res["segmentation_passed"], res
        assert all(_SCOPE in s["message"] for s in res["segmentation_passed"])
        rec = tmp_path / "r.json"
        rec.write_text(g.to_result(gate, "c19"))
        body, worst = render([str(rec)])
        assert worst == "PASS" and _SCOPE in body, body


# --------------------------------------------------------------------------- #
# F9: CHANGELOG Compatibility
# --------------------------------------------------------------------------- #
def test_f9_changelog_compatibility_covers_the_behaviour_changes():
    with open(os.path.join(_ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
        text = fh.read()
    head = text.split("\n## ", 2)
    section = head[1] if len(head) > 1 else text
    compat = section.split("### Compatibility", 1)[1].split("\n### ", 1)[0]
    assert "fail-on: none" in compat and "`passed`" in compat, compat
    assert "iptables-fragments" in compat, compat
    assert "rulehawk_compare" in compat and "NO_NEW_RISK" in compat, compat
    assert "keep the job advisory with `fail-on: none`" not in compat, compat
