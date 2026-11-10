"""#42 phase 2, slice 6: zone placement, in shadow (design v3 section 5.1,
v4 sections 2, 3, 10 and 13).

For a file the grammar parses, run with a policy, the shadow block gets a
`placement` entry read from the final model:
- every addressed Junos unit (`family inet` with an `address`) is a
  segment, its network the address's subnet. PAN-OS and iptables have no
  interface production yet, so they have no segment;
- (a) a segment that overlaps two asserted zones: `zones-share-segment`,
  and that is the blocking reason;
- a zone is pinned when every CIDR of it lies inside a segment that
  carries no other asserted zone. Any unpinned zone adds the placement
  assumption (`zone-placement-assumed`) to `scope_assumptions` and
  `headline_assumptions`, and, in the strict mode, gives
  `zone-placement-unpinned` (`blocking_reason_strict`);
- (b) bridging, (c) PAN-OS zones, (d) static routes and `rule-type` have
  no production, so a file holding one does not parse and gets no
  placement.

Both modes are computed; neither changes any output, and `would_pass`
stays false. The `--strict-placement` option and the headline on the
reporting surfaces come with the phase-3 flip (its default is Vedu's
decision, v4 sections 10 and 16).
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_K00 = os.path.join(_D, "controls", "k00_base.conf")
_P00 = os.path.join(_D, "controls", "p00_base.set")
_I00 = os.path.join(_D, "controls", "i00_base.sh")
_POL = os.path.join(_D, "pol", "v4_ip.json")

_HEADLINE = "assumes CORP and PCI are on separate segments"
# Review of #52-#57, G9: no grammar reads a static route, so the sentence
# does not say routes were checked.
_SCOPE = ("RuleHawk checked the interfaces this file configures; it read no "
          "static route; zones not attached in this file are assumed not to "
          "share a segment with another asserted zone.")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _policy():
    with open(_POL, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def shadow(monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")


def _gate_shadow(path, policy="default"):
    pol = _policy() if policy == "default" else policy
    d = json.loads(g.to_json(g.run_gate([path], pol, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    return f.get("shadow")


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return str(p)


def _cli_shadow(path, monkeypatch, capsys):
    from rulehawk import cli
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")
    try:
        cli.main([path, "--policy", _POL, "--json"])
    except SystemExit:
        pass
    return json.loads(capsys.readouterr().out)["shadow"]


# ----------------------------------------------------------------- the controls

def test_k00_both_zones_pinned(shadow):
    sh = _gate_shadow(_K00)
    pl = sh["placement"]
    assert pl["segments"] == [
        {"path": ["interfaces", "ge-0/0/0", "unit 0", "family inet"],
         "network": "192.0.2.0/24", "zones": ["CORP"]},
        {"path": ["interfaces", "ge-0/0/1", "unit 0", "family inet"],
         "network": "198.51.100.0/24", "zones": ["PCI"]}], pl
    assert pl["pinned"] == ["CORP", "PCI"] and pl["unpinned"] == [], pl
    assert pl["reason"] is None and pl["headline_assumptions"] == [], pl
    assert pl["scope_assumptions"] == [_SCOPE], pl
    assert pl["rows"] == [], pl
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["blocking_reason_strict"] == "file-uncertified", sh
    assert sh["would_pass"] is False, sh


@pytest.mark.parametrize("path", [_P00, _I00])
def test_unaddressed_controls_rest_on_the_assumption(path, shadow):
    """v4 section 11: under the strict mode the p00 and i00 controls flip."""
    sh = _gate_shadow(path)
    pl = sh["placement"]
    assert pl["segments"] == [] and pl["pinned"] == [], pl
    assert pl["unpinned"] == ["CORP", "PCI"], pl
    assert pl["reason"] is None, pl
    assert pl["headline_assumptions"] == [_HEADLINE], pl
    assert pl["scope_assumptions"] == [_SCOPE], pl
    assert pl["rows"] == ["zone-placement-assumed"], pl
    # Review of #60-#62, F60-1 and r2 F60-5: the checker is indeterminate on
    # iptables and PAN-OS while their pending rows stand, so both controls
    # are checker-disagrees.
    want = "checker-disagrees"
    assert sh["blocking_reason"] == want, sh
    assert sh["blocking_reason_strict"] == "zone-placement-unpinned", sh
    assert sh["would_pass"] is False, sh


def test_the_cli_carries_the_same_placement(monkeypatch, capsys):
    sh = _cli_shadow(_K00, monkeypatch, capsys)
    assert sh["placement"]["pinned"] == ["CORP", "PCI"], sh


# ------------------------------------------------------------------- rule (a)

def test_one_segment_overlapping_both_zones_shares_a_segment(tmp_path, shadow):
    """(a): one broad mask covers both zones (192.0.2.1/5 holds
    192.0.2.0/24 and 198.51.100.0/24)."""
    text = _read(_K00).replace("address 192.0.2.1/24;", "address 192.0.2.1/5;")
    sh = _gate_shadow(_write(tmp_path, "k.conf", text))
    pl = sh["placement"]
    assert pl["reason"] == "zones-share-segment", pl
    assert pl["segments"][0]["zones"] == ["CORP", "PCI"], pl
    assert sh["blocking_reason"] == "zones-share-segment", sh
    assert sh["blocking_reason_strict"] == "zones-share-segment", sh
    assert sh["would_pass"] is False, sh


def test_a_segment_that_only_partly_covers_a_zone_does_not_pin_it(tmp_path, shadow):
    text = _read(_K00).replace("address 198.51.100.1/24;", "address 198.51.100.1/25;")
    sh = _gate_shadow(_write(tmp_path, "k.conf", text))
    pl = sh["placement"]
    assert pl["pinned"] == ["CORP"] and pl["unpinned"] == ["PCI"], pl
    assert pl["headline_assumptions"] == [_HEADLINE], pl
    assert sh["blocking_reason_strict"] == "zone-placement-unpinned", sh


def test_an_unaddressed_zone_is_unpinned(tmp_path, shadow):
    lines = _read(_K00).split("\n")
    del lines[2]                                  # ge-0/0/1, the PCI unit
    sh = _gate_shadow(_write(tmp_path, "k.conf", "\n".join(lines)))
    pl = sh["placement"]
    assert pl["pinned"] == ["CORP"] and pl["unpinned"] == ["PCI"], pl
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["blocking_reason_strict"] == "zone-placement-unpinned", sh


def test_every_policy_zone_counts(tmp_path, shadow):
    """Decided by agent: every zone in the policy is asserted, named in an
    assertion or not (the more conservative reading)."""
    pol = _policy()
    pol["zones"]["DMZ"] = ["203.0.113.0/24"]
    sh = _gate_shadow(_K00, pol)
    pl = sh["placement"]
    assert pl["unpinned"] == ["DMZ"], pl
    assert pl["headline_assumptions"] == [
        "assumes CORP, DMZ and PCI are on separate segments"], pl


def test_a_zone_cidr_that_is_not_ipv4_is_unpinned(shadow):
    pol = _policy()
    pol["zones"]["PCI"] = ["2001:db8::/32"]
    sh = _gate_shadow(_K00, pol)
    # Review of #52-#57, G3: PCI may sit on any segment, so CORP's is no
    # longer its own either.
    assert sh["placement"]["unpinned"] == ["CORP", "PCI"], sh
    # Review of #52-#57, G3: a zone the placement cannot read is not
    # dropped; placement is off, in both modes.
    assert sh["blocking_reason"] == "zones-share-segment", sh
    assert sh["blocking_reason_strict"] == "zones-share-segment", sh


# -------------------------------------------- when there is no placement entry

def test_no_policy_no_placement(shadow):
    sh = _gate_shadow(_K00, None)
    assert "placement" not in sh and "blocking_reason_strict" not in sh, sh


@pytest.mark.parametrize("rel", ["cfg3/k13_junos_irb_both_zones_one_unit.conf",
                                 "cfg3/k15_junos_pci_nexthop_on_corp_segment.conf",
                                 "cfg3/p14_panos_pci_nexthop_on_corp_segment.set",
                                 "cfg3/p02_panos_rule_type_interzone_deny.set",
                                 "cfg3/p03_panos_same_zone_two_segments.set"])
def test_v4_slice_6_rows_do_not_parse(rel, shadow):
    """k13 (irb), k15 and p14 (static routes), p02 (`rule-type`) and p03
    (zones): no production, so no model and no placement."""
    sh = _gate_shadow(os.path.join(_D, rel))
    assert sh["grammar"]["parses"] is False, sh
    assert "placement" not in sh and "model" not in sh, sh
    assert sh["would_pass"] is False, sh


@pytest.mark.parametrize("value", ["universal", "interzone", "intrazone"])
def test_rule_type_is_off(value):
    """v4 section 3: the any/any exemption needs the rule-type row, which is
    not cited; every rule-type line is off, universal included."""
    from rulehawk import grammar_panos
    text = _read(_P00) + f"set rulebase security rules d rule-type {value}\n"
    r = grammar_panos.parse(text.encode())
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 2, r


@pytest.mark.parametrize("extra", [
    "set network virtual-router VR routing-table ip static-route s destination "
    "198.51.100.0/24 nexthop ip-address 192.0.2.254",
    "set zone inside network layer3 [ ethernet1/1 ]",
    "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24",
])
def test_panos_placement_lines_are_off(extra):
    from rulehawk import grammar_panos
    r = grammar_panos.parse((_read(_P00) + extra + "\n").encode())
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 2, r


def test_junos_routing_options_is_off():
    from rulehawk import grammar_junos
    text = _read(_K00) + "routing-options {\n    static { route 198.51.100.0/24 next-hop 192.0.2.254; }\n}\n"
    r = grammar_junos.parse(text.encode())
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 16, r


@pytest.mark.xfail(strict=True, reason="rule (d) needs static-route productions, "
                   "which need cited rows; until then k15 and p14 are off the "
                   "allowlist (line-not-allowlisted), not zones-share-segment")
@pytest.mark.parametrize("rel", ["cfg3/k15_junos_pci_nexthop_on_corp_segment.conf",
                                 "cfg3/p14_panos_pci_nexthop_on_corp_segment.set"])
def test_rule_d_pin(rel, shadow):
    """v4 section 2, rule (d): whoever adds a static-route production must
    make these zones-share-segment."""
    sh = _gate_shadow(os.path.join(_D, rel))
    assert sh["blocking_reason"] == "zones-share-segment", sh


def test_the_placement_module_imports_only_the_standard_library():
    import ast
    for base in ("rulehawk", os.path.join("docs", "rulehawk")):
        src = _read(os.path.join(_ROOT, base, "placement.py"))
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom):
                assert not node.level, ast.dump(node)
                mods = [node.module or ""]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert m.split(".")[0] in ("__future__", "ipaddress", "typing"), m


def test_no_placement_without_the_switch(monkeypatch):
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    d = json.loads(g.to_json(g.run_gate([_K00], _policy(), fail_on="high", vendor="auto")))
    (f,) = d["files"]
    assert "shadow" not in f, f


# ------------------------------------------- review of #52-#57, G3, G4 and G8

@pytest.mark.parametrize("corp", [["192.0.2.0/25", "2001:db8::/32"],
                                  ["192.0.2.0/25", "not-a-cidr"]])
def test_a_zone_with_any_unreadable_cidr_turns_placement_off(corp, shadow):
    """G3, the reviewer's cases B and C: the file puts CORP and PCI on one
    segment (192.0.2.1/24 holds both); an IPv6 or unreadable CIDR in CORP
    must not take CORP out of rule (a)."""
    pol = _policy()
    pol["zones"] = {"CORP": corp, "PCI": ["192.0.2.128/25"]}
    sh = _gate_shadow(_K00, pol)
    pl = sh["placement"]
    assert pl["reason"] == "zones-share-segment", pl
    assert pl["unreadable"] == ["CORP"], pl
    assert sh["blocking_reason"] == "zones-share-segment", sh
    assert sh["blocking_reason_strict"] == "zones-share-segment", sh
    assert pl["headline_assumptions"] == [], pl   # no claim of separation
    assert sh["would_pass"] is False


def test_the_readable_case_still_shares_a_segment(shadow):
    """G3, case A: without the unreadable CIDR, (a) already blocks."""
    pol = _policy()
    pol["zones"] = {"CORP": ["192.0.2.0/25"], "PCI": ["192.0.2.128/25"]}
    sh = _gate_shadow(_K00, pol)
    assert sh["placement"]["reason"] == "zones-share-segment", sh
    assert sh["placement"]["unreadable"] == [], sh


def test_two_units_on_one_port_are_one_segment(tmp_path, shadow):
    """G4: with no VLAN separation cited, the units of one physical port are
    one L2 wire, so CORP and PCI share it."""
    text = _read(_K00).replace(
        "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n", "")
    text = text.replace(
        "address 192.0.2.1/24; } } }",
        "address 192.0.2.1/24; } } unit 1 { family inet { filter { input F; } "
        "address 198.51.100.1/24; } } }")
    assert "unit 1" in text and "ge-0/0/1" not in text
    sh = _gate_shadow(_write(tmp_path, "k.conf", text))
    assert "placement" in sh, sh
    pl = sh["placement"]
    assert pl["reason"] == "zones-share-segment", pl
    assert pl["pinned"] == [], pl
    assert sh["blocking_reason"] == "zones-share-segment", sh


def test_a_placement_error_fails_closed(monkeypatch, shadow):
    """G8: an exception in placement is a blocking reason in both modes,
    never a traceback."""
    from rulehawk import placement

    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(placement, "assess", boom)
    sh = _gate_shadow(_K00)
    assert sh["placement"]["error"] == "RuntimeError", sh
    assert sh["blocking_reason"] == "zone-placement-unpinned", sh
    assert sh["blocking_reason_strict"] == "zone-placement-unpinned", sh
    assert sh["would_pass"] is False
