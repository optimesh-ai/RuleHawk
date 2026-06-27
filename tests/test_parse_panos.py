"""Palo Alto PAN-OS security-policy frontend (RH-4).

The PAN-OS parser emits the same `(List[ACE], notes)` IR as the Cisco/Junos
parsers, so the existing analysis/segmentation engine consumes it unchanged.
These tests pin:
  1. happy path — a real-shaped set-format policy (with address + service object
     resolution) maps to the right ACEs;
  2. discipline — every unmodeled construct (zone, L7 application, group) is
     SURFACED as a note, the rule is kept and marked imprecise, never dropped;
  3. value — a PAN-OS sample produces a concrete segmentation violation, and an
     earlier deny rule blocks the flow with no false alarm;
  4. soundness — an unparsed/unresolved value widens to ANY but is flagged
     imprecise, so it can never prove a later deny dead (the RH-3 lesson).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import analyze, parse_panos  # noqa: E402
from rulehawk.analyze import analyze as _analyze_aces  # noqa: E402
from rulehawk.parse_panos import detect  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# A real-shaped PAN-OS set-format policy: address + service objects, an L3/L4
# web-allow (any zones/app so it's exact), then a default deny.
_POLICY_CFG = """
set address corp ip-netmask 10.20.0.0/16
set address pci ip-netmask 10.10.0.0/16
set service svc-web protocol tcp port 80,443
set rulebase security rules allow-web from any to any source corp destination pci application any service svc-web action allow
set rulebase security rules default-deny from any to any source any destination any application any service any action deny
"""


def test_detect_routes_panos_not_cisco_or_junos():
    assert detect(_POLICY_CFG) is True
    cisco = "ip access-list extended A\n permit tcp any any eq 443\n"
    junos = "firewall { family inet { filter F { term T { then accept; } } } }"
    assert detect(cisco) is False
    assert detect(junos) is False


def test_happy_path_resolves_objects_to_aces():
    aces, notes = parse_panos(_POLICY_CFG)
    # allow-web expands over svc-web's two ports (80, 443) -> 2 ACEs; default-deny
    # -> 1 ACE; total 3. Object names resolve to their CIDRs.
    assert len(aces) == 3
    permits = [a for a in aces if a.action == "permit"]
    denies = [a for a in aces if a.action == "deny"]
    assert len(permits) == 2 and len(denies) == 1
    for a in permits:
        assert a.proto == "tcp"
        assert str(a.src) == "10.20.0.0/16" and str(a.dst) == "10.10.0.0/16"
        assert a.dst_port.lo == a.dst_port.hi  # one concrete port each
        assert a.imprecise is False            # any zones + any app + concrete svc
    assert {a.dst_port.lo for a in permits} == {80, 443}
    d = denies[0]
    assert d.src_any and d.dst_any and d.proto == "ip"


def test_unmodeled_zone_and_application_surfaced_not_dropped():
    # A specific from/to zone and a specific L7 application are narrowings the
    # L3/L4 model can't represent -> the rule MUST be kept, marked imprecise, and
    # each construct surfaced as a note (never silently dropped).
    cfg = """
    set rulebase security rules r1 from trust to untrust source 10.0.0.0/8 destination 10.10.0.0/16 application web-browsing service any action allow
    """
    aces, notes = parse_panos(cfg)
    assert len(aces) == 1                       # rule kept, not dropped
    assert aces[0].imprecise is True            # over-approximated -> can't prove deadness
    assert any("zone" in n and "trust" in n for n in notes)
    assert any("application" in n and "web-browsing" in n for n in notes)


def test_disabled_rule_skipped_with_note():
    cfg = """
    set rulebase security rules dead from any to any source any destination any application any service any action allow
    set rulebase security rules dead disabled yes
    """
    aces, notes = parse_panos(cfg)
    assert aces == []
    assert any("disabled" in n for n in notes)


def test_unknown_action_surfaced_not_dropped():
    cfg = ("set rulebase security rules r from any to any source any "
           "destination any application any service any action frobnicate\n")
    aces, notes = parse_panos(cfg)
    assert aces == []
    assert any("frobnicate" in n for n in notes)


def test_xml_form_is_surfaced_not_silent():
    xmlcfg = ("<rulebase><security><rules>"
              "<entry name='r'><action>allow</action></entry>"
              "</rules></security></rulebase>")
    # XML lacks the set-format anchor, so detect() declines it; if force-routed
    # here it must surface guidance, never silently return nothing.
    assert detect(xmlcfg) is False
    aces, notes = parse_panos(xmlcfg)
    assert aces == []
    assert any("XML" in n and "set-format" in n for n in notes)


_SEG_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def test_segmentation_violation_on_panos_sample():
    # A PAN-OS rule that permits CORP->PCI on 445 (any zones, concrete service)
    # is a concrete segmentation violation with an auditor-grade witness packet.
    cfg = """
    set service svc-smb protocol tcp port 445
    set rulebase security rules leak from any to any source 10.20.0.0/16 destination 10.10.0.0/16 application any service svc-smb action allow
    """
    aces, _ = parse_panos(cfg)
    findings = check_segmentation(aces, _SEG_POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    assert "10.20" in viol[0].message and "10.10" in viol[0].message
    assert ":445" in viol[0].witness


def test_earlier_deny_blocks_no_false_alarm():
    # The forbidden flow is denied before the broad allow -> PASS, not a
    # violation (first-match semantics honored, same as the Cisco/Junos path).
    cfg = """
    set service svc-smb protocol tcp port 445
    set rulebase security rules block from any to any source 10.20.0.0/16 destination 10.10.0.0/16 application any service svc-smb action deny
    set rulebase security rules allow-all from any to any source any destination any application any service any action allow
    """
    aces, _ = parse_panos(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_permit_any_any_flagged_overly_permissive():
    cfg = ("set rulebase security rules anyany from any to any source any "
           "destination any application any service any action allow\n")
    aces, _ = parse_panos(cfg)
    kinds = {f.kind for f in analyze(aces)}
    assert "permit-any-any" in kinds


# ── RH-4 soundness regression (the RH-3 lesson) ────────────────────────────────
# When a referenced object/value cannot be resolved, the dimension must NOT
# silently widen to ANY with imprecise=False: an all-unresolved permit would then
# COVER a later deny and emit a false CRITICAL "intent-inversion-deny-dead". The
# parser flips imprecise on any unresolved value so the rule never proves another
# rule dead.

def test_unresolved_service_marks_imprecise_not_silent_any():
    cfg = ("set rulebase security rules r from any to any source any destination "
           "any application any service svc-undefined action allow\n")
    aces, notes = parse_panos(cfg)
    assert len(aces) == 1
    a = aces[0]
    assert a.dst_port.is_any()        # fell back to ANY (service unresolved) ...
    assert a.imprecise is True        # ... but flagged so it can't prove deadness
    assert any("svc-undefined" in n and "imprecise" in n for n in notes)


def test_unresolved_address_marks_imprecise():
    cfg = ("set rulebase security rules r from any to any source not-an-object "
           "destination 10.10.0.0/16 application any service any action allow\n")
    aces, notes = parse_panos(cfg)
    assert len(aces) == 1
    assert aces[0].src_any            # widened to ANY src
    assert aces[0].imprecise is True
    assert any("not-an-object" in n and "imprecise" in n for n in notes)


def test_unresolved_service_does_not_falsely_kill_later_deny():
    # The actual harm: an imprecise all-ANY permit must NOT prove a real later
    # deny on 445 dead. Without the imprecise flag this emits a false CRITICAL.
    cfg = """
    set service svc-smb protocol tcp port 445
    set rulebase security rules allow from any to any source any destination any application any service svc-undefined action allow
    set rulebase security rules block from any to any source any destination any application any service svc-smb action deny
    """
    aces, _ = parse_panos(cfg)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds, (
        "an imprecise (unresolved-value) permit must never prove a later deny dead")


def test_static_address_group_resolves_to_union():
    # Static address-groups resolve exactly (union of members) — sound coverage,
    # not imprecise.
    cfg = """
    set address a1 ip-netmask 10.20.1.0/24
    set address a2 ip-netmask 10.20.2.0/24
    set address-group corp static [ a1 a2 ]
    set rulebase security rules r from any to any source corp destination 10.10.0.0/16 application any service any action allow
    """
    aces, _ = parse_panos(cfg)
    srcs = sorted(str(a.src) for a in aces)
    assert srcs == ["10.20.1.0/24", "10.20.2.0/24"]
    assert all(a.imprecise is False for a in aces)


def test_ip_range_address_expands_exactly():
    cfg = """
    set address r1 ip-range 10.10.0.0-10.10.0.255
    set rulebase security rules r from any to any source 10.20.0.0/16 destination r1 application any service any action allow
    """
    aces, _ = parse_panos(cfg)
    # 10.10.0.0-10.10.0.255 summarizes exactly to a single /24.
    assert {str(a.dst) for a in aces} == {"10.10.0.0/24"}
    assert all(a.imprecise is False for a in aces)
