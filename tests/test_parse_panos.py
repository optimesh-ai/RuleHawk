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


# ── Confirmed-bug regressions (parser contract: SUPERSET, never subset) ────────
# model.py: an ACE's modeled space must be a superset of the rule's true match
# space; imprecise=True never excuses a subset (segcheck checks containment
# before imprecise). Each test below pins one confirmed subset-emission /
# widening bug (P3, P4, P5, P6, P7, P8).


def test_builtin_service_http_includes_8080():
    # P3: the predefined PAN-OS service-http is tcp 80 AND 8080 — modeling only
    # 80 FALSE-PASSED an 8080 leak.
    cfg = ("set rulebase security rules web from any to any source 10.20.0.0/16 "
           "destination 10.10.0.0/16 application any service service-http "
           "action allow\n")
    aces, _ = parse_panos(cfg)
    assert {(a.dst_port.lo, a.dst_port.hi) for a in aces} == {(80, 80), (8080, 8080)}
    assert all(a.proto == "tcp" and a.imprecise is False for a in aces)
    pol = {"zones": _SEG_POLICY["zones"],
           "must_not_reach": [{"src": "CORP", "dst": "PCI",
                               "proto": "tcp", "ports": [8080]}]}
    kinds = {f.kind for f in check_segmentation(aces, pol)}
    assert "segmentation-violation" in kinds


def test_builtin_service_https_stays_443():
    # P3: service-https is unchanged — exactly tcp/443.
    cfg = ("set rulebase security rules web from any to any source any "
           "destination any application any service service-https action allow\n")
    aces, _ = parse_panos(cfg)
    assert [(a.dst_port.lo, a.dst_port.hi) for a in aces] == [(443, 443)]


def test_multiline_address_group_members_accumulate():
    # P4: `set address-group G static [ m ]` on multiple lines APPENDS (set
    # semantics; exports emit one member per line) — overwriting kept only the
    # last member, so a leak through the first FALSE-PASSED.
    cfg = """
    set address corp-a ip-netmask 10.20.0.0/16
    set address corp-b ip-netmask 192.168.5.0/24
    set address-group grp static [ corp-a ]
    set address-group grp static [ corp-b ]
    set service svc-smb protocol tcp port 445
    set rulebase security rules leak from any to any source grp destination 10.10.0.0/16 application any service svc-smb action allow
    """
    aces, _ = parse_panos(cfg)
    assert {str(a.src) for a in aces} == {"10.20.0.0/16", "192.168.5.0/24"}
    assert all(a.imprecise is False for a in aces)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-violation" in kinds    # the first-line member leaks


def test_mixed_static_group_unresolved_member_never_false_passes():
    # P5: one unresolvable member (fqdn) means the resolved subset alone is NOT
    # the rule's match space — keeping only the resolvable subset FALSE-PASSED
    # flows through the unresolvable member. Partial precision now emits the
    # resolved member as an EXACT ACE plus one opaque any/any imprecise ACE
    # covering the unresolved remainder. The sound outcome is unchanged: the
    # assertion can never PASS (the fqdn may cover CORP) and no false CRITICAL
    # is invented (the resolved 192.168.5.0/24 is outside CORP).
    cfg = """
    set address good ip-netmask 192.168.5.0/24
    set address evil fqdn evil.example.com
    set address-group grp static [ good evil ]
    set service svc-smb protocol tcp port 445
    set rulebase security rules r from any to any source grp destination 10.10.0.0/16 application any service svc-smb action allow
    """
    aces, notes = parse_panos(cfg)
    precise = [a for a in aces if not a.imprecise]
    opaque = [a for a in aces if a.imprecise]
    assert len(precise) == 1 and str(precise[0].src) == "192.168.5.0/24"
    assert len(opaque) == 1
    assert opaque[0].src_any and opaque[0].dst_any   # marker covers the remainder
    assert any("partially resolved" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" not in kinds            # never a false PASS
    assert "segmentation-violation" not in kinds     # never a false CRITICAL
    assert "segmentation-indeterminate" in kinds


def test_max_expand_widens_to_any_never_truncates():
    # P6: >_MAX_EXPAND expansions used to keep only the FIRST value per
    # dimension — the forbidden source (a later member) vanished -> FALSE PASS.
    # Now the rule becomes one all-ANY imprecise ACE: indeterminate, never PASS.
    members = " ".join(f"198.18.{i // 250}.{i % 250 + 1}" for i in range(299))
    cfg = (
        "set service svc-smb protocol tcp port 445\n"
        f"set rulebase security rules big from any to any source "
        f"[ {members} 10.20.0.0/16 ] destination 10.10.0.0/16 "
        f"application any service svc-smb action allow\n"
    )
    aces, notes = parse_panos(cfg)
    assert len(aces) == 1
    assert aces[0].src_any and aces[0].imprecise is True
    assert any("widened" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" not in kinds


def test_bare_ipv6_address_is_host_route_not_slash32():
    # P7: a bare v6 address was widened to f"{v}/32" (2001:db8::/32), colliding
    # distinct hosts -> false-critical deny-dead. ip_network() yields the /128
    # host route — via both the object path and the literal path.
    cfg = """
    set address h5 ip-netmask 2001:db8::5
    set rulebase security rules a from any to any source any destination h5 application any service service-https action allow
    set rulebase security rules b from any to any source any destination 2001:db8::6 application any service service-https action deny
    """
    aces, _ = parse_panos(cfg)
    assert str(aces[0].dst) == "2001:db8::5/128"    # object path
    assert str(aces[1].dst) == "2001:db8::6/128"    # literal path
    assert all(a.imprecise is False for a in aces)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds


def test_sctp_service_ports_kept_exact():
    # P8: sctp is port-carrying in the model (covers() compares its ports), so
    # a custom sctp service keeps EXACT ports — a permit on 5000 can't kill a
    # later deny on 132 (disjoint ports, no deny-dead).
    cfg = """
    set service svc-sctp-hi protocol sctp port 5000
    set service svc-sctp-sig protocol sctp port 132
    set rulebase security rules a from any to any source any destination any application any service svc-sctp-hi action allow
    set rulebase security rules b from any to any source any destination any application any service svc-sctp-sig action deny
    """
    aces, _ = parse_panos(cfg)
    assert [(a.proto, str(a.dst_port)) for a in aces] == [("sctp", "5000"),
                                                          ("sctp", "132")]
    assert all(a.imprecise is False for a in aces)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds


def test_ports_on_unported_protocol_widen_and_flag():
    # P8: a port spec on a protocol covers() doesn't compare was dropped with no
    # note and imprecise=False — the ACE then claimed an exact ALL-ports space.
    cfg = """
    set service svc-weird protocol gre port 47
    set rulebase security rules r from any to any source any destination any application any service svc-weird action allow
    """
    aces, notes = parse_panos(cfg)
    assert len(aces) == 1
    assert aces[0].proto == "gre" and aces[0].dst_port.is_any()
    assert aces[0].imprecise is True
    assert any("non-port-carrying" in n for n in notes)


# ── negate-source/destination soundness (false-PASS regression) ───────────────
# `negate-source yes` means the rule matches the COMPLEMENT of the listed set.
# Modeling the LISTED nets (even marked imprecise) UNDER-approximates: segcheck
# skips any ACE whose modeled src doesn't contain the probe, so a probe outside
# the listed set never sees the permit and the audit prints a false PASS. The
# negated dimension must widen to ANY (⊇ complement), imprecise=True — the same
# discipline parse_iptables applies to `! -s` (src left at ANY).

def test_negate_source_widens_to_any_not_listed_nets():
    cfg = """
    set address corp-net ip-netmask 10.99.0.0/16
    set rulebase security rules allow-except from any to any source [ corp-net ] negate-source yes destination 10.10.0.0/16 application any service any action allow
    """
    aces, notes = parse_panos(cfg)
    assert len(aces) == 1
    a = aces[0]
    # The real match is everything EXCEPT 10.99.0.0/16 — the modeled src must be
    # ANY (a superset), never the listed 10.99.0.0/16 (a disjoint set).
    assert str(a.src) == "0.0.0.0/0"
    assert str(a.dst) == "10.10.0.0/16"       # non-negated dim stays exact
    assert a.imprecise is True                # ANY over-approximates -> no proofs
    assert any("negate-source" in n and "widened to any" in n for n in notes)


def test_negate_destination_widens_to_any_not_listed_nets():
    cfg = """
    set address dmz-net ip-netmask 192.0.2.0/24
    set rulebase security rules allow-except from any to any source 10.20.0.0/16 destination [ dmz-net ] negate-destination yes application any service any action allow
    """
    aces, notes = parse_panos(cfg)
    assert len(aces) == 1
    a = aces[0]
    assert str(a.dst) == "0.0.0.0/0"          # complement -> widened to ANY
    assert str(a.src) == "10.20.0.0/16"       # non-negated dim stays exact
    assert a.imprecise is True
    assert any("negate-destination" in n and "widened to any" in n for n in notes)


def test_negate_source_repro_indeterminate_not_pass():
    # The live repro: 'source [ CORP-NET(10.99/16) ] negate-source yes action
    # allow' + default deny. The real firewall PERMITS 10.20.0.0/16 -> PCI
    # (10.20/16 is outside the negated set), so a green "PASS: CORP cannot reach
    # PCI" is a false compliance claim. The honest verdict is INDETERMINATE.
    cfg = """
    set address corp-net ip-netmask 10.99.0.0/16
    set rulebase security rules allow-except from any to any source [ corp-net ] negate-source yes destination any application any service any action allow
    set rulebase security rules default-deny from any to any source any destination any application any service any action deny
    """
    aces, _ = parse_panos(cfg)
    findings = check_segmentation(aces, _SEG_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" not in kinds, (
        "FALSE PASS: negate-source permit modeled as the listed net — the real "
        "firewall permits CORP->PCI (CORP is outside the negated set)")
    # Fail-closed, not fail-wrong: no concrete witness exists in the modeled
    # space, so it must be INDETERMINATE (review manually), never CRITICAL.
    assert "segmentation-indeterminate" in kinds
    assert "segmentation-violation" not in kinds
