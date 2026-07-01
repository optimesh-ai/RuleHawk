"""Linux iptables / ip6tables filter frontend (RH-5).

The iptables parser emits the same `(List[ACE], notes)` IR as the Cisco / Junos /
PAN-OS parsers, so the existing analysis / segmentation engine consumes it
unchanged. These tests pin the four properties the task requires:
  1. happy path  — a real-shaped iptables-save filter table (and the command
     form) map to the right ordered first-match ACEs, with the chain default
     policy appended as the implicit trailing rule;
  2. discipline  — every unmodeled construct (conntrack/state, ipset, interface,
     a NAT/other table, a custom-chain jump, multiport beyond the single-range
     model) is SURFACED as a note, never silently dropped;
  3. value       — an iptables sample produces a concrete segmentation
     violation, and an earlier DROP blocks the flow with no false alarm;
  4. soundness   — an unparsed/over-approximated value is flagged imprecise, so
     it can never prove a later deny dead (the RH-3 lesson).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import analyze, parse_iptables  # noqa: E402
from rulehawk.analyze import analyze as _analyze_aces  # noqa: E402
from rulehawk.parse_iptables import detect  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# A real-shaped iptables-save filter table: SSH from a mgmt net, web to a server,
# then a default DROP policy on INPUT.
_SAVE_CFG = """
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
COMMIT
"""


def test_detect_routes_iptables_not_other_vendors():
    assert detect(_SAVE_CFG) is True
    assert detect("iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n") is True
    cisco = "ip access-list extended A\n permit tcp any any eq 443\n"
    junos = "firewall { family inet { filter F { term T { then accept; } } } }"
    panos = "set rulebase security rules r from any to any action allow\n"
    assert detect(cisco) is False
    assert detect(junos) is False
    assert detect(panos) is False


def test_happy_path_save_form_maps_to_aces():
    aces, notes = parse_iptables(_SAVE_CFG)
    # 4 explicit INPUT rules (the `-i lo` one is kept but imprecise) + the
    # appended default-DROP policy = 5 ACEs, all in the INPUT chain.
    inp = [a for a in aces if a.acl == "INPUT"]
    assert len(inp) == 5
    # The OUTPUT chain's ACCEPT policy is appended as its own (separate) ACE.
    out = [a for a in aces if a.acl == "OUTPUT"]
    assert len(out) == 1 and out[0].action == "permit" and out[0].src_any

    ssh = next(a for a in inp if a.dst_port.lo == 22)
    assert ssh.action == "permit" and ssh.proto == "tcp"
    assert str(ssh.src) == "10.0.0.0/8"
    assert ssh.imprecise is False

    web = next(a for a in inp if a.dst_port.lo == 443)
    assert web.action == "permit" and web.src_any            # no -s => any
    assert web.imprecise is False

    icmp = next(a for a in inp if a.proto == "icmp")
    assert icmp.icmp_type == "echo-request"

    # The default policy is the LAST rule of the chain and is a deny any/any.
    last = sorted(inp, key=lambda a: a.seq)[-1]
    assert last.action == "deny" and last.src_any and last.dst_any
    assert "policy" in last.raw


def test_command_form_equivalent():
    cfg = (
        "iptables -P INPUT DROP\n"
        "iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 3306 -j ACCEPT\n"
        "ip6tables -A INPUT -p tcp --dport 80 -j DROP\n"   # mixed: still parses
    )
    aces, _ = parse_iptables(cfg)
    permits = [a for a in aces if a.action == "permit"]
    assert any(str(a.src) == "192.168.1.0/24" and a.dst_port.lo == 3306
               for a in permits)


def test_multiport_expands_exactly_not_imprecise():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    permits = sorted(a.dst_port.lo for a in aces if a.action == "permit")
    assert permits == [80, 443, 8080]                       # exact union of 3 ACEs
    assert all(a.imprecise is False for a in aces if a.action == "permit")
    assert any("multiport" in n and "expanded" in n for n in notes)


def test_conntrack_state_modeled_stateful_and_surfaced():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    est = [a for a in aces if a.action == "permit"]
    assert est and est[0].stateful is True                  # return-traffic only
    assert any("stateful" in n and ("conntrack" in n or "state" in n) for n in notes)


def test_interface_match_marks_imprecise_and_surfaced():
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -i eth0 -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.dst_port.lo == 22)
    assert rule.imprecise is True                           # -i narrows; can't model
    assert any("interface" in n and "imprecise" in n for n in notes)


def test_custom_chain_jump_surfaced_not_silent():
    cfg = ("*filter\n:INPUT DROP [0:0]\n:DOCKER - [0:0]\n"
           "-A INPUT -j DOCKER\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    # The jump to the custom DOCKER chain emits no decision ACE (effect unknown)
    # but MUST be surfaced — never an invisible hole.
    assert not [a for a in aces if a.acl == "INPUT" and "policy" not in a.raw]
    assert any("custom chain" in n and "DOCKER" in n for n in notes)


def test_nat_table_and_masquerade_surfaced():
    cfg = ("*nat\n:POSTROUTING ACCEPT [0:0]\n"
           "-A POSTROUTING -o eth0 -j MASQUERADE\nCOMMIT\n"
           "*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    # Only the filter table is modeled; the nat table is surfaced and skipped.
    assert all(a.acl == "INPUT" for a in aces)
    assert any("nat" in n.lower() and "not modeled" in n for n in notes)


_SEG_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def test_segmentation_violation_on_iptables_forward():
    # A FORWARD rule that permits CORP->PCI on 445 is a concrete segmentation
    # violation with an auditor-grade witness packet.
    cfg = ("*filter\n:FORWARD ACCEPT [0:0]\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
           "COMMIT\n")
    aces, _ = parse_iptables(cfg)
    findings = check_segmentation(aces, _SEG_POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    assert "10.20" in viol[0].message and "10.10" in viol[0].message
    assert ":445" in viol[0].witness


# ── RH-iptables soundness regression: cross-chain shadowing (FALSE PASS) ───────
# A transit (inter-zone) packet is forwarded through the box and traverses ONLY
# the FORWARD chain. A normal host firewall sets `:INPUT DROP` / `:OUTPUT DROP`
# defaults. Before the fix the frontend flattened INPUT/FORWARD/OUTPUT into one
# ordered first-match stream, so INPUT's default `deny ip any any` (emitted first)
# shadowed the later FORWARD permit and segcheck FALSE-PASSed a real CORP->PCI:445
# leak. The FORWARD chain alone must govern the inter-zone verdict.

_MULTI_CHAIN_LEAK = (
    "*filter\n"
    ":INPUT DROP [0:0]\n"        # host-inbound default deny — must NOT shadow FORWARD
    ":FORWARD DROP [0:0]\n"
    ":OUTPUT ACCEPT [0:0]\n"     # host-outbound default accept — must NOT count as transit
    # the real inter-zone leak (transit path):
    "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
    # a legitimate, allowed transit flow that must keep PASSing where asserted:
    "-A FORWARD -s 10.20.0.0/16 -d 10.30.0.0/16 -p tcp --dport 443 -j ACCEPT\n"
    "COMMIT\n"
)

_MULTI_CHAIN_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"],
              "DMZ": ["203.0.113.0/24"]},
    "must_not_reach": [
        {"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]},
        {"src": "DMZ", "dst": "PCI", "proto": "ip"},
    ],
}


def test_multichain_input_drop_does_not_shadow_forward_leak():
    """The core soundness regression: with INPUT/OUTPUT default policies present,
    the FORWARD CORP->PCI:445 leak MUST surface as a CRITICAL violation (it used
    to FALSE-PASS because INPUT's default deny shadowed FORWARD). Reverting the
    `transit` exclusion makes this test fail."""
    aces, _ = parse_iptables(_MULTI_CHAIN_LEAK)
    findings = check_segmentation(aces, _MULTI_CHAIN_POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol, "FALSE PASS: FORWARD CORP->PCI:445 leak hidden by INPUT default deny"
    assert viol[0].severity == "critical"
    assert "FORWARD" in viol[0].rule_id          # the witness is in the FORWARD chain
    assert "10.20" in viol[0].message and "10.10" in viol[0].message
    assert ":445" in viol[0].witness


def test_multichain_input_output_flagged_non_transit():
    """INPUT/OUTPUT ACEs are excluded from the transit witness (transit=False);
    FORWARD ACEs stay transit-eligible. This is the mechanism the fix relies on."""
    aces, _ = parse_iptables(_MULTI_CHAIN_LEAK)
    assert all(a.transit for a in aces if a.acl == "FORWARD")
    assert all(not a.transit for a in aces if a.acl in ("INPUT", "OUTPUT"))


def test_multichain_no_false_pass_for_dmz_rule_and_legit_flow_passes():
    """No false PASS hiding under the noise: DMZ->PCI stays isolated (PASS, no
    permit on that path) and the legitimate CORP->DMZ:443 transit flow is not
    mis-reported as a violation."""
    aces, _ = parse_iptables(_MULTI_CHAIN_LEAK)
    findings = check_segmentation(aces, _MULTI_CHAIN_POLICY)
    by_label = {f.rule_id: f for f in findings}
    # DMZ!->PCI: no permit on that path anywhere -> a clean PASS, not a violation.
    dmz_oks = [f for f in findings if f.kind == "segmentation-ok" and "DMZ" in f.rule_id]
    assert dmz_oks, "DMZ->PCI should PASS (isolated), not be silently dropped"
    assert not [f for f in findings
                if f.kind == "segmentation-violation" and "DMZ" in (f.rule_id or "")]
    # The only violation is the CORP->PCI:445 leak; the legit CORP->DMZ:443 flow
    # (not asserted as forbidden) raises nothing.
    viols = [f for f in findings if f.kind == "segmentation-violation"]
    assert len(viols) == 1 and "10.10.0" in viols[0].message  # dst is PCI, not DMZ


# ── RH-iptables soundness regression: leak hidden in a jumped custom chain ─────
# `-A FORWARD -j CROSSZONE` jumps the TRANSIT path into a custom chain whose
# ACCEPT rule permits CORP->PCI:445. The custom-chain effect is unmodeled, so the
# jump emitted no decision — and the FORWARD default-deny then shadowed the
# CROSSZONE permit in the flat first-match stream, FALSE-PASSing a real leak.
# Fail-closed fix: an unmodeled transit jump emits an IMPRECISE marker that the
# engine turns into segmentation-INDETERMINATE, so a clean PASS is impossible for
# any flow the sub-chain could carry.

_CUSTOM_JUMP_LEAK = (
    "*filter\n"
    ":INPUT DROP [0:0]\n"
    ":FORWARD DROP [0:0]\n"
    ":CROSSZONE - [0:0]\n"
    "-A FORWARD -j CROSSZONE\n"
    "-A CROSSZONE -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
    "COMMIT\n"
)


def test_custom_chain_jump_on_transit_path_is_indeterminate_not_ok():
    """When the jumped custom chain IS fully modeled, precision resolution turns
    the former INDETERMINATE into a precise CRITICAL verdict. CROSSZONE contains a
    concrete ACCEPT for CORP->PCI:445 with no RETURN rules and no imprecise ACEs,
    so the resolved permit ACE is emitted in FORWARD and segcheck flags CRITICAL.
    Mutation guard: if resolution is disabled this reverts to INDETERMINATE or
    FALSE-PASS — both wrong."""
    aces, notes = parse_iptables(_CUSTOM_JUMP_LEAK)
    findings = check_segmentation(aces, _MULTI_CHAIN_POLICY)
    # Fully-modeled CROSSZONE ACCEPT → precise CRITICAL, NOT INDETERMINATE
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol, ("CORP->PCI:445 leak via fully-modeled CROSSZONE must surface "
                  "as CRITICAL (precision resolution)")
    assert viol[0].severity == "critical"
    assert not [f for f in findings
                if f.kind == "segmentation-ok" and "CORP" in (f.rule_id or "")], \
        "CORP->PCI must not FALSE-PASS"
    # Precision resolution note must be present
    assert any("resolved precisely" in n and "CROSSZONE" in n for n in notes)
    # Original jump surface note must still be present (never an invisible hole)
    assert any("custom chain" in n and "CROSSZONE" in n for n in notes)


def test_custom_chain_jump_emits_imprecise_transit_marker():
    """Mechanism check: when CROSSZONE is fully modeled, the FORWARD jump
    placeholder is replaced with a PRECISE transit ACE (permit tcp CORP->PCI:445).
    The resolved ACE is non-imprecise — it represents a real, auditable permit."""
    aces, _ = parse_iptables(_CUSTOM_JUMP_LEAK)
    fwd = [a for a in aces if a.acl == "FORWARD" and "policy" not in a.raw]
    assert fwd, "FORWARD must have at least one non-policy ACE (the resolved jump)"
    # Resolved ACE must be precise (not imprecise) and transit-eligible
    assert all(not a.imprecise and a.transit for a in fwd), \
        "resolved jump ACEs must be precise and transit=True"
    # Must represent the CROSSZONE ACCEPT: permit tcp CORP->PCI dport 445
    assert any(a.action == "permit" and a.proto == "tcp"
               and a.dst_port.lo == 445 and a.dst_port.hi == 445
               for a in fwd)


def test_custom_chain_jump_on_input_stays_surface_only():
    """A jump on the NON-transit INPUT hook does not decide inter-zone reachability,
    so it keeps the surface-only behavior (no synthetic ACE) — no regression to the
    existing custom-chain-jump test."""
    cfg = ("*filter\n:INPUT DROP [0:0]\n:DOCKER - [0:0]\n"
           "-A INPUT -j DOCKER\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert not [a for a in aces if a.acl == "INPUT" and "policy" not in a.raw]
    assert any("custom chain" in n and "DOCKER" in n for n in notes)


def test_clean_fully_modeled_config_still_passes():
    """No over-blocking regression: a fully-modeled FORWARD config with NO unmodeled
    construct and no permitted forbidden flow must still cleanly PASS."""
    cfg = ("*filter\n"
           ":INPUT DROP [0:0]\n"
           ":FORWARD DROP [0:0]\n"
           # only a benign, non-forbidden transit flow is permitted:
           "-A FORWARD -s 10.20.0.0/16 -d 10.30.0.0/16 -p tcp --dport 443 -j ACCEPT\n"
           "COMMIT\n")
    aces, _ = parse_iptables(cfg)
    findings = check_segmentation(aces, _MULTI_CHAIN_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" in kinds
    assert "segmentation-indeterminate" not in kinds
    assert "segmentation-violation" not in kinds


def test_earlier_drop_blocks_no_false_alarm():
    # The forbidden flow is DROPped before the broad ACCEPT policy -> PASS, not a
    # violation (first-match semantics honored, same as the other vendors).
    cfg = ("*filter\n:FORWARD ACCEPT [0:0]\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j DROP\n"
           "COMMIT\n")
    aces, _ = parse_iptables(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_default_accept_policy_flagged_overly_permissive():
    # A default-ACCEPT INPUT chain is the dangerous host-firewall default — the
    # appended `permit ip any any` must trip the overly-permissive check.
    cfg = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    aces, _ = parse_iptables(cfg)
    kinds = {f.kind for f in analyze(aces)}
    assert "permit-any-any" in kinds


# ── RH-5 soundness regression (the RH-3 lesson) ────────────────────────────────
# An over-approximated permit (unparsed port, ipset membership, negation) must
# NOT silently widen and prove a later deny dead — that would emit a false
# CRITICAL "intent-inversion-deny-dead" and could recommend deleting a real rule.

def test_unparsed_port_marks_imprecise():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp --dport not-a-port -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.dst_port.is_any()              # fell back to ANY ...
    assert rule.imprecise is True              # ... but flagged so it can't prove deadness
    assert any("not-a-port" in n and "imprecise" in n for n in notes)


def test_ipset_match_marks_imprecise():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -m set --match-set badips src -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.imprecise is True
    assert any("ipset" in n and "badips" in n and "imprecise" in n for n in notes)


def test_negated_source_marks_imprecise():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT ! -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.src_any and rule.imprecise is True
    assert any("negated source" in n and "imprecise" in n for n in notes)


def test_imprecise_permit_does_not_falsely_kill_later_deny():
    # The actual harm: an imprecise all-ANY permit must NOT prove a later real
    # deny on 445 dead. Without the imprecise flag this emits a false CRITICAL.
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -m set --match-set anyset src -j ACCEPT\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j DROP\n"
           "COMMIT\n")
    aces, _ = parse_iptables(cfg)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds, (
        "an imprecise (ipset) permit must never prove a later deny dead")


def test_ipv6_rules_use_v6_any():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -s 2001:db8::/32 -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, _ = parse_iptables(cfg)
    rule = next(a for a in aces if a.dst_port.lo == 22)
    assert rule.src.version == 6
    assert rule.dst.version == 6 and rule.dst_any   # unspecified dst -> ::/0


# ── RH-iptables-precision: custom-chain jump precision resolution ─────────────
# When the jumped chain IS fully modeled (all rules precise, no RETURN/NAT),
# the imprecise placeholder is replaced with exact ACEs. The five tests below
# cover: (a) drop → PASS, (b) accept → CRITICAL, (c) absent chain → INDETERMINATE,
# (d) fall-through / implicit RETURN → parent rule fires, (e) cycle → fail closed.

# Shared policy for (a)(b)(c)(d)(e) tests
_PREC_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def test_precision_modeled_chain_drop_gives_pass():
    """(a) Transit jump to a fully-modeled chain that DROPs the forbidden flow.

    ZONE_FILTER only contains an explicit DROP for tcp/445. Resolution replaces
    the imprecise placeholder with a precise deny ACE. Segcheck must yield
    segmentation-ok (PASS), never INDETERMINATE or CRITICAL."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":ZONE_FILTER - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j ZONE_FILTER\n"
        "-A ZONE_FILTER -p tcp --dport 445 -j DROP\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    findings = check_segmentation(aces, _PREC_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" in kinds, \
        "DROP in fully-modeled chain must give precise PASS"
    assert "segmentation-indeterminate" not in kinds, \
        "fully-modeled chain must not remain INDETERMINATE"
    assert "segmentation-violation" not in kinds, \
        "DROP must not give CRITICAL"
    # Mechanism: FORWARD has a precise deny ACE for tcp/445
    fwd_non_policy = [a for a in aces
                      if a.acl == "FORWARD" and "policy" not in a.raw]
    assert any(a.action == "deny" and not a.imprecise
               and a.proto == "tcp" and a.dst_port.lo == 445
               for a in fwd_non_policy), \
        "resolved deny for tcp/445 must be a precise ACE in FORWARD"
    assert any("resolved precisely" in n and "ZONE_FILTER" in n for n in notes)


def test_precision_modeled_chain_accept_gives_critical():
    """(b) Transit jump to a fully-modeled chain that ACCEPTs the forbidden flow.

    The jump rule narrows src only (-s CORP); the custom chain further narrows
    dst and proto (tcp/445 ACCEPT). Resolution computes the intersection and
    emits a precise permit ACE → segcheck must report CRITICAL."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":XZONE - [0:0]\n"
        # Jump rule matches CORP source only (no dst/proto restriction here)
        "-A FORWARD -s 10.20.0.0/16 -j XZONE\n"
        # Subchain adds dst+proto restriction and ACCEPTs
        "-A XZONE -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    findings = check_segmentation(aces, _PREC_POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol, "ACCEPT in fully-modeled chain must give precise CRITICAL"
    assert viol[0].severity == "critical"
    assert ":445" in viol[0].witness
    assert "10.20" in viol[0].message and "10.10" in viol[0].message
    # The resolved FORWARD ACE must be precise (not imprecise)
    fwd_non_policy = [a for a in aces
                      if a.acl == "FORWARD" and "policy" not in a.raw]
    assert any(a.action == "permit" and not a.imprecise
               and a.proto == "tcp" and a.dst_port.lo == 445
               for a in fwd_non_policy)
    assert any("resolved precisely" in n and "XZONE" in n for n in notes)


def test_precision_absent_chain_stays_indeterminate():
    """(c) Transit jump to a chain that is never defined in this config.

    The target MISSING_CHAIN is absent from by_chain → precision resolution
    fails closed. The imprecise placeholder stays → segmentation-INDETERMINATE.
    Never a false PASS."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        # MISSING_CHAIN is referenced but never declared or populated
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j MISSING_CHAIN\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    findings = check_segmentation(aces, _PREC_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-indeterminate" in kinds, \
        "absent chain must keep imprecise placeholder → INDETERMINATE (fail closed)"
    assert "segmentation-ok" not in kinds, \
        "must not FALSE-PASS when target chain is absent"
    # Jump must still be surfaced as a note (never an invisible hole)
    assert any("custom chain" in n and "MISSING_CHAIN" in n for n in notes)
    assert not any("resolved precisely" in n for n in notes)


def test_precision_fallthrough_return_parent_rule_fires():
    """(d) Fall-through / implicit RETURN path: precise resolution for matched
    space, parent chain fires for unmatched space.

    PORTCHECK only DROPs tcp/445. For the forbidden tcp/445 flow the custom chain
    provides a precise deny → PASS (no violation). For all other traffic the custom
    chain has no matching rule, so it falls through (implicit RETURN) and the next
    FORWARD rule handles it — the FORWARD DROP policy then catches anything else."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":PORTCHECK - [0:0]\n"
        # Jump rule narrows to CORP→PCI space
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j PORTCHECK\n"
        # Next FORWARD rule — fires for traffic that PORTCHECK does NOT terminate
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 443 -j ACCEPT\n"
        # PORTCHECK drops 445 only; 443 traffic falls through to parent
        "-A PORTCHECK -p tcp --dport 445 -j DROP\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)

    # tcp/445 must be blocked by the resolved deny → PASS (no isolation violation)
    findings_445 = check_segmentation(aces, _PREC_POLICY)
    kinds_445 = {f.kind for f in findings_445}
    assert "segmentation-ok" in kinds_445, \
        "tcp/445 must be precisely denied → PASS for isolation"
    assert "segmentation-indeterminate" not in kinds_445, \
        "fully-modeled PORTCHECK must not remain INDETERMINATE"

    # The FORWARD rule for tcp/443 must still be present after renumbering
    fwd_non_policy = [a for a in aces if a.acl == "FORWARD" and "policy" not in a.raw]
    assert any(a.action == "permit" and a.proto == "tcp" and a.dst_port.lo == 443
               for a in fwd_non_policy), \
        "parent chain ACCEPT for tcp/443 must survive chain renumbering"

    # Resolved deny for 445 must be precise
    assert any(a.action == "deny" and not a.imprecise
               and a.proto == "tcp" and a.dst_port.lo == 445
               for a in fwd_non_policy)
    assert any("resolved precisely" in n and "PORTCHECK" in n for n in notes)


def test_precision_chain_cycle_fails_closed_no_hang():
    """(e) Mutually-recursive chain cycle → fail closed, no infinite loop.

    CHAIN_A jumps to CHAIN_B; CHAIN_B jumps back to CHAIN_A. Each sub-chain
    jump emits an imprecise placeholder ACE in the respective chain. When
    FORWARD→CHAIN_A is resolved, CHAIN_A has an imprecise ACE (from its own
    sub-jump) → the "no imprecise ACE in subchain" gate fires → fail closed.
    Result: INDETERMINATE. No hang. No false PASS."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":CHAIN_A - [0:0]\n"
        ":CHAIN_B - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j CHAIN_A\n"
        "-A CHAIN_A -j CHAIN_B\n"
        "-A CHAIN_B -j CHAIN_A\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    findings = check_segmentation(aces, _PREC_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-indeterminate" in kinds, \
        "chain cycle must fail closed to INDETERMINATE (not hang, not FALSE-PASS)"
    assert "segmentation-ok" not in kinds, \
        "must not FALSE-PASS on a cyclic chain structure"
    # Resolution was NOT applied (cycle blocked by imprecise-ACE gate)
    assert not any("resolved precisely" in n for n in notes)
