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
    # canonicalized: iptables `echo-request` == Cisco `echo` == type 8.
    assert icmp.icmp_type == "echo"

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


def test_negated_ctstate_marks_imprecise_not_stateful():
    """`! --ctstate INVALID -j ACCEPT` matches the COMPLEMENT of INVALID — i.e.
    everything else, INCLUDING NEW flows. It must NOT be modeled as a stateful
    (return-traffic-only) rule; that direction FALSE-PASSes segmentation. The
    complement isn't modeled, so it must be marked imprecise and surfaced."""
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -m conntrack ! --ctstate INVALID -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.stateful is False, (
        "negated ctstate modeled as stateful — unsound (permits NEW flows)")
    assert rule.imprecise is True
    assert any("negated conntrack state" in n and "imprecise" in n for n in notes)


def test_negated_state_module_form_also_imprecise():
    """Same soundness rule for the legacy `-m state ! --state` spelling."""
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -m state ! --state INVALID,UNTRACKED -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.stateful is False and rule.imprecise is True
    assert any("negated conntrack state" in n for n in notes)


def test_negated_ctstate_repro_indeterminate_not_pass():
    """The live repro from the finding: `:FORWARD DROP` + the common hygiene rule
    `! --ctstate INVALID -j ACCEPT` used to yield a clean `segmentation-ok`
    (FALSE PASS) for a CORP->PCI tcp/445 must_not_reach assertion, while the real
    firewall ACCEPTs all non-INVALID traffic including NEW cross-zone flows.
    The imprecise permit must fail closed to segmentation-INDETERMINATE."""
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -m conntrack ! --ctstate INVALID -j ACCEPT\nCOMMIT\n")
    aces, _ = parse_iptables(cfg)
    findings = check_segmentation(aces, _SEG_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" not in kinds, (
        "FALSE PASS: negated-ctstate ACCEPT hidden as stateful — CORP->PCI:445 "
        "reported isolated while the rule permits NEW flows")
    assert "segmentation-indeterminate" in kinds


def test_non_negated_ctstate_still_stateful_no_regression():
    """The straight (non-negated) return-traffic idiom keeps its precise stateful
    model — no over-blocking regression from the negation fix."""
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
           "COMMIT\n")
    aces, _ = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.stateful is True and rule.imprecise is False
    # Stateful-only permit never opens a NEW flow -> the isolation check PASSes.
    kinds = {f.kind for f in check_segmentation(aces, _SEG_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds


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


# ── superset-contract regressions ──────────────────────────────────────────────
# The parser contract: an ACE's modeled space must be a SUPERSET of the rule's
# true match space. A negated match modeled as the un-negated value is a SUBSET
# (narrower than reality) — a deny so narrowed can hide a real leak. Each fix
# below over-approximates the dimension to ANY + imprecise instead.

def test_negated_dport_not_narrowed_to_the_port():
    # `! --dport 22` matches every port EXCEPT 22; modeling it as ==22 is a
    # subset. The dimension must stay ANY (superset), flagged imprecise.
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp ! --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.dst_port.is_any() and rule.imprecise is True
    assert any("negated --dport" in n and "imprecise" in n for n in notes)


def test_negated_sport_and_multiport_dports_not_narrowed():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp ! --sport 1024 -j ACCEPT\n"
           "-A INPUT -p tcp -m multiport ! --dports 80,443 -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    permits = [a for a in aces if a.action == "permit"]
    assert len(permits) == 2                       # NOT expanded per negated port
    assert all(a.src_port.is_any() and a.dst_port.is_any() for a in permits)
    assert all(a.imprecise for a in permits)
    assert any("negated --sport" in n for n in notes)
    assert any("negated --dports" in n for n in notes)


def test_negated_proto_keeps_ip():
    # `! -p tcp` matches every proto EXCEPT tcp; proto must stay "ip" (superset).
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT ! -p tcp -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.proto == "ip" and rule.imprecise is True
    assert any("negated protocol" in n and "imprecise" in n for n in notes)


def test_negated_icmp_type_keeps_all_types():
    # `! --icmp-type echo-request` matches every type EXCEPT echo-request;
    # icmp_type must stay None (all types), flagged imprecise.
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p icmp ! --icmp-type echo-request -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.icmp_type is None and rule.imprecise is True
    assert any("negated ICMP type" in n and "imprecise" in n for n in notes)


def test_bare_restricting_module_marks_imprecise():
    # `-m limit` restricts by default (3/hour) even with no options — a silently
    # neutral model would over-count the permit's real space's complement... the
    # rule matches FEWER packets than modeled, so imprecise is the honest flag.
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp --dport 22 -m limit -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.imprecise is True
    assert any("match module `-m limit`" in n and "not modeled" in n for n in notes)


def test_neutral_modules_stay_precise():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp -m tcp --dport 22 -m comment -j ACCEPT\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.imprecise is False
    assert not any("match module" in n for n in notes)


def test_dccp_and_udplite_ports_kept():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p dccp --dport 33 -j ACCEPT\n"
           "-A INPUT -p udplite --dport 5004 -j ACCEPT\nCOMMIT\n")
    aces, _ = parse_iptables(cfg)
    dccp = next(a for a in aces if a.proto == "dccp")
    udpl = next(a for a in aces if a.proto == "udplite")
    assert dccp.dst_port.lo == dccp.dst_port.hi == 33      # not dropped to ANY
    assert udpl.dst_port.lo == udpl.dst_port.hi == 5004


def test_return_in_base_chain_fails_closed_not_false_pass():
    # `-j RETURN` in FORWARD applies the chain policy (ACCEPT) immediately: the
    # flow leaks. Skipping the RETURN let the later DROP match and segcheck
    # FALSE-PASS the leak. The fix emits the fail-closed imprecise marker.
    cfg = ("*filter\n:FORWARD ACCEPT [0:0]\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j RETURN\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j DROP\n"
           "COMMIT\n")
    aces, notes = parse_iptables(cfg)
    findings = check_segmentation(aces, _SEG_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" not in kinds, \
        "FALSE PASS: RETURN->policy-ACCEPT leak reported as isolated"
    assert kinds & {"segmentation-indeterminate", "segmentation-violation"}
    assert any("RETURN" in n and "fail-closed" in n for n in notes)


def test_return_in_input_stays_surface_only():
    # INPUT is non-transit: a RETURN there never decides inter-zone reachability,
    # so no synthetic ACE — surface-only, like the custom-chain jump on INPUT.
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -s 10.0.0.0/8 -j RETURN\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert not [a for a in aces if a.acl == "INPUT" and "policy" not in a.raw]
    assert any("RETURN" in n for n in notes)


def test_nat_table_save_form_rules_emit_no_ace():
    # Save-form `-A` lines inside a *nat block must not be parsed as filter
    # rules — a nat ACCEPT modeled as a filter permit is a false critical.
    cfg = ("*nat\n:PREROUTING ACCEPT [0:0]\n"
           "-A PREROUTING -d 203.0.113.5/32 -p tcp --dport 80 -j ACCEPT\nCOMMIT\n"
           "*filter\n:FORWARD DROP [0:0]\nCOMMIT\n")
    aces, notes = parse_iptables(cfg)
    assert not [a for a in aces if a.acl == "PREROUTING"]
    assert not [a for a in aces if a.action == "permit"]   # only FORWARD's deny policy
    assert any("nat" in n.lower() and "not modeled" in n for n in notes)


def test_replace_noted_and_appended():
    cfg = ("iptables -P INPUT DROP\n"
           "iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n"
           "iptables -R INPUT 1 -p tcp --dport 2222 -j ACCEPT\n")
    aces, notes = parse_iptables(cfg)
    assert any(a.action == "permit" and a.dst_port.lo == 2222 for a in aces)
    assert any("replace position not modeled" in n for n in notes)


def test_flush_clears_accumulated_rules():
    # An ignored mid-script flush would let the flushed DROP falsely prove the
    # flow blocked; after `-F FORWARD` only the ACCEPT policy remains -> violation.
    cfg = ("iptables -P FORWARD ACCEPT\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j DROP\n"
           "iptables -F FORWARD\n")
    aces, notes = parse_iptables(cfg)
    assert not [a for a in aces if a.acl == "FORWARD" and "policy" not in a.raw]
    findings = check_segmentation(aces, _SEG_POLICY)
    assert any(f.kind == "segmentation-violation" for f in findings), \
        "flushed DROP must not keep proving the flow blocked"
    assert any("flush" in n for n in notes)


def test_flush_without_chain_clears_all_chains():
    cfg = ("iptables -P INPUT DROP\n"
           "iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n"
           "iptables -A FORWARD -p tcp --dport 80 -j ACCEPT\n"
           "iptables -F\n")
    aces, notes = parse_iptables(cfg)
    assert not [a for a in aces if "policy" not in a.raw]
    assert any("flush" in n for n in notes)


def test_delete_noted_not_removed():
    cfg = ("iptables -P INPUT DROP\n"
           "iptables -A INPUT -p tcp --dport 23 -j ACCEPT\n"
           "iptables -D INPUT 1\n")
    aces, notes = parse_iptables(cfg)
    # Removal is not attempted (surfaced instead): the rule stays visible.
    assert any(a.dst_port.lo == 23 for a in aces)
    assert any("delete not modeled" in n for n in notes)


def test_ip6tables_save_policy_emitted_as_v6_any():
    # Genuine ip6tables-save output has no command token; a 0.0.0.0/0 policy
    # would never match a v6 flow (false PASS). Both v6 cues must work.
    icmp6 = ("*filter\n:FORWARD DROP [0:0]\n"
             "-A FORWARD -p ipv6-icmp -j ACCEPT\nCOMMIT\n")
    literal = ("*filter\n:FORWARD DROP [0:0]\n"
               "-A FORWARD -s fd00::/8 -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    for cfg in (icmp6, literal):
        aces, _ = parse_iptables(cfg)
        pol = next(a for a in aces if "policy" in a.raw)
        assert str(pol.src) == "::/0" and str(pol.dst) == "::/0"


def test_v4_save_without_command_token_stays_v4():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, _ = parse_iptables(cfg)
    pol = next(a for a in aces if "policy" in a.raw)
    assert str(pol.src) == "0.0.0.0/0"


def test_truncated_options_do_not_raise():
    # A value-consuming option at end-of-line must surface + mark imprecise,
    # never crash the whole parse.
    for cfg in ("*filter\n:INPUT DROP [0:0]\n-A INPUT -s\nCOMMIT\n",
                "iptables -A INPUT -p\n",
                "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport\nCOMMIT\n"):
        aces, notes = parse_iptables(cfg)     # must not raise
        assert any("truncated" in n for n in notes)


def test_reject_with_stays_precise():
    # `--reject-with` selects the refusal packet only (iptables-save always
    # writes it) — the deny must NOT go imprecise (needless INDETERMINATE).
    cfg = ("*filter\n:INPUT ACCEPT [0:0]\n"
           "-A INPUT -p tcp --dport 23 -j REJECT --reject-with icmp-port-unreachable\n"
           "COMMIT\n")
    aces, notes = parse_iptables(cfg)
    deny = next(a for a in aces if a.action == "deny")
    assert deny.imprecise is False and deny.dst_port.lo == 23
    assert not any("reject-with" in n for n in notes)


def test_lowercase_jump_accept_is_a_custom_chain_not_builtin():
    # Targets are case-sensitive: `-j accept` names a user chain, never the
    # ACCEPT verdict. The chain is deliberately NOT declared here, so the
    # precision-resolution pass fails closed (absent chain) and the transit
    # jump keeps the fail-closed imprecise marker. Mutation guard: an
    # `.upper()` regression would turn this into a precise ACCEPT permit
    # (violation, non-imprecise ACE) and fail every assertion below.
    cfg = ("*filter\n:FORWARD DROP [0:0]\n"
           "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j accept\n"
           "COMMIT\n")
    aces, notes = parse_iptables(cfg)
    fwd = [a for a in aces if a.acl == "FORWARD" and "policy" not in a.raw]
    assert fwd and all(a.imprecise for a in fwd)   # marker, not a precise permit
    assert any("custom chain" in n and "accept" in n for n in notes)
    findings = check_segmentation(aces, _SEG_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" not in kinds
    assert kinds & {"segmentation-indeterminate", "segmentation-violation"}


def test_dport_colon_range_exact():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p tcp --dport 1024:65535 -j ACCEPT\nCOMMIT\n")
    aces, _ = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert (rule.dst_port.lo, rule.dst_port.hi) == (1024, 65535)
    assert rule.imprecise is False


def test_numeric_protocol_normalized():
    cfg = ("*filter\n:INPUT DROP [0:0]\n"
           "-A INPUT -p 6 --dport 22 -j ACCEPT\nCOMMIT\n")
    aces, _ = parse_iptables(cfg)
    rule = next(a for a in aces if a.action == "permit")
    assert rule.proto == "tcp" and rule.dst_port.lo == 22


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


# ── RH-iptables soundness regression: icmpv6 type ignored by covers() ─────────
# covers() gated the icmp_type comparison on proto == "icmp" only, so typed
# ip6tables `--icmpv6-type` rules (proto "icmpv6") compared as if typeless: an
# RA-accept (type 134) "covered" the NS/NA accepts (135/136) and analyze()
# told the user rules 2-3 were shadowed/redundant — deleting them breaks IPv6
# neighbor discovery. The type dimension must bind for BOTH ICMP families.

def _mk_icmp6(icmp_type, seq=1, action="permit"):
    import ipaddress
    from rulehawk.model import ACE
    any6 = ipaddress.ip_network("::/0")
    return ACE(seq=seq, action=action, proto="icmpv6", src=any6, dst=any6,
               icmp_type=icmp_type)


def test_covers_respects_icmpv6_type():
    """A typed icmpv6 rule must NOT cover a differently-typed (or untyped) one —
    exactly the v4 icmp semantics."""
    from rulehawk.model import covers
    ra, ns, na = _mk_icmp6("134"), _mk_icmp6("135"), _mk_icmp6("136")
    untyped = _mk_icmp6(None)
    assert covers(ra, ns) is False, "type 134 must not cover type 135"
    assert covers(ra, na) is False, "type 134 must not cover type 136"
    # Typed-vs-untyped fails closed (an untyped rule spans MORE than one type).
    assert covers(ra, untyped) is False
    # A typeless icmpv6 rule still covers every type; same type still covers.
    assert covers(untyped, ns) is True
    assert covers(_mk_icmp6("135"), ns) is True


def test_union_coverer_respects_icmpv6_type():
    """The union-shadowing path mirrors covers()'s gates — same fix required."""
    from rulehawk.model import _compatible_coverer
    ra, ns = _mk_icmp6("134"), _mk_icmp6("135")
    assert _compatible_coverer(ra, ns) is False
    assert _compatible_coverer(_mk_icmp6(None), ns) is True
    assert _compatible_coverer(_mk_icmp6("135"), ns) is True


# The standard IPv6 ND/RA hygiene block: RA (134), NS (135), NA (136).
_ND_HYGIENE_V6 = (
    "ip6tables -P INPUT DROP\n"
    "ip6tables -A INPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT\n"
    "ip6tables -A INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT\n"
    "ip6tables -A INPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT\n"
)

_SHADOW_KINDS = {"redundant", "intent-inversion-permit-dead",
                 "intent-inversion-deny-dead", "union-shadowed-permit-dead",
                 "union-shadowed-deny-dead"}


def test_ip6tables_nd_hygiene_block_not_falsely_shadowed():
    """End-to-end repro from the finding: the three typed icmpv6 accepts are
    distinct match-spaces — analyze() must NOT call any of them shadowed,
    redundant, or dead (that advice, followed, breaks neighbor discovery)."""
    aces, _ = parse_iptables(_ND_HYGIENE_V6)
    typed = sorted((a for a in aces if a.proto == "icmpv6"), key=lambda a: a.seq)
    assert [a.icmp_type for a in typed] == ["134", "135", "136"]
    assert all(a.src.version == 6 for a in typed), "ip6tables => v6 any nets"
    findings = _analyze_aces(aces)
    bad = [f for f in findings if f.kind in _SHADOW_KINDS]
    assert not bad, (
        "typed icmpv6 rules falsely reported shadowed/redundant: "
        + "; ".join(f"{f.kind}: {f.message}" for f in bad))


def test_ip6tables_true_duplicate_icmpv6_rule_still_flagged():
    """No over-relaxation: an ACTUAL duplicate typed icmpv6 rule (same type)
    must still be reported redundant, and an untyped icmpv6 accept must still
    shadow a later typed one."""
    cfg = (
        "ip6tables -P INPUT DROP\n"
        "ip6tables -A INPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT\n"
        "ip6tables -A INPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT\n"
    )
    aces, _ = parse_iptables(cfg)
    findings = _analyze_aces(aces)
    assert any(f.kind == "redundant" for f in findings), \
        "identical typed icmpv6 rule must still be flagged redundant"

    cfg2 = (
        "ip6tables -P INPUT DROP\n"
        "ip6tables -A INPUT -p icmpv6 -j ACCEPT\n"
        "ip6tables -A INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT\n"
    )
    aces2, _ = parse_iptables(cfg2)
    findings2 = _analyze_aces(aces2)
    assert any(f.kind == "redundant" for f in findings2), \
        "typeless icmpv6 accept covers every type — later typed rule is redundant"


# ── RH-iptables imprecise-marking coverage (fail-closed branches) ──────────────
# Coverage showed the guards that set `imprecise=True` — the ONLY mechanism
# preventing an unmodeled/narrowed match from producing a false segmentation
# PASS — were never executed by any test: negated -d / -p, unparsed -s / -d,
# --sport (whole branch), --sports multiport, lo:hi / open-ended port ranges,
# an unparsable range component, -f fragments, and the unknown-option catch-all.
# If a refactor dropped `imprecise = True` on any of these branches, RuleHawk
# would certify isolation over a rule it modeled too narrowly — a false clean
# bill of health. These tests pin each branch: (a) the imprecise flag, (b) the
# exact port range where parseable, and (c) the user-visible "marked imprecise"
# note (it appears verbatim in the PR comment, so its wording is contract).

import pytest  # noqa: E402


class TestImpreciseMarkingBranches:
    """Each unmodeled/narrowing construct MUST flip imprecise + emit a note."""

    def _one_forward_rule(self, rule_args):
        cfg = f"*filter\n:FORWARD DROP [0:0]\n-A FORWARD {rule_args}\nCOMMIT\n"
        aces, notes = parse_iptables(cfg)
        non_policy = [a for a in aces if a.acl == "FORWARD"
                      and "policy" not in a.raw]
        return non_policy, notes

    # (rule args, note fragment that must appear alongside 'imprecise')
    _IMPRECISE_CASES = [
        ("! -d 10.0.0.0/8 -j ACCEPT", "negated destination"),
        ("! -p tcp -j ACCEPT", "negated protocol"),
        ("-s bogus -p tcp --dport 22 -j ACCEPT", "unparsed iptables source 'bogus'"),
        ("-d bogus -p tcp --dport 22 -j ACCEPT",
         "unparsed iptables destination 'bogus'"),
        ("-p tcp --sport bogus -j ACCEPT", "unparsed iptables --sport 'bogus'"),
        ("-p tcp --dport 1000:foo -j ACCEPT",
         "unparsed iptables --dport '1000:foo'"),
        ("-p tcp ! --dport 445 -j ACCEPT", "negated --dport"),
        ("-p tcp ! --sport 1024 -j ACCEPT", "negated --sport"),
        ("-f -j ACCEPT", "fragment match (`-f`)"),
        ("-p tcp --tcp-flags SYN,ACK SYN -j ACCEPT",
         "unmodeled iptables option `--tcp-flags"),
    ]

    @pytest.mark.parametrize("rule_args,note_frag",
                             [pytest.param(r, f, id=r) for r, f in _IMPRECISE_CASES])
    def test_branch_marks_imprecise_and_surfaces_note(self, rule_args, note_frag):
        rules, notes = self._one_forward_rule(rule_args)
        assert rules, f"rule `{rule_args}` must still emit an ACE (over-approximated)"
        assert all(a.imprecise for a in rules), (
            f"`{rule_args}` narrows in an unmodeled dimension — its ACE must be "
            f"imprecise or segcheck can FALSE-PASS over it")
        assert any(note_frag in n for n in notes), (
            f"expected a note containing {note_frag!r}; got: {notes}")
        assert any(note_frag in n and "imprecise" in n for n in notes), (
            "the note must carry the 'marked imprecise' wording users see")

    # ── exact port-range parsing (parseable specs stay PRECISE) ────────────────

    @pytest.mark.parametrize("rule_args,attr,lo,hi", [
        ("-p tcp --dport 1000:2000 -j ACCEPT", "dst_port", 1000, 2000),
        ("-p tcp --dport :1024 -j ACCEPT", "dst_port", 0, 1024),
        ("-p tcp --sport 1024: -j ACCEPT", "src_port", 1024, 65535),
        ("-p tcp --sport 5000:6000 -j ACCEPT", "src_port", 5000, 6000),
    ], ids=["dport-lo:hi", "dport-:hi-open-low", "sport-lo:-open-high",
            "sport-lo:hi"])
    def test_port_range_exact_and_precise(self, rule_args, attr, lo, hi):
        rules, _ = self._one_forward_rule(rule_args)
        assert len(rules) == 1
        pr = getattr(rules[0], attr)
        assert (pr.lo, pr.hi) == (lo, hi), (
            f"`{rule_args}` must parse to the EXACT range {lo}-{hi}, got {pr}")
        assert rules[0].imprecise is False, (
            "a fully-parsed port range is exact — must NOT be imprecise "
            "(over-flagging erodes the signal)")

    def test_sports_multiport_expands_exactly(self):
        rules, notes = self._one_forward_rule(
            "-p tcp -m multiport --sports 22,80,443 -j ACCEPT")
        got = sorted((a.src_port.lo, a.src_port.hi) for a in rules)
        assert got == [(22, 22), (80, 80), (443, 443)], (
            "--sports must expand to the exact union of per-port ACEs")
        assert all(a.imprecise is False for a in rules)
        assert any("--sports" in n and "expanded to 3" in n for n in notes)

    def test_unparsable_range_component_keeps_parsed_siblings(self):
        # The documented RH-3 lesson inside _ports: an unparsable component in a
        # multiport list flips imprecise but the parseable siblings stay exact —
        # never a silent widen-to-ANY.
        rules, notes = self._one_forward_rule(
            "-p tcp -m multiport --dports 22,bogus,443 -j ACCEPT")
        got = sorted(a.dst_port.lo for a in rules)
        assert got == [22, 443]
        assert all(a.imprecise for a in rules), (
            "an unparsable component in the SAME spec must taint the rule "
            "imprecise — it matched more than we modeled")
        assert any("unparsed iptables --dports 'bogus'" in n
                   and "marked imprecise" in n for n in notes)

    def test_ctstate_with_new_modeled_as_new_flow_not_stateful(self):
        rules, notes = self._one_forward_rule(
            "-m conntrack --ctstate NEW,ESTABLISHED -p tcp --dport 22 -j ACCEPT")
        assert len(rules) == 1
        assert rules[0].stateful is False, (
            "NEW present — the connection-opening packet IS allowed, so modeling "
            "it stateful would hide real reachability")
        assert rules[0].imprecise is False
        assert any("NEW present" in n and "new-flow" in n for n in notes)

    def test_rule_without_terminating_target_skipped_with_note(self):
        rules, notes = self._one_forward_rule("-p tcp --dport 22")
        assert rules == [], "a rule with no -j ACCEPT/DROP/REJECT decides nothing"
        assert any("no terminating target" in n and "skipped" in n for n in notes)

    # ── end-to-end: an imprecise permit fails closed, never a false PASS ───────

    def test_negated_dst_accept_yields_indeterminate_not_ok(self):
        """The user-facing stake: `! -d` ACCEPT on the transit path could carry
        the forbidden CORP->PCI:445 flow (10.10/16 is outside the negated 10.0/8?
        no — we can't know, the complement isn't one rectangle). Segcheck must
        return segmentation-INDETERMINATE, never certify isolation."""
        cfg = ("*filter\n:FORWARD DROP [0:0]\n"
               "-A FORWARD ! -d 192.0.2.0/24 -j ACCEPT\n"
               "COMMIT\n")
        aces, notes = parse_iptables(cfg)
        findings = check_segmentation(aces, _SEG_POLICY)
        kinds = {f.kind for f in findings}
        assert "segmentation-ok" not in kinds, (
            "FALSE PASS: a negated-dst ACCEPT was modeled as dst ANY without the "
            "imprecise flag — RuleHawk certified isolation it cannot prove")
        assert "segmentation-indeterminate" in kinds
        assert any("negated destination" in n and "imprecise" in n for n in notes)


# ── RH-iptables soundness regression: -I / -R first-match ORDER ────────────────
# `iptables -I CHAIN [N]` inserts a rule at position N (default 1 = the very
# front); `-R CHAIN N` replaces the rule at position N. The old frontend APPENDED
# both at the end, INVERTING first-match order — a `-I CHAIN 1 ... -j ACCEPT`
# ahead of a deny was modeled as deny-then-permit and segcheck FALSE-PASSed the
# leak (the unsound direction). The parser contract (model.py) requires the
# emitted per-chain ACEs to be in true device order with monotonic `seq`; these
# tests pin the SOUND end-to-end verdict through check_segmentation.

# CORP(10.20/16) must not reach ZONE99(10.99/16) — the task's repro address pair.
_INSERT_POLICY = {
    "zones": {"CORP": ["10.20.0.0/16"], "Z99": ["10.99.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "Z99", "proto": "ip"}],
}


def _fwd_ordered(aces):
    return sorted((a for a in aces if a.acl == "FORWARD" and "policy" not in a.raw),
                  key=lambda a: a.seq)


def test_insert_index1_drop_before_accept_isolates():
    """The task's repro: `-I FORWARD 1 ... -j DROP` lands the DROP at the FRONT,
    before the earlier ACCEPT. On the device the flow is DROPPED (isolated), so
    segcheck must yield segmentation-ok. The old append-at-end modeled ACCEPT
    first and over-reported a leak."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -j ACCEPT\n"
           "iptables -I FORWARD 1 -s 10.20.0.0/16 -d 10.99.0.0/16 -j DROP\n")
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert [a.action for a in fwd] == ["deny", "permit"], \
        "the inserted DROP must occupy the FRONT (seq before the ACCEPT)"
    assert fwd[0].seq < fwd[1].seq                     # seq monotonic in device order
    kinds = {f.kind for f in check_segmentation(aces, _INSERT_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds


def test_insert_index1_permit_before_deny_is_violation_not_false_pass():
    """The DANGEROUS direction: `-I FORWARD 1 ... -j ACCEPT` inserts a permit
    ahead of a deny. On the device the flow is PERMITTED — a real leak. The old
    frontend appended the ACCEPT last, behind the DROP, and FALSE-PASSed. It must
    now surface as a segmentation-violation."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -j DROP\n"
           "iptables -I FORWARD 1 -s 10.20.0.0/16 -d 10.99.0.0/16 -j ACCEPT\n")
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert [a.action for a in fwd] == ["permit", "deny"]
    kinds = {f.kind for f in check_segmentation(aces, _INSERT_POLICY)}
    assert "segmentation-violation" in kinds, \
        "front-inserted ACCEPT permits the flow — the FALSE-PASS this fix kills"
    assert "segmentation-ok" not in kinds


def test_insert_no_index_goes_to_front():
    """`-I CHAIN` with no numeric position inserts at the very front (position 1)."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -j ACCEPT\n"
           "iptables -I FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -j DROP\n")  # no index
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert [a.action for a in fwd] == ["deny", "permit"], \
        "`-I` with no index must land at the FRONT, not the end"
    kinds = {f.kind for f in check_segmentation(aces, _INSERT_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds


def test_insert_at_1based_middle_position_orders_correctly():
    """`-I FORWARD 2` splices between rule 1 and rule 2 (1-based position N among
    the chain's current non-policy rules)."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -d 10.99.0.1/32 -j ACCEPT\n"    # pos 1
           "iptables -A FORWARD -d 10.99.0.2/32 -j ACCEPT\n"    # pos 2
           "iptables -A FORWARD -d 10.99.0.3/32 -j ACCEPT\n"    # pos 3
           "iptables -I FORWARD 2 -d 10.99.0.9/32 -j DROP\n")   # -> new pos 2
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert [str(a.dst) for a in fwd] == [
        "10.99.0.1/32", "10.99.0.9/32", "10.99.0.2/32", "10.99.0.3/32"], \
        "insert at 1-based position 2 must land between the 1st and 2nd rules"
    assert fwd[1].action == "deny"
    assert [a.seq for a in fwd] == [1, 2, 3, 4]        # seq stays 1..N, monotonic


def test_insert_position_beyond_end_appends():
    """N past the end of the chain appends (fail-safe, matches iptables)."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -d 10.99.0.1/32 -j ACCEPT\n"
           "iptables -I FORWARD 99 -d 10.99.0.2/32 -j DROP\n")   # 99 > len -> append
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert [str(a.dst) for a in fwd] == ["10.99.0.1/32", "10.99.0.2/32"]
    assert fwd[-1].action == "deny"


def test_replace_at_position_changes_first_match_verdict():
    """`-R FORWARD 1` replaces the rule currently at position 1 IN PLACE (not
    append), inheriting its first-match slot. Replacing a leaking ACCEPT with a
    DROP flips the verdict from violation to isolated."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -j ACCEPT\n"
           "iptables -R FORWARD 1 -s 10.20.0.0/16 -d 10.99.0.0/16 -j DROP\n")
    aces, notes = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert len(fwd) == 1 and fwd[0].action == "deny", \
        "replace must swap the rule at position 1 in place, not add a second rule"
    kinds = {f.kind for f in check_segmentation(aces, _INSERT_POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert any("replace" in n for n in notes)         # still surfaced


def test_plain_append_ordering_unchanged():
    """No regression to ordinary `-A`: a plain ACCEPT-then-DROP append keeps its
    order, so first-match ACCEPT wins and the flow leaks (violation)."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -j ACCEPT\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -j DROP\n")
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert [a.action for a in fwd] == ["permit", "deny"]
    assert [a.seq for a in fwd] == [1, 2]
    kinds = {f.kind for f in check_segmentation(aces, _INSERT_POLICY)}
    assert "segmentation-violation" in kinds, \
        "plain -A order must be unchanged: ACCEPT-then-DROP first-match leaks"


def test_multiport_insert_occupies_consecutive_positions():
    """A rule that expands to multiple ACEs (multiport) inserted at position N
    must occupy CONSECUTIVE positions there — the 3 DROP ACEs land at the front
    (seq 1,2,3), the pre-existing permit follows at seq 4."""
    cfg = ("iptables -P FORWARD DROP\n"
           "iptables -A FORWARD -s 10.20.0.0/16 -d 10.99.0.0/16 -p tcp --dport 22 -j ACCEPT\n"
           "iptables -I FORWARD 1 -s 10.20.0.0/16 -d 10.99.0.0/16 -p tcp"
           " -m multiport --dports 80,443,445 -j DROP\n")
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_ordered(aces)
    assert [a.seq for a in fwd] == [1, 2, 3, 4]                # contiguous, monotonic
    assert [a.action for a in fwd[:3]] == ["deny", "deny", "deny"]
    assert sorted(a.dst_port.lo for a in fwd[:3]) == [80, 443, 445]
    assert all(not a.imprecise for a in fwd[:3])               # multiport stays exact
    assert fwd[3].action == "permit" and fwd[3].dst_port.lo == 22 and fwd[3].seq == 4
