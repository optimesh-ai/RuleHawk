"""Edge coverage for the transit custom-chain jump resolution (RH-iptables).

These tests pin the soundness guards of `_resolve_transit_jump` and the
untested dispatch paths of `parse_iptables`, all through the PUBLIC surface
(`parse_iptables` + `check_segmentation`) so mutations to the intersection
math or the fail-closed gates are caught by observable verdicts:

  1. proto intersection when the JUMP is narrow (tcp) and the CHILD is
     proto-wildcard — the resolved ACE must carry the jump's proto;
  2. disjoint src / dst address spaces — zero resolved ACEs (fall-through
     to the parent chain), never a fabricated permit/deny;
  3. an imprecise (`--match-set`) child ACE — the placeholder stays
     imprecise and segcheck fails closed to INDETERMINATE;
  4. disjoint dst-port / src-port ranges — zero resolved ACEs; partial
     overlap — the intersected range, exactly;
  5. `-I CHAIN [pos]` insert — parsed, appended at end, and the
     compensating 'insert position not modeled (verify)' note is present
     (the ONLY mitigation for the front-insert under-approximation);
  6. command-form `-t nat` — zero ACEs plus the filter-space-only note;
  7. `-N CUSTOM` declaration then a transit jump into it — resolves;
  8. shlex fallback on an unbalanced quote — the rule is kept (never a
     silent hole) and fails closed as imprecise.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_iptables import parse_iptables  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# CORP -> PCI tcp/445 is the forbidden flow throughout.
_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                        "ports": [445]}],
}


def _fwd_non_policy(aces):
    return [a for a in aces if a.acl == "FORWARD" and "policy" not in a.raw]


# ── (1) proto intersection: narrow jump proto × wildcard child ────────────────

def test_jump_proto_narrow_child_wildcard_keeps_jump_proto():
    """Jump says `-p tcp -s 10.0.0.0/8`; the child is proto-WILDCARD
    (`-d 192.168.0.0/16 -j DROP`). The resolved ACE must be the intersection:
    exactly one ACE, proto tcp (the jump's), src 10/8 (the jump's), dst
    192.168/16 (the child's). Picking the child's wildcard proto instead would
    over-widen a resolved permit in the mirrored case — wrong verdicts."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":ZF - [0:0]\n"
        "-A FORWARD -p tcp -s 10.0.0.0/8 -j ZF\n"
        "-A ZF -d 192.168.0.0/16 -j DROP\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1, "exactly one resolved ACE expected"
    ace = fwd[0]
    assert ace.action == "deny"
    assert ace.proto == "tcp", "resolved proto must be the jump's tcp, not wildcard"
    assert str(ace.src) == "10.0.0.0/8"
    assert str(ace.dst) == "192.168.0.0/16"
    assert ace.src_port.is_any() and ace.dst_port.is_any()
    assert ace.imprecise is False and ace.transit is True
    assert any("resolved precisely" in n and "ZF" in n for n in notes)


def test_jump_nonported_proto_child_wildcard_any_ports():
    """Non-ported protocol (icmp) through a wildcard child: the resolved ACE
    must fall back to ANY ports (the else arm of the port intersection), and
    carry proto icmp."""
    cfg = (
        "*filter\n"
        ":FORWARD ACCEPT [0:0]\n"
        ":ICMPCTL - [0:0]\n"
        "-A FORWARD -p icmp -s 10.20.0.0/16 -d 10.10.0.0/16 -j ICMPCTL\n"
        "-A ICMPCTL -j DROP\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1
    ace = fwd[0]
    assert ace.action == "deny" and ace.proto == "icmp"
    assert ace.src_port.is_any() and ace.dst_port.is_any()
    assert ace.imprecise is False
    assert any("resolved precisely" in n and "ICMPCTL" in n for n in notes)


def test_jump_narrow_proto_prunes_disjoint_proto_child():
    """A `-p tcp` jump into a chain holding BOTH a udp child and a tcp child:
    the udp child must be pruned at the disjoint-protocol branch (neither the
    jump proto nor the child proto is a wildcard, and they differ), so exactly
    ONE FORWARD ACE resolves — the tcp child's — and NOTHING derived from the
    udp rule. If that pruning branch fell through instead of dropping the child,
    the udp rule would be injected into FORWARD as a spurious TCP ACE, corrupting
    the first-match stream segcheck/shadow analysis evaluate → false verdicts."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":SEG - [0:0]\n"
        "-A FORWARD -p tcp -j SEG\n"
        "-A SEG -p udp -d 10.10.0.0/16 -j ACCEPT\n"
        "-A SEG -p tcp -d 10.20.0.0/16 --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1, "only the tcp child survives; the udp child is pruned"
    ace = fwd[0]
    # The one surviving ACE is the tcp child — never a proto-mismatched spurion.
    assert ace.action == "permit"
    assert ace.proto == "tcp"
    assert str(ace.dst) == "10.20.0.0/16"
    assert ace.dst_port.lo == 22 and ace.dst_port.hi == 22
    assert ace.imprecise is False and ace.transit is True
    # Zero ACEs may carry the udp child's dst (10.10/16) or lack a dport — proof
    # the disjoint-proto child was dropped, not fabricated as a tcp ACE.
    assert not any(str(a.dst) == "10.10.0.0/16" for a in fwd)
    assert any("resolved precisely" in n and "SEG" in n for n in notes)


# ── (2) disjoint address spaces → zero resolved ACEs (fall-through) ───────────

def test_disjoint_src_spaces_resolve_to_zero_aces_fall_through():
    """The jump narrows src to CORP (10.20/16); the child only matches
    172.16/12 sources. Disjoint → the child can never terminate a jumped
    packet → ZERO resolved ACEs; the forbidden flow falls through to the
    FORWARD DROP policy → precise PASS. Emitting an ACE here would fabricate
    a decision for traffic the subchain never matches."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":OTHERNET - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j OTHERNET\n"
        "-A OTHERNET -s 172.16.0.0/12 -j DROP\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    assert _fwd_non_policy(aces) == [], "disjoint src must resolve to zero ACEs"
    assert any("resolved precisely" in n and "0 ACE(s)" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-indeterminate" not in kinds
    assert "segmentation-violation" not in kinds


def test_disjoint_dst_spaces_resolve_to_zero_aces():
    """Same fall-through soundness for the dst dimension: jump dst PCI
    (10.10/16), child dst 192.168/16 — disjoint → zero resolved ACEs. Here the
    child is an ACCEPT: fabricating the intersection would FALSE-FAIL (or with
    the wrong operand order FALSE-PASS) the isolation check."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":OTHERNET - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j OTHERNET\n"
        "-A OTHERNET -d 192.168.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    assert _fwd_non_policy(aces) == [], "disjoint dst must resolve to zero ACEs"
    assert any("resolved precisely" in n and "0 ACE(s)" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds


# ── (3) imprecise child ACE → placeholder stays, INDETERMINATE ────────────────

def test_imprecise_child_matchset_keeps_placeholder_indeterminate():
    """The child chain contains a `--match-set` (ipset) ACE — its space is
    over-approximated. The strictly-conjunctive gate must refuse resolution:
    the imprecise placeholder stays and segcheck yields INDETERMINATE for
    CORP->PCI:445 — never a PASS built on an over-widened subchain rule."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":BADSET - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j BADSET\n"
        "-A BADSET -m set --match-set corpset src -p tcp --dport 445 -j ACCEPT\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-indeterminate" in kinds, \
        "imprecise subchain must fail closed to INDETERMINATE"
    assert "segmentation-ok" not in kinds, \
        "must not FALSE-PASS through an over-approximated subchain"
    assert not any("resolved precisely" in n for n in notes)
    # The fail-closed placeholder is still there, imprecise, in FORWARD.
    fwd = _fwd_non_policy(aces)
    assert fwd and all(a.imprecise for a in fwd)


# ── (4) port-range intersection: disjoint → zero; overlap → exact ─────────────

def test_disjoint_dport_ranges_resolve_to_zero_aces():
    """Jump narrows to dport 445; the child only ACCEPTs dport 80. Disjoint →
    zero resolved ACEs; tcp/445 falls through to the FORWARD DROP policy →
    PASS. A wrong (non-empty) port intersection would FALSE-FAIL here."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":WEBONLY - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j WEBONLY\n"
        "-A WEBONLY -p tcp --dport 80 -j ACCEPT\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    assert _fwd_non_policy(aces) == [], "disjoint dports must resolve to zero ACEs"
    assert any("resolved precisely" in n and "0 ACE(s)" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds


def test_disjoint_sport_ranges_resolve_to_zero_aces():
    """Same for the src-port dimension: jump sport 1024:2048 vs child sport
    5000:6000 → no overlap → zero resolved ACEs."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":HIGHPORTS - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -p tcp --sport 1024:2048 -j HIGHPORTS\n"
        "-A HIGHPORTS -p tcp --sport 5000:6000 -j ACCEPT\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    assert _fwd_non_policy(aces) == [], "disjoint sports must resolve to zero ACEs"
    assert any("resolved precisely" in n and "0 ACE(s)" in n for n in notes)


def test_partial_dport_overlap_resolves_to_exact_intersection():
    """Intersection math: jump dport 400:500 × child ACCEPT dport 445:600 →
    exactly PortRange(445, 500). The range contains 445, so the isolation
    check must flag a CRITICAL violation — with the precise witness."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        ":RANGED - [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 400:500 -j RANGED\n"
        "-A RANGED -p tcp --dport 445:600 -j ACCEPT\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1
    ace = fwd[0]
    assert ace.action == "permit" and ace.proto == "tcp"
    assert (ace.dst_port.lo, ace.dst_port.hi) == (445, 500), \
        "resolved dport must be the exact range intersection"
    assert ace.imprecise is False
    findings = check_segmentation(aces, _POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    assert ":445" in viol[0].witness


# ── (5) -I insert: appended at end, compensating note pinned ──────────────────

def test_insert_with_position_parsed_and_note_present():
    """`-I FORWARD 1 ... -j DROP` — iptables inserts at the FRONT; RuleHawk
    appends at the END. The 'insert position not modeled (verify)' note is the
    ONLY mitigation for that under-approximation, so it must be pinned. The
    numeric position token must be dropped, not parsed as a match option."""
    cfg = (
        "iptables -P FORWARD ACCEPT\n"
        "iptables -I FORWARD 1 -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp"
        " --dport 445 -j DROP\n"
    )
    aces, notes = parse_iptables(cfg)
    assert any("insert" in n and "appended at end" in n
               and "insert position not modeled (verify)" in n
               for n in notes), "the compensating -I note is the only mitigation"
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1
    ace = fwd[0]
    assert ace.action == "deny" and ace.proto == "tcp"
    assert str(ace.src) == "10.20.0.0/16" and ace.dst_port.lo == 445
    assert ace.imprecise is False, "position token must not poison the parse"
    # Deny sits before the appended permit-any policy → isolation PASSes.
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-ok" in kinds
    assert "segmentation-violation" not in kinds


def test_insert_without_position_also_parsed():
    """`-I FORWARD ...` with no numeric position: nothing to drop; the rule
    must still parse into an ACE plus the same note."""
    cfg = (
        "iptables -P FORWARD DROP\n"
        "iptables -I FORWARD -s 10.20.0.0/16 -p tcp --dport 22 -j ACCEPT\n"
    )
    aces, notes = parse_iptables(cfg)
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1
    assert fwd[0].action == "permit" and fwd[0].dst_port.lo == 22
    assert str(fwd[0].src) == "10.20.0.0/16"
    assert any("insert position not modeled" in n for n in notes)


# ── (6) command-form -t nat → skipped with the filter-space-only note ─────────

def test_command_form_t_nat_rule_skipped_and_surfaced():
    """A command-form `-t nat` DNAT rule contributes ZERO ACEs (filter-space
    only) and is surfaced with a note — never a silent hole."""
    cfg = ("iptables -t nat -A PREROUTING -s 10.20.0.0/16 -p tcp --dport 80"
           " -j DNAT --to-destination 10.10.0.5\n")
    aces, notes = parse_iptables(cfg)
    assert aces == [], "nat-table command rule must emit no ACEs"
    assert any("'nat' table rule present" in n and "not modeled" in n
               and "filter-space only" in n for n in notes)


def test_command_form_t_filter_still_parses_normally():
    """The `-t` dispatch must pass `-t filter` through unchanged (the flag pair
    is consumed, the rest of the rule parses normally)."""
    cfg = (
        "iptables -P FORWARD DROP\n"
        "iptables -t filter -A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16"
        " -p tcp --dport 445 -j ACCEPT\n"
    )
    aces, _ = parse_iptables(cfg)
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1
    assert fwd[0].action == "permit" and fwd[0].dst_port.lo == 445
    findings = check_segmentation(aces, _POLICY)
    assert any(f.kind == "segmentation-violation" for f in findings)


# ── (7) -N declaration then a transit jump into it resolves ───────────────────

def test_new_chain_declaration_then_jump_resolves_precisely():
    """Command form: `-N XZONE` declares the chain, `-A XZONE ... -j ACCEPT`
    populates it, and the FORWARD jump resolves precisely → the CORP->PCI:445
    leak surfaces as a precise CRITICAL, not INDETERMINATE."""
    cfg = (
        "iptables -P FORWARD DROP\n"
        "iptables -N XZONE\n"
        "iptables -A FORWARD -s 10.20.0.0/16 -j XZONE\n"
        "iptables -A XZONE -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
    )
    aces, notes = parse_iptables(cfg)
    assert any("resolved precisely" in n and "XZONE" in n for n in notes)
    fwd = _fwd_non_policy(aces)
    assert any(a.action == "permit" and not a.imprecise and a.proto == "tcp"
               and a.dst_port.lo == 445 for a in fwd)
    findings = check_segmentation(aces, _POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    kinds = {f.kind for f in findings}
    assert "segmentation-indeterminate" not in kinds


# ── (8) shlex fallback on an unbalanced quote: kept, fail-closed ──────────────

def test_unbalanced_quote_falls_back_and_fails_closed():
    """A rule line with an unbalanced quote (a real-world `--comment "don't`)
    breaks shlex; the whitespace-split fallback must KEEP the rule (an ACCEPT
    silently dropped would be an invisible hole) and the stray comment tokens
    surface as unmodeled options → the ACE is imprecise → the segmentation
    verdict fails closed to INDETERMINATE, never a PASS."""
    cfg = (
        "*filter\n"
        ":FORWARD DROP [0:0]\n"
        "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445"
        " -j ACCEPT -m comment --comment \"don't panic\n"
        "COMMIT\n"
    )
    aces, notes = parse_iptables(cfg)
    fwd = _fwd_non_policy(aces)
    assert len(fwd) == 1, "unbalanced-quote rule must not be silently dropped"
    ace = fwd[0]
    assert ace.action == "permit" and ace.dst_port.lo == 445
    assert ace.imprecise is True, "unmodeled comment tokens must fail closed"
    assert any("unmodeled iptables option" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-ok" not in kinds, \
        "imprecise permit for the forbidden flow must not PASS"
    assert "segmentation-indeterminate" in kinds
