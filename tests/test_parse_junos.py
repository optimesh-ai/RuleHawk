"""Juniper Junos firewall-filter frontend (RH-3).

The Junos parser emits the same `(List[ACE], notes)` IR as the Cisco parser, so
the existing analysis/segmentation engine consumes it unchanged. These tests pin:
  1. happy path — a real-shaped brace-form filter maps to the right ACEs;
  2. discipline — every unmodeled construct is SURFACED as a note, never dropped,
     while the rule itself is still parsed (or honestly skipped with a note);
  3. value — a Junos sample produces a concrete segmentation violation, and an
     earlier discard term blocks the flow with no false alarm.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import analyze, parse_junos  # noqa: E402
from rulehawk.parse_junos import detect  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# A real-shaped Junos filter: web allowed CORP->PCI, an explicit block of the
# sensitive ports, then a default discard.
_FILTER = """
firewall {
    family inet {
        filter PCI-EDGE {
            term ALLOW-WEB {
                from {
                    source-address {
                        10.20.0.0/16;
                    }
                    destination-address {
                        10.10.0.0/16;
                    }
                    protocol tcp;
                    destination-port [ 80 443 ];
                }
                then {
                    count web;
                    accept;
                }
            }
            term DEFAULT {
                then {
                    discard;
                }
            }
        }
    }
}
"""


def test_detect_routes_junos_not_cisco():
    assert detect(_FILTER) is True
    cisco = "ip access-list extended A\n permit tcp any any eq 443\n"
    assert detect(cisco) is False


def test_happy_path_maps_terms_to_aces():
    aces, notes = parse_junos(_FILTER)
    # ALLOW-WEB expands over its two destination-ports (union) -> 2 ACEs, plus the
    # default discard -> 3 ACEs total. The `count` modifier is ignored cleanly.
    assert len(aces) == 3
    permits = [a for a in aces if a.action == "permit"]
    denies = [a for a in aces if a.action == "deny"]
    assert len(permits) == 2 and len(denies) == 1
    for a in permits:
        assert a.proto == "tcp"
        assert str(a.src) == "10.20.0.0/16" and str(a.dst) == "10.10.0.0/16"
        assert a.dst_port.lo == a.dst_port.hi  # a single concrete port each
    assert {a.dst_port.lo for a in permits} == {80, 443}
    # default term has no `from` -> matches everything (deny ip any any).
    d = denies[0]
    assert d.src_any and d.dst_any and d.proto == "ip"
    # `count web` is a benign modifier — it must not produce a parse note.
    assert not any("count" in n for n in notes)


def test_unmodeled_match_is_surfaced_not_dropped():
    # `application` and `tcp-flags` are not modeled — they MUST be surfaced as
    # notes, and the rule must still be parsed (marked imprecise), never silently
    # dropped (a dropped rule would be an invisible hole in the audit).
    cfg = """
    firewall { family inet { filter F {
        term T {
            from {
                source-address 10.0.0.0/8;
                destination-address 10.10.0.0/16;
                application junos-http;
                tcp-flags "(syn & !ack)";
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1                       # rule kept, not dropped
    assert aces[0].imprecise is True            # over-approximated, can't prove deadness
    assert any("application" in n for n in notes)
    assert any("tcp-flags" in n.lower() for n in notes)


def test_unknown_then_action_is_surfaced():
    cfg = """
    firewall { family inet { filter F {
        term T { from { protocol tcp; } then { frobnicate; accept; } }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1 and aces[0].action == "permit"
    assert any("frobnicate" in n for n in notes)


def test_set_format_is_surfaced_not_silent():
    setcfg = ("set firewall family inet filter F term T from destination-port 445\n"
              "set firewall family inet filter F term T then discard\n")
    aces, notes = parse_junos(setcfg)
    assert aces == []
    assert any("set" in n.lower() and "show configuration" in n for n in notes)


_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def test_segmentation_violation_on_junos_sample():
    # A Junos filter that permits CORP->PCI on 445 is a concrete segmentation
    # violation with an auditor-grade witness packet.
    cfg = """
    firewall { family inet { filter LEAK {
        term BAD {
            from {
                source-address 10.20.0.0/16;
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 445;
            }
            then accept;
        }
    } } }
    """
    aces, _ = parse_junos(cfg)
    findings = check_segmentation(aces, _POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    assert "10.20" in viol[0].message and "10.10" in viol[0].message
    assert ":445" in viol[0].witness


def test_earlier_discard_blocks_no_false_alarm():
    # The forbidden flow is discarded before the broad accept -> PASS, not a
    # violation (first-match semantics honored, same as the Cisco path).
    cfg = """
    firewall { family inet { filter SAFE {
        term BLOCK {
            from {
                source-address 10.20.0.0/16;
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 445;
            }
            then discard;
        }
        term ALLOW-ALL { then accept; }
    } } }
    """
    aces, _ = parse_junos(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_default_accept_flagged_overly_permissive():
    # A filter ending in `then accept` with no match = permit ip any any.
    cfg = "firewall { family inet { filter F { term ANY { then accept; } } } }"
    aces, _ = parse_junos(cfg)
    kinds = {f.kind for f in analyze(aces)}
    assert "permit-any-any" in kinds


# ── RH-3 soundness regression (verifier-found false-CRITICAL) ──────────────────
# When a port/address VALUE fails to parse, the dimension must NOT silently widen
# to ANY with imprecise=False: an all-unparsed permit would then COVER a later
# deny and emit a false CRITICAL "intent-inversion-deny-dead". The fix flips
# imprecise on any unparsed value so the rule can never prove another rule dead.
from rulehawk.analyze import analyze as _analyze_aces  # noqa: E402


def test_unparsed_port_value_marks_imprecise_not_silent_any():
    cfg = """
    firewall { family inet { filter F {
        term ALLOW { from { protocol tcp; destination-port totally-bogus-svc; } then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    a = aces[0]
    # dimension fell back to ANY (no parsable port) ...
    assert a.dst_port.is_any()
    # ... but MUST be flagged imprecise so it can never prove deadness.
    assert a.imprecise is True
    assert any("totally-bogus-svc" in n and "imprecise" in n for n in notes)


def test_unparsed_address_value_marks_imprecise():
    cfg = """
    firewall { family inet { filter F {
        term ALLOW { from { source-address not-an-ip; protocol tcp; destination-port 80; } then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].src_any           # widened to ANY src
    assert aces[0].imprecise is True
    assert any("not-an-ip" in n and "imprecise" in n for n in notes)


# ── apply-groups inside a filter must never become an invisible hole ──────────
# Junos configuration groups inject inherited terms (BEFORE local terms) that a
# pasted snippet does not show. Before the fix, `apply-groups G;` in a filter
# body was silently skipped: the missing inherited permit fell to the implicit
# default deny and segcheck printed PASS for a flow the device actually allows —
# a false PASS with zero notes. The fix: note + one leading opaque ACE (permit
# ip any->any, imprecise) so evaluation is INDETERMINATE, never default-deny.

_APPLY_GROUPS_FILTER = """
firewall { family inet { filter PCI-EDGE {
    apply-groups SEC-BOILERPLATE;
    term DEFAULT { then discard; }
} } }
"""


def test_apply_groups_in_filter_injects_leading_opaque_ace():
    aces, notes = parse_junos(_APPLY_GROUPS_FILTER)
    assert len(aces) == 2
    opaque = aces[0]                       # inherited terms precede local terms
    assert opaque.seq == 1
    assert opaque.action == "permit" and opaque.proto == "ip"
    assert opaque.src_any and opaque.dst_any
    assert opaque.imprecise is True
    assert "apply-groups" in opaque.raw
    assert aces[1].action == "deny"        # the literal DEFAULT term still parses
    assert any("apply-groups" in n and "SEC-BOILERPLATE" in n for n in notes)


def test_apply_groups_filter_yields_indeterminate_not_false_pass():
    # The trust-breaking case: only literal term is a discard, so pre-fix the
    # forbidden flow fell to default deny -> PASS. It must now be indeterminate.
    aces, _ = parse_junos(_APPLY_GROUPS_FILTER)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-indeterminate" in kinds
    assert "segmentation-ok" not in kinds, (
        "a filter with apply-groups (invisible inherited terms) must never "
        "PASS a segmentation assertion")
    assert "segmentation-violation" not in kinds  # opaque never proves a leak


def test_apply_groups_opaque_never_proves_deadness_or_any_any():
    # The injected opaque ACE is imprecise: it must not shadow the literal terms
    # (no intent-inversion) and must not fire permit-any-any on itself.
    aces, _ = parse_junos(_APPLY_GROUPS_FILTER)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds
    assert "permit-any-any" not in kinds


def test_apply_groups_except_in_filter_also_fails_closed():
    cfg = """
    firewall { family inet { filter F {
        apply-groups-except [ G1 G2 ];
        term DEFAULT { then discard; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert aces[0].imprecise is True and aces[0].src_any and aces[0].dst_any
    assert any("apply-groups-except" in n and "G1 G2" in n for n in notes)


def test_top_level_apply_groups_is_surfaced_as_note_only():
    # apply-groups OUTSIDE a filter body (the ubiquitous top-of-config form)
    # can't be attributed to one filter: it is surfaced as a note, and the
    # literal filters keep their exact model (no opaque ACE injected).
    cfg = """
    apply-groups [ re0 re1 ];
    firewall { family inet { filter F {
        term BLOCK { from { protocol tcp; destination-port 445; } then discard; }
        term DEFAULT { then discard; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 2                       # no opaque ACE injected
    assert all(a.imprecise is False for a in aces)
    assert any("apply-groups re0 re1" in n and "outside a filter body" in n
               for n in notes)


def test_harmless_filter_statement_skipped_without_note():
    cfg = """
    firewall { family inet { filter F {
        interface-specific;
        term T { from { protocol tcp; destination-port 22; } then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1 and aces[0].action == "permit"
    assert not any("interface-specific" in n for n in notes)


def test_unknown_filter_statement_gets_note_terms_still_parse():
    cfg = """
    firewall { family inet { filter F {
        frobnicate-mode strict;
        term T { from { protocol tcp; destination-port 22; } then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1 and aces[0].action == "permit"
    assert aces[0].imprecise is False           # note-only; term model stays exact
    assert any("frobnicate-mode" in n for n in notes)


def test_inactive_term_is_skipped_with_note():
    # `inactive: term X` is NOT evaluated on the device — modeling it as live
    # (the old token-skip behavior) could let a deactivated deny falsely block
    # a witness. It must be skipped and surfaced.
    cfg = """
    firewall { family inet { filter F {
        inactive: term BLOCK {
            from { protocol tcp; destination-port 445; } then discard;
        }
        term ALLOW-ALL { then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1 and aces[0].action == "permit"
    assert any("inactive:" in n and "BLOCK" in n for n in notes)


# ── family inet6: v4 any-fallbacks made v6 permits invisible (false PASS) ─────
# Before the fix the parser ignored the `family` keyword: an inet6 term with a
# missing src/dst fell back to 0.0.0.0/0. Mixed IP versions never intersect
# (segcheck._intersect returns None; `v6addr in v4net` is False), so the emitted
# ACE could never match a v6 witness — real inet6 permits were INVISIBLE and
# segcheck printed PASS on assertions the device actually violates, silently
# (no note, imprecise=False). These tests pin the fail-closed v6 behavior.

_POLICY6 = {
    "zones": {"BAD6": ["2001:db8:bad::/48"], "DB6": ["2001:db8:db::/48"]},
    "must_not_reach": [{"src": "BAD6", "dst": "DB6"}],
}

_V6_LEAK = """
firewall { family inet6 { filter V6-EDGE {
    term allow-db {
        from { source-address 2001:db8:bad::/48; }
        then accept;
    }
} } }
"""


def test_inet6_missing_dst_falls_back_to_v6_any_not_v4():
    # The exact reproduction: an inet6 term with no destination-address matches
    # ALL of v6 on the device — the emitted ACE must say ::/0, not 0.0.0.0/0.
    aces, _ = parse_junos(_V6_LEAK)
    assert len(aces) == 1
    a = aces[0]
    assert str(a.src) == "2001:db8:bad::/48"
    assert a.dst.version == 6 and str(a.dst) == "::/0"
    assert a.dst_any
    assert a.imprecise is False                 # the v6 space is exact


def test_inet6_segmentation_violation_no_longer_false_passes():
    # Pre-fix: dst fell back to 0.0.0.0/0, the v6 witness never matched, and the
    # assertion PASSed while the real device permits the flow. Must be CRITICAL.
    aces, _ = parse_junos(_V6_LEAK)
    findings = check_segmentation(aces, _POLICY6)
    kinds = {f.kind for f in findings}
    assert "segmentation-ok" not in kinds, (
        "an inet6 permit the device enforces must never false-PASS a v6 "
        "segmentation assertion")
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    assert "2001:db8:bad" in viol[0].witness


def test_inet6_default_term_and_earlier_discard_still_sound():
    # An inet6 discard of the forbidden flow before a broad accept must PASS —
    # the deny fallback nets are v6 too, so first-match still blocks the witness.
    cfg = """
    firewall { family inet6 { filter SAFE6 {
        term BLOCK {
            from { source-address 2001:db8:bad::/48;
                   destination-address 2001:db8:db::/48; }
            then discard;
        }
        term ALLOW-ALL { then accept; }
    } } }
    """
    aces, _ = parse_junos(cfg)
    assert all(a.src.version == 6 and a.dst.version == 6 for a in aces)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY6)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_inet6_apply_groups_opaque_is_v6_fail_closed():
    # Pre-fix the apply-groups fail-closed opaque ACE was v4 any/any: it never
    # matched a v6 witness, so the guard failed OPEN for inet6 filters (the
    # invisible inherited permit fell to default deny -> false PASS).
    cfg = """
    firewall { family inet6 { filter PCI6 {
        apply-groups SEC-BOILERPLATE;
        term DEFAULT { then discard; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    opaque = aces[0]
    assert opaque.imprecise is True
    assert opaque.src.version == 6 and str(opaque.src) == "::/0"
    assert opaque.dst.version == 6 and str(opaque.dst) == "::/0"
    kinds = {f.kind for f in check_segmentation(aces, _POLICY6)}
    assert "segmentation-indeterminate" in kinds
    assert "segmentation-ok" not in kinds
    assert any("apply-groups" in n for n in notes)


def test_inet6_unresolved_remainder_opaque_is_v6():
    # Partial precision in an inet6 filter: the opaque remainder for the
    # unresolved named address must be ::/0 (a v4 remainder can never keep a
    # v6 assertion indeterminate — it would fail open).
    cfg = """
    firewall { family inet6 { filter F6 {
        term T {
            from {
                source-address { 2001:db8:bad::/48; web-servers-v6; }
                destination-address 2001:db8:db::/48;
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 2
    exact, opaque = aces
    assert exact.imprecise is False and str(exact.src) == "2001:db8:bad::/48"
    assert opaque.imprecise is True
    assert opaque.src.version == 6 and opaque.dst.version == 6
    assert any("partially resolved" in n for n in notes)


def test_family_inferred_inet6_without_family_block():
    # A filter pasted WITHOUT its enclosing family block but holding v6
    # addresses is modeled as inet6 (fail toward the v6 any), with a note.
    cfg = """
    filter BARE6 {
        term allow { from { source-address 2001:db8:bad::/48; } then accept; }
        term DEFAULT { then discard; }
    }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 2
    assert aces[0].dst.version == 6            # allow: missing dst -> ::/0
    assert aces[1].src.version == 6            # DEFAULT: both fallbacks -> ::/0
    assert aces[1].dst.version == 6
    assert any("inet6" in n and "BARE6" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY6)}
    assert "segmentation-violation" in kinds


def test_family_less_v4_filter_behavior_unchanged():
    # Pure-v4 filter outside a family block: v4 fallbacks, no inference note.
    cfg = """
    filter BARE4 {
        term allow { from { source-address 10.20.0.0/16; } then accept; }
    }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert str(aces[0].dst) == "0.0.0.0/0"
    assert not any("inet6" in n for n in notes)


def test_one_sided_fallback_matches_the_given_sides_version():
    # Even with no family context at all per-term, the missing side must take
    # the IP version of the given side (never a cross-version dead ACE).
    cfg = """
    firewall {
        family inet6 { filter A6 {
            term t { from { destination-address 2001:db8:db::/48; } then accept; }
        } }
        family inet { filter A4 {
            term t { from { destination-address 10.10.0.0/16; } then accept; }
        } }
    }
    """
    aces, _ = parse_junos(cfg)
    by_acl = {a.acl: a for a in aces}
    assert str(by_acl["A6"].src) == "::/0"
    assert str(by_acl["A4"].src) == "0.0.0.0/0"


def test_bare_v6_host_address_is_slash_128_not_v6_slash_32():
    # A bare v6 address is a HOST match: appending the v4 "/32" would widen it
    # to a v6 /32 (2^96 addresses) — an over-approximation that could mint a
    # false CRITICAL from a permit that matches only one host.
    cfg = """
    firewall { family inet6 { filter H {
        term t { from { source-address 2001:db8:bad::1;
                        destination-address 2001:db8:db::7; } then accept; }
    } } }
    """
    aces, _ = parse_junos(cfg)
    assert len(aces) == 1
    assert str(aces[0].src) == "2001:db8:bad::1/128"
    assert str(aces[0].dst) == "2001:db8:db::7/128"


def test_unparsed_port_does_not_falsely_kill_later_deny():
    # The actual harm: an imprecise all-ANY permit must NOT prove a real later
    # deny on 445 dead. Before the fix this emitted a false CRITICAL.
    cfg = """
    firewall { family inet { filter F {
        term ALLOW { from { protocol tcp; destination-port totally-bogus-svc; } then accept; }
        term BLOCK { from { protocol tcp; destination-port 445; } then discard; }
    } } }
    """
    aces, _ = parse_junos(cfg)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds, (
        "an imprecise (unparsed-value) permit must never prove a later deny dead")
