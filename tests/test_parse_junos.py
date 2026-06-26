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
