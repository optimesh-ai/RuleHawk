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


# ── Confirmed-bug regressions (parser contract: SUPERSET, never subset) ────────
# model.py: an ACE's modeled space must be a superset of the rule's true match
# space; imprecise=True never excuses a subset (segcheck checks containment
# before imprecise). Each test below pins one confirmed subset-emission /
# widening bug (J1, J2, J7, J8, J9, J10, J-MAXEXPAND, J-ADDRS).


def test_tcp_flags_permit_visible_to_witness_search():
    # J1: `tcp-flags syn` matches NEW-flow SYNs. Modeling it stateful hid the
    # permit from the segmentation witness search -> FALSE PASS on the leak.
    cfg = """
    firewall { family inet { filter F {
        term SYNLEAK {
            from {
                source-address 10.20.0.0/16;
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 445;
                tcp-flags syn;
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].stateful is False        # stateful would hide it from the search
    assert aces[0].imprecise is True        # flag restriction over-approximated
    assert any("tcp-flags" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-ok" not in kinds   # never a false PASS


def test_tcp_established_still_stateful_tcp_initial_not():
    # J1: only tcp-established is return-traffic-only; tcp-initial can match new
    # flows and must be over-approximated instead.
    est = ("firewall { family inet { filter F { term R "
           "{ from { protocol tcp; tcp-established; } then accept; } } } }")
    ini = ("firewall { family inet { filter F { term I "
           "{ from { protocol tcp; tcp-initial; } then accept; } } } }")
    a_est, _ = parse_junos(est)
    a_ini, _ = parse_junos(ini)
    assert a_est[0].stateful is True
    assert a_ini[0].stateful is False and a_ini[0].imprecise is True


def test_inactive_term_is_not_enforced():
    # J2: a deactivated (`inactive:`) deny is NOT enforced — parsing it let it
    # block the witness and FALSE-PASS while the live accept leaks the flow.
    cfg = """
    firewall { family inet { filter F {
        inactive: term BLOCK {
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
    aces, notes = parse_junos(cfg)
    assert all("BLOCK" not in a.raw for a in aces)      # inactive term absent
    assert any("inactive" in n and "BLOCK" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-violation" in kinds
    assert "segmentation-ok" not in kinds


def test_inactive_filter_is_not_enforced():
    # J2: `inactive:` on a whole filter deactivates every term in it.
    cfg = """
    firewall { family inet {
        inactive: filter DEAD { term T { then accept; } }
    } }
    """
    aces, notes = parse_junos(cfg)
    assert aces == []
    assert any("inactive" in n and "DEAD" in n for n in notes)


def test_bare_ipv6_address_is_host_route_not_slash32():
    # J7: a bare v6 address was widened to f"{v}/32" (2001:db8::/32 — ~4e9x too
    # wide, imprecise=False), colliding distinct hosts -> false-critical
    # deny-dead. ip_network() yields the /128 host route.
    cfg = """
    firewall { family inet6 { filter F6 {
        term A { from { destination-address 2001:db8::5; next-header tcp;
                        destination-port 443; } then accept; }
        term B { from { destination-address 2001:db8::6; next-header tcp;
                        destination-port 443; } then discard; }
    } } }
    """
    aces, _ = parse_junos(cfg)
    assert str(aces[0].dst) == "2001:db8::5/128"
    assert str(aces[1].dst) == "2001:db8::6/128"
    assert all(a.imprecise is False for a in aces)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds    # distinct hosts, no cover


def test_ports_on_unported_protocol_widen_and_flag():
    # J8: ports on a protocol covers() doesn't compare were dropped with
    # imprecise=False — the ACE then claimed an exact ALL-ports space.
    cfg = """
    firewall { family inet { filter F {
        term T { from { protocol gre; destination-port 445; } then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].dst_port.is_any()
    assert aces[0].imprecise is True
    assert any("non-port-carrying" in n for n in notes)


def test_ports_with_omitted_protocol_widen_and_flag():
    # J8: no `protocol` match -> proto "ip" (unported) — same widening + flag.
    cfg = """
    firewall { family inet { filter F {
        term T { from { destination-port 445; } then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert aces[0].proto == "ip" and aces[0].dst_port.is_any()
    assert aces[0].imprecise is True


def test_sctp_ports_kept_exact_disjoint_deny_stays_live():
    # J8: sctp is port-carrying in the model (covers() compares its ports), so
    # sctp ports stay EXACT — a permit on 5000 can't kill a later deny on 132.
    cfg = """
    firewall { family inet { filter F {
        term A { from { protocol sctp; destination-port 5000; } then accept; }
        term B { from { protocol sctp; destination-port 132; } then discard; }
    } } }
    """
    aces, _ = parse_junos(cfg)
    assert [str(a.dst_port) for a in aces] == ["5000", "132"]
    assert all(a.imprecise is False for a in aces)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds


def test_hyphenated_named_ports_parse_whole_token():
    # J9: `ftp-data` is port 20 — the lo-hi split ran first and misparsed every
    # hyphenated service name in _NAMED_PORTS.
    cfg = """
    firewall { family inet { filter F {
        term T { from { protocol tcp;
                        destination-port [ ftp-data netbios-ssn microsoft-ds ]; }
                 then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert {a.dst_port.lo for a in aces} == {20, 139, 445}
    assert all(a.dst_port.lo == a.dst_port.hi for a in aces)
    assert all(a.imprecise is False for a in aces)
    assert notes == []


def test_bracket_list_named_port_deny_stays_live():
    # J9 end-to-end: a deny on [ ftp-data 80 ] was silently narrowed (ftp-data
    # skipped, imprecise) -> the live deny turned into a false alarm instead of
    # a clean PASS on the port-20 assertion, and analyze had a covered subset.
    cfg = """
    firewall { family inet { filter F {
        term WEB { from { protocol tcp; destination-port 443; } then accept; }
        term BLOCK {
            from {
                source-address 10.20.0.0/16;
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port [ ftp-data 80 ];
            }
            then discard;
        }
        term ALL { then accept; }
    } } }
    """
    aces, _ = parse_junos(cfg)
    denies = [a for a in aces if a.action == "deny"]
    assert {a.dst_port.lo for a in denies} == {20, 80}    # exact, both members
    assert all(a.imprecise is False for a in denies)
    kinds = {f.kind for f in _analyze_aces(aces)}
    assert "intent-inversion-deny-dead" not in kinds      # deny is live
    pol = {"zones": _POLICY["zones"],
           "must_not_reach": [{"src": "CORP", "dst": "PCI",
                               "proto": "tcp", "ports": [20]}]}
    kinds = {f.kind for f in check_segmentation(aces, pol)}
    assert kinds == {"segmentation-ok"}                   # deny blocks port 20


def test_unparseable_port_in_list_widens_dimension_to_any():
    # J9: an unparseable VALUE inside a list must widen the whole dimension to
    # ANY (superset), never just drop the member (subset).
    cfg = """
    firewall { family inet { filter F {
        term T { from { protocol tcp; destination-port [ bogus-svc 80 ]; }
                 then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].dst_port.is_any()
    assert aces[0].imprecise is True
    assert any("bogus-svc" in n and "ANY" in n for n in notes)


def test_except_prefix_never_in_match_space():
    # J10: an `except` prefix is EXCLUDED from the match — emitting it as
    # positive matched space inverted the semantics. The non-except remainder
    # (exclusion un-subtracted) is the sound superset, marked imprecise.
    cfg = """
    firewall { family inet { filter F {
        term T {
            from {
                source-address {
                    10.0.0.0/8;
                    10.1.0.0/16 except;
                }
                destination-address 10.10.0.0/16;
                protocol tcp;
                destination-port 445;
            }
            then accept;
        }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert {str(a.src) for a in aces} == {"10.0.0.0/8"}   # excluded prefix absent
    assert all(a.imprecise for a in aces)
    assert any("except" in n and "excluded" in n for n in notes)
    assert not any("kept the broader prefix" in n for n in notes)


def test_unparseable_address_in_list_widens_dimension_to_any():
    # J-ADDRS: an unparseable address inside a list must widen the whole
    # dimension to ANY (superset), never just drop the member (subset).
    cfg = """
    firewall { family inet { filter F {
        term T { from { source-address { 10.0.0.0/8; not-an-ip; }
                        protocol tcp; destination-port 80; } then accept; }
    } } }
    """
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].src_any                  # whole dimension widened
    assert aces[0].imprecise is True
    assert any("not-an-ip" in n and "ANY" in n for n in notes)


def test_max_expand_widens_to_any_never_truncates():
    # J-MAXEXPAND: >_MAX_EXPAND expansions used to keep only the FIRST value per
    # dimension — the forbidden source (a later member) vanished -> FALSE PASS.
    # Now the term becomes one all-ANY imprecise ACE: indeterminate, never PASS.
    members = [f"198.18.{i // 250}.{i % 250 + 1}" for i in range(299)]
    members.append("10.20.0.0/16")          # the forbidden source, last
    body = " ".join(f"{m};" for m in members)
    cfg = ("firewall { family inet { filter BIG { term T { from { "
           "source-address { " + body + " } "
           "destination-address 10.10.0.0/16; protocol tcp; "
           "destination-port 445; } then accept; } } } }")
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].src_any and aces[0].imprecise is True
    assert any("widened" in n for n in notes)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-ok" not in kinds
