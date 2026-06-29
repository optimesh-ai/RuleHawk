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


def test_set_format_basic_discard():
    """set-display form: a single term with a port match and discard action."""
    setcfg = ("set firewall family inet filter F term T from destination-port 445\n"
              "set firewall family inet filter F term T then discard\n")
    aces, notes = parse_junos(setcfg)
    # Set format is now parsed — we expect one ACE (deny tcp/udp any any dport 445)
    # but the parser emits separate ACEs per protocol if protocol is not specified.
    # With no protocol, proto defaults to "ip" and ports are ignored (non-ported
    # proto), so we get one deny ip any any (imprecise — the port condition is
    # unhandled for a non-tcp/udp proto match). A note is emitted about the port
    # on a non-tcp/udp protocol.
    assert len(aces) == 1
    assert aces[0].action == "deny"


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


# ── set-display format (new in RH-3.1) ────────────────────────────────────────
# The `set firewall family inet filter F term T ...` form is the CLI output
# from `show configuration | display set`. Tests mirror the brace-form tests
# above to ensure parity: same ACE semantics, same soundness guarantees.

def test_set_format_detect():
    """detect() must fire on set-display lines and not fire on Cisco IOS."""
    from rulehawk.parse_junos import detect as _detect
    setcfg = ("set firewall family inet filter F term T from protocol tcp\n"
              "set firewall family inet filter F term T then accept\n")
    assert _detect(setcfg) is True
    cisco = "ip access-list extended A\n permit tcp any any eq 443\n"
    assert _detect(cisco) is False


def test_set_format_basic_permit_deny():
    """set-display form: permit + deny terms produce correctly typed ACEs."""
    cfg = (
        "set firewall family inet filter INGRESS-FILTER term ALLOW-SSH"
        " from source-address 10.0.0.0/8\n"
        "set firewall family inet filter INGRESS-FILTER term ALLOW-SSH"
        " from protocol tcp\n"
        "set firewall family inet filter INGRESS-FILTER term ALLOW-SSH"
        " from destination-port 22\n"
        "set firewall family inet filter INGRESS-FILTER term ALLOW-SSH"
        " then accept\n"
        "set firewall family inet filter INGRESS-FILTER term DENY-ALL"
        " then discard\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 2
    ssh = aces[0]
    assert ssh.action == "permit"
    assert ssh.proto == "tcp"
    assert str(ssh.src) == "10.0.0.0/8"
    assert ssh.dst_any
    assert ssh.dst_port.lo == ssh.dst_port.hi == 22
    deny_all = aces[1]
    assert deny_all.action == "deny"
    assert deny_all.src_any and deny_all.dst_any
    assert deny_all.proto == "ip"
    assert not notes


def test_set_format_proto_src_dst_port_mapping():
    """set-display form: all five dimensions map exactly to ACE fields."""
    cfg = (
        "set firewall family inet filter PCI-EDGE term ALLOW-WEB"
        " from source-address 10.20.0.0/16\n"
        "set firewall family inet filter PCI-EDGE term ALLOW-WEB"
        " from destination-address 10.10.0.0/16\n"
        "set firewall family inet filter PCI-EDGE term ALLOW-WEB"
        " from protocol tcp\n"
        "set firewall family inet filter PCI-EDGE term ALLOW-WEB"
        " from source-port 1024-65535\n"
        "set firewall family inet filter PCI-EDGE term ALLOW-WEB"
        " from destination-port 443\n"
        "set firewall family inet filter PCI-EDGE term ALLOW-WEB"
        " then accept\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    a = aces[0]
    assert a.action == "permit"
    assert a.proto == "tcp"
    assert str(a.src) == "10.20.0.0/16"
    assert str(a.dst) == "10.10.0.0/16"
    assert a.src_port.lo == 1024 and a.src_port.hi == 65535
    assert a.dst_port.lo == a.dst_port.hi == 443
    assert not notes


def test_set_format_multi_value_address_expands_to_union():
    """Multiple source-address lines under one term expand to one ACE per net."""
    cfg = (
        "set firewall family inet filter F term T from source-address 10.0.0.0/8\n"
        "set firewall family inet filter F term T from source-address 192.168.0.0/16\n"
        "set firewall family inet filter F term T from protocol tcp\n"
        "set firewall family inet filter F term T from destination-port 80\n"
        "set firewall family inet filter F term T then accept\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 2
    srcs = {str(a.src) for a in aces}
    assert srcs == {"10.0.0.0/8", "192.168.0.0/16"}
    assert all(a.action == "permit" for a in aces)
    assert all(a.dst_port.lo == 80 for a in aces)
    assert not notes


def test_set_format_multi_term_ordering():
    """Seq numbers must reflect term declaration order — shadowing depends on it."""
    cfg = (
        "set firewall family inet filter F term FIRST from protocol tcp\n"
        "set firewall family inet filter F term FIRST from destination-port 22\n"
        "set firewall family inet filter F term FIRST then accept\n"
        "set firewall family inet filter F term SECOND from protocol tcp\n"
        "set firewall family inet filter F term SECOND from destination-port 445\n"
        "set firewall family inet filter F term SECOND then discard\n"
        "set firewall family inet filter F term LAST then discard\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 3
    assert aces[0].seq < aces[1].seq < aces[2].seq
    assert aces[0].action == "permit" and aces[0].dst_port.lo == 22
    assert aces[1].action == "deny" and aces[1].dst_port.lo == 445
    assert aces[2].action == "deny" and aces[2].src_any and aces[2].dst_any
    assert not notes


def test_set_format_empty_from_is_match_all():
    """A term with only a `then` clause and no `from` matches everything (any/any)."""
    cfg = (
        "set firewall family inet filter F term CATCH-ALL then accept\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    a = aces[0]
    assert a.action == "permit"
    assert a.src_any and a.dst_any
    assert a.proto == "ip"
    assert a.dst_port.is_any()
    assert not notes


def test_set_format_unmodeled_match_surfaced_not_dropped():
    """An unmodeled from-key (e.g. 'application') marks the ACE imprecise and
    emits a note — the rule is NEVER silently dropped."""
    cfg = (
        "set firewall family inet filter F term T from source-address 10.0.0.0/8\n"
        "set firewall family inet filter F term T from application junos-ssh\n"
        "set firewall family inet filter F term T then accept\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1             # kept, not dropped
    assert aces[0].imprecise is True  # over-approximated, can't prove deadness
    assert any("application" in n for n in notes)


def test_set_format_reject_maps_to_deny():
    """JunOS `reject` (drop + ICMP unreachable) maps to ACE action `deny`."""
    cfg = (
        "set firewall family inet filter F term T from protocol tcp\n"
        "set firewall family inet filter F term T from destination-port 23\n"
        "set firewall family inet filter F term T then reject\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].action == "deny"


def test_set_format_multi_filter_independent_seq():
    """Two filters in the same set-format blob each start seq at 1 (per-filter)."""
    cfg = (
        "set firewall family inet filter FILTER-A term T1 from protocol tcp\n"
        "set firewall family inet filter FILTER-A term T1 from destination-port 80\n"
        "set firewall family inet filter FILTER-A term T1 then accept\n"
        "set firewall family inet filter FILTER-B term T1 from protocol tcp\n"
        "set firewall family inet filter FILTER-B term T1 from destination-port 443\n"
        "set firewall family inet filter FILTER-B term T1 then accept\n"
        "set firewall family inet filter FILTER-B term T2 then discard\n"
    )
    aces, notes = parse_junos(cfg)
    a_aces = [a for a in aces if a.acl == "FILTER-A"]
    b_aces = [a for a in aces if a.acl == "FILTER-B"]
    assert len(a_aces) == 1 and a_aces[0].seq == 1
    assert len(b_aces) == 2
    assert b_aces[0].seq == 1 and b_aces[1].seq == 2
    assert not notes


def test_set_format_segmentation_violation():
    """set-display form: a leaked CORP->PCI permit is a concrete CRITICAL finding."""
    cfg = (
        "set firewall family inet filter LEAK term BAD"
        " from source-address 10.20.0.0/16\n"
        "set firewall family inet filter LEAK term BAD"
        " from destination-address 10.10.0.0/16\n"
        "set firewall family inet filter LEAK term BAD"
        " from protocol tcp\n"
        "set firewall family inet filter LEAK term BAD"
        " from destination-port 445\n"
        "set firewall family inet filter LEAK term BAD then accept\n"
    )
    aces, _ = parse_junos(cfg)
    findings = check_segmentation(aces, _POLICY)
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol and viol[0].severity == "critical"
    assert "10.20" in viol[0].message and "10.10" in viol[0].message
    assert ":445" in viol[0].witness


def test_set_format_earlier_discard_blocks_no_false_alarm():
    """set-display form: first-match semantics — an earlier discard prevents
    a later accept from producing a false segmentation violation."""
    cfg = (
        "set firewall family inet filter SAFE term BLOCK"
        " from source-address 10.20.0.0/16\n"
        "set firewall family inet filter SAFE term BLOCK"
        " from destination-address 10.10.0.0/16\n"
        "set firewall family inet filter SAFE term BLOCK"
        " from protocol tcp\n"
        "set firewall family inet filter SAFE term BLOCK"
        " from destination-port 445\n"
        "set firewall family inet filter SAFE term BLOCK then discard\n"
        "set firewall family inet filter SAFE term ALLOW-ALL then accept\n"
    )
    aces, _ = parse_junos(cfg)
    kinds = {f.kind for f in check_segmentation(aces, _POLICY)}
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


def test_set_format_unparsed_address_marks_imprecise():
    """An unparseable address in set-format must mark the ACE imprecise — the
    dimension falls back to ANY but can never be used to prove another rule dead."""
    cfg = (
        "set firewall family inet filter F term T from source-address not-an-ip\n"
        "set firewall family inet filter F term T from protocol tcp\n"
        "set firewall family inet filter F term T from destination-port 80\n"
        "set firewall family inet filter F term T then accept\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].src_any            # widened to ANY src
    assert aces[0].imprecise is True
    assert any("not-an-ip" in n and "imprecise" in n for n in notes)


def test_set_format_unparsed_port_marks_imprecise():
    """An unparseable port in set-format must mark the ACE imprecise — falls
    back to ANY dst_port but is never used to prove a later deny dead."""
    cfg = (
        "set firewall family inet filter F term T from protocol tcp\n"
        "set firewall family inet filter F term T from destination-port totally-bogus-svc\n"
        "set firewall family inet filter F term T then accept\n"
    )
    aces, notes = parse_junos(cfg)
    assert len(aces) == 1
    assert aces[0].dst_port.is_any()
    assert aces[0].imprecise is True
    assert any("totally-bogus-svc" in n and "imprecise" in n for n in notes)
