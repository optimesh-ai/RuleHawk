"""Infoblox / ISC BIND named.conf DNS client-ACL frontend.

The parser models ONLY the DNS client access-control (reach-the-resolver) layer:
which client networks may query / transfer from the DNS service on 53. It emits
the same `(List[ACE], notes)` IR as the other frontends, so the existing
`segcheck` engine consumes it unchanged. These tests pin the properties the
task requires:
  1. detect      — fires on named.conf-style DNS-ACL text, never on
     Cisco / iptables / Fortinet / JSON;
  2. mapping     — an address-match-list maps to ordered first-match permit/deny
     ACEs (two per member: udp/53 + tcp/53, dst = ANY resolver);
  3. value       — a permitted client provably reaches DNS on 53 (must_reach ok);
     a client outside the allow-list is provably isolated (must_not_reach ok);
  4. exactness   — a negated `!subnet` member (placed first) EXACTLY denies that
     subnet while the surrounding range stays permitted — BIND lists are ordered,
     so this is exact, NOT imprecise;
  5. soundness   — `allow-transfer { none; }` denies everyone; an undefined acl
     reference and `localnets` widen to imprecise -> segcheck indeterminate,
     never a false PASS.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_infoblox import detect, parse_infoblox  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# A named.conf-style DNS-ACL config in the target format.
_CFG = """
acl "trusted" {
    10.20.0.0/16;
    10.50.0.0/16;
    localhost;
};
acl "dmz" { 203.0.113.0/24; };
options {
    allow-query { trusted; localnets; };
    allow-recursion { trusted; };
    allow-transfer { none; };
};
view "internal" {
    match-clients { trusted; };
    allow-query { any; };
};
"""

_DNS = ["10.0.0.53/32"]   # the resolver zone (dst is ANY in the model, so any CIDR works)


def _run(cfg, policy):
    aces, _ = parse_infoblox(cfg)
    return [(f.kind, f.severity) for f in check_segmentation(aces, policy)]


# ── 1. detect ────────────────────────────────────────────────────────────────

def test_detect_true_on_named_conf_and_bare_access_statement():
    assert detect(_CFG) is True
    # An access statement with an inline list is enough (plain ISC BIND too).
    assert detect('options { allow-query { 10.0.0.0/8; }; };') is True
    assert detect('view "v" {\n  match-clients { 10.1.0.0/16; };\n};') is True


def test_detect_false_on_other_vendors_and_json():
    cisco = "ip access-list extended A\n permit tcp any any eq 443\n"
    iptables = "*filter\n-A INPUT -p tcp --dport 53 -j ACCEPT\nCOMMIT\n"
    fortinet = ('config firewall policy\n    edit 1\n'
                '        set srcaddr "all"\n    next\nend\n')
    js = '{"rules": [{"src": "10.0.0.0/8", "action": "allow"}]}\n'
    junos = "firewall { family inet { filter F { term T { then accept; } } } }\n"
    for other in (cisco, iptables, fortinet, js, junos):
        assert detect(other) is False


# ── 2. address-match-list -> ordered first-match ACEs (two per member) ────────

def test_matchlist_maps_to_udp_and_tcp_permits_to_any_resolver():
    aces, _ = parse_infoblox('options { allow-query { 10.20.0.0/16; }; };')
    ctx = [a for a in aces if a.acl == "global:allow-query"]
    permits = [a for a in ctx if a.action == "permit"]
    # One member -> exactly a udp/53 and a tcp/53 ACE.
    assert {a.proto for a in permits} == {"udp", "tcp"}
    for a in permits:
        assert str(a.src) == "10.20.0.0/16"
        assert a.dst.prefixlen == 0                 # dst = ANY resolver (superset)
        assert a.dst_port.lo == 53 and a.dst_port.hi == 53
        assert a.imprecise is False
    # BIND deny-if-unmatched is present as a trailing default deny.
    assert any(a.action == "deny" and a.dst.prefixlen == 0 for a in ctx)
    # One context per statement, named "<view or global>:<statement>".
    assert {a.acl for a in aces} == {"global:allow-query"}


def test_context_named_per_view_and_statement():
    aces, _ = parse_infoblox(_CFG)
    ctxs = {a.acl for a in aces}
    assert "internal:allow-query" in ctxs        # per-view statement
    assert "internal:match-clients" in ctxs
    assert "global:allow-recursion" in ctxs      # options-scope statement


# ── 3. value: connectivity proof + isolation proof ───────────────────────────

def test_allowed_client_provably_reaches_dns_on_53():
    cfg = ('acl "corp" { 10.30.0.0/16; };\n'
           'options { allow-query { corp; }; };\n')
    pol_udp = {"zones": {"CORP": ["10.30.0.0/16"], "DNS": _DNS},
               "must_reach": [{"src": "CORP", "dst": "DNS",
                               "proto": "udp", "ports": [53]}]}
    pol_tcp = {"zones": {"CORP": ["10.30.0.0/16"], "DNS": _DNS},
               "must_reach": [{"src": "CORP", "dst": "DNS",
                               "proto": "tcp", "ports": [53]}]}
    assert _run(cfg, pol_udp) == [("connectivity-ok", "info")]
    assert _run(cfg, pol_tcp) == [("connectivity-ok", "info")]   # DNS uses both


def test_client_outside_allowlist_is_provably_isolated():
    cfg = ('acl "corp" { 10.30.0.0/16; };\n'
           'options { allow-query { corp; }; allow-recursion { corp; }; };\n')
    pol = {"zones": {"GUEST": ["192.168.0.0/16"], "DNS": _DNS},
           "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                               "proto": "udp", "ports": [53]}]}
    assert _run(cfg, pol) == [("segmentation-ok", "info")]


def test_allow_query_any_permits_everyone_is_a_violation():
    cfg = 'view "open" { allow-query { any; }; };'
    pol = {"zones": {"GUEST": ["192.168.0.0/16"], "DNS": _DNS},
           "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                               "proto": "udp", "ports": [53]}]}
    assert _run(cfg, pol) == [("segmentation-violation", "critical")]


# ── 4. negated member is EXACT (ordered first-match), not imprecise ───────────

# The `!` entry is placed BEFORE the covering /16 — under BIND's ordered
# first-match that denies the /24 and permits the rest of the /16.
_NEG_CFG = ('acl "corp" {\n'
            '    !10.20.99.0/24;\n'
            '    10.20.0.0/16;\n'
            '};\n'
            'options { allow-query { corp; }; };\n')


def test_negated_member_deny_ace_is_exact_not_imprecise():
    aces, _ = parse_infoblox(_NEG_CFG)
    denies = [a for a in aces if a.action == "deny"
              and str(a.src) == "10.20.99.0/24"]
    assert len(denies) == 2                         # udp/53 + tcp/53
    assert all(a.imprecise is False for a in denies)  # BIND lists are ordered
    # ...and the deny precedes the /16 permit in first-match order.
    ctx = sorted((a for a in aces if a.acl == "global:allow-query"),
                 key=lambda a: a.seq)
    first_deny = next(i for i, a in enumerate(ctx)
                      if a.action == "deny" and str(a.src) == "10.20.99.0/24")
    first_permit = next(i for i, a in enumerate(ctx)
                        if a.action == "permit" and str(a.src) == "10.20.0.0/16")
    assert first_deny < first_permit


def test_negated_member_excludes_subnet_while_permitting_the_rest():
    # The excluded /24 is provably DENIED (isolated)...
    pol_excl = {"zones": {"EXCL": ["10.20.99.0/24"], "DNS": _DNS},
                "must_not_reach": [{"src": "EXCL", "dst": "DNS",
                                    "proto": "udp", "ports": [53]}]}
    assert _run(_NEG_CFG, pol_excl) == [("segmentation-ok", "info")]
    # ...while a different /24 inside the /16 stays PERMITTED (reachable).
    pol_rest = {"zones": {"REST": ["10.20.5.0/24"], "DNS": _DNS},
                "must_reach": [{"src": "REST", "dst": "DNS",
                                "proto": "udp", "ports": [53]}]}
    assert _run(_NEG_CFG, pol_rest) == [("connectivity-ok", "info")]


# ── 5. soundness: none denies all; unresolvables fail closed ──────────────────

def test_allow_transfer_none_denies_everyone():
    cfg = 'options { allow-transfer { none; }; };'
    pol_iso = {"zones": {"ANY": ["0.0.0.0/1"], "DNS": _DNS},
               "must_not_reach": [{"src": "ANY", "dst": "DNS",
                                   "proto": "tcp", "ports": [53]}]}
    assert _run(cfg, pol_iso) == [("segmentation-ok", "info")]     # everyone denied
    # ...and a required transfer flow is correspondingly BROKEN.
    pol_reach = {"zones": {"CORP": ["10.30.0.0/16"], "DNS": _DNS},
                 "must_reach": [{"src": "CORP", "dst": "DNS",
                                 "proto": "tcp", "ports": [53]}]}
    assert _run(cfg, pol_reach) == [("connectivity-broken", "high")]


def test_undefined_acl_reference_is_imprecise_never_false_pass():
    cfg = 'options { allow-query { nosuch_acl; }; };'
    aces, notes = parse_infoblox(cfg)
    assert any(a.imprecise for a in aces)
    assert any("undefined acl" in n.lower() for n in notes)
    pol = {"zones": {"GUEST": ["192.168.0.0/16"], "DNS": _DNS},
           "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                               "proto": "udp", "ports": [53]}]}
    # Fail-closed: indeterminate, NOT a (false) segmentation-ok PASS.
    assert _run(cfg, pol) == [("segmentation-indeterminate", "medium")]


def test_localnets_is_imprecise():
    cfg = 'options { allow-query { localnets; }; };'
    aces, notes = parse_infoblox(cfg)
    assert any(a.imprecise for a in aces)
    assert any("localnets" in n and "imprecise" in n for n in notes)
    pol = {"zones": {"GUEST": ["192.168.0.0/16"], "DNS": _DNS},
           "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                               "proto": "udp", "ports": [53]}]}
    assert _run(cfg, pol) == [("segmentation-indeterminate", "medium")]


# ── robustness: malformed input degrades, never crashes ───────────────────────

def test_unbalanced_braces_degrade_with_a_note_never_crash():
    truncated = 'options {\n  allow-query { 10.0.0.0/8;\n'   # missing closes
    aces, notes = parse_infoblox(truncated)                 # must not raise
    assert any("truncat" in n.lower() or "unbalanced" in n.lower() for n in notes)


def test_non_acl_bind_config_is_ignored_not_crashed():
    cfg = ('zone "example.com" { type master; file "db.example"; };\n'
           'logging { channel c { file "log"; }; };\n'
           'options { allow-query { 10.0.0.0/8; }; };\n')
    aces, _ = parse_infoblox(cfg)
    # Only the access statement is modeled; the zone/logging blocks are ignored.
    assert {a.acl for a in aces} == {"global:allow-query"}
