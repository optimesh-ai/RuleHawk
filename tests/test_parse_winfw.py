"""Tests for the Windows Defender Firewall (WFAS) frontend (parse_winfw.py).

These pin the properties the frontend must guarantee:
  1. detect()      — routes netsh show-rule output, and NOT the other vendors.
  2. value         — an inbound RDP-from-Any Allow produces a dangerous-exposure
                     hygiene finding.
  3. block-first   — a Block rule is ordered before an Allow for the same packet
                     (WFAS block-precedence), so the Allow is proven dead.
  4. discipline    — a disabled rule is skipped (surfaced), every host-hook ACE
                     is transit=False, dynamic RPC ports / keyword scopes widen to
                     imprecise, a numeric port list expands to exact per-port ACEs.
  5. mapping       — inbound host = destination, outbound host = source, and the
                     LocalPort/RemotePort -> dst_port/src_port mapping is correct.
  6. soundness     — an imprecise (widened) ACE never proves another rule dead.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.model import covers  # noqa: E402
from rulehawk.parse_winfw import detect, parse_winfw  # noqa: E402


# --------------------------------------------------------------------------- #
# Canonical netsh `advfirewall firewall show rule name=all` samples.
# --------------------------------------------------------------------------- #

_RDP_FROM_ANY = """\
Rule Name:                            Allow RDP from Any
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow
"""

# An inbound Allow, a matching inbound Block, plus a disabled rule. LocalIP is a
# concrete v4 host so the family is pinned to v4 (one ACE per rule).
_BLOCK_AND_ALLOW = """\
Rule Name:                            Allow RDP
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.10
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Action:                               Allow

Rule Name:                            Block RDP
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.10
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Action:                               Block

Rule Name:                            Disabled Telnet
Enabled:                              No
Direction:                            In
LocalIP:                              10.0.0.10
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            23
RemotePort:                           Any
Action:                               Allow
"""

# Inbound rule with concrete Local/Remote IPs (host = destination).
_INBOUND_SQL = """\
Rule Name:                            Allow SQL from CORP
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.5
RemoteIP:                             10.20.0.0/16
Protocol:                             TCP
LocalPort:                            1433
RemotePort:                           Any
Action:                               Allow
"""

# Outbound rule (host = source).
_OUTBOUND_HTTPS = """\
Rule Name:                            Allow HTTPS egress
Enabled:                              Yes
Direction:                            Out
LocalIP:                              10.0.0.7
RemoteIP:                             10.20.0.0/16
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           443
Action:                               Allow
"""


def _by(aces, **kw):
    """Return the single ACE matching every kw predicate (attr==value)."""
    hits = [a for a in aces
            if all(getattr(a, k) == v for k, v in kw.items())]
    assert len(hits) == 1, f"expected 1 match for {kw}, got {len(hits)}"
    return hits[0]


# --------------------------------------------------------------------------- #
# 1. detect()
# --------------------------------------------------------------------------- #

def test_detect_true_on_netsh_output_and_command():
    assert detect(_RDP_FROM_ANY) is True
    assert detect(_BLOCK_AND_ALLOW) is True
    # The command string alone is enough.
    assert detect("netsh advfirewall firewall show rule name=all\n") is True


def test_detect_false_on_other_vendors():
    cisco = "ip access-list extended A\n permit tcp any any eq 443\n deny ip any any\n"
    iptables = ("*filter\n:INPUT DROP [0:0]\n"
                "-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    junos = ("firewall { family inet { filter F { term T { "
             "then accept; } } } }")
    panos = "set rulebase security rules r from any to any action allow\n"
    for other in (cisco, iptables, junos, panos):
        assert detect(other) is False


# --------------------------------------------------------------------------- #
# 2. value — inbound RDP from Any fires dangerous-exposure
# --------------------------------------------------------------------------- #

def test_inbound_rdp_from_any_is_dangerous_exposure():
    aces, _ = parse_winfw(_RDP_FROM_ANY)
    permits = [a for a in aces if a.action == "permit"]
    # RemoteIP Any + LocalIP Any -> both families, both src_any, dst_port 3389.
    assert permits and all(a.src_any and a.dst_port.lo == 3389 for a in permits)
    kinds = {f.kind for f in analyze(aces)}
    assert "dangerous-exposure" in kinds


# --------------------------------------------------------------------------- #
# 3. block-first ordering (WFAS block-precedence)
# --------------------------------------------------------------------------- #

def test_block_ordered_before_allow_and_kills_it():
    aces, _ = parse_winfw(_BLOCK_AND_ALLOW)
    inbound = [a for a in aces if a.acl == "Inbound"]
    deny_rdp = _by(inbound, action="deny", proto="tcp")   # the Block RDP
    permit_rdp = _by(inbound, action="permit", proto="tcp")  # the Allow RDP
    # Block-first: the deny sits at a LOWER seq than the permit for the same packet.
    assert deny_rdp.seq < permit_rdp.seq
    # ... and because the block precedes and covers the allow, analyze proves the
    # allow dead (an intent-inversion: the traffic you meant to allow is blocked).
    kinds = {f.kind for f in analyze(aces)}
    assert "intent-inversion-permit-dead" in kinds
    # The block-precedence deny is EXACT and genuinely covers the allow.
    assert covers(deny_rdp, permit_rdp)


def test_direction_default_is_trailing_deny_inbound():
    aces, _ = parse_winfw(_BLOCK_AND_ALLOW)
    inbound = sorted((a for a in aces if a.acl == "Inbound"), key=lambda a: a.seq)
    last = inbound[-1]
    # Inbound default is block -> a trailing deny ip any any.
    assert last.action == "deny" and last.proto == "ip" and last.dst_any


def test_outbound_default_is_trailing_permit():
    aces, _ = parse_winfw(_OUTBOUND_HTTPS)
    outbound = sorted((a for a in aces if a.acl == "Outbound"), key=lambda a: a.seq)
    last = outbound[-1]
    # Outbound default is allow -> a trailing permit ip any any.
    assert last.action == "permit" and last.proto == "ip" and last.src_any and last.dst_any


# --------------------------------------------------------------------------- #
# 4. discipline — disabled skipped, transit=False, imprecision, expansion
# --------------------------------------------------------------------------- #

def test_disabled_rule_is_skipped_with_note():
    aces, notes = parse_winfw(_BLOCK_AND_ALLOW)
    # The disabled Telnet rule (port 23) emits NO ACE.
    assert not any(a.dst_port.lo == 23 for a in aces if a.proto == "tcp")
    assert any("disabled" in n.lower() and "Telnet" in n for n in notes)


def test_all_host_hook_aces_are_transit_false():
    aces, _ = parse_winfw(_BLOCK_AND_ALLOW + "\n" + _OUTBOUND_HTTPS)
    assert aces
    assert all(a.transit is False for a in aces)
    assert {a.acl for a in aces} == {"Inbound", "Outbound"}


def test_dynamic_rpc_port_widens_to_any_imprecise():
    cfg = """\
Rule Name:                            Allow RPC endpoint
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.5
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Action:                               Allow
"""
    aces, notes = parse_winfw(cfg)
    rpc = _by([a for a in aces if a.action == "permit"], proto="tcp")
    assert rpc.imprecise is True
    assert rpc.dst_port.is_any()          # widened, not a narrowed subset
    assert any("RPC" in n and "imprecise" in n for n in notes)


def test_named_port_list_expands_to_exact_per_port_aces():
    cfg = """\
Rule Name:                            Allow Web
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.6
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            80,443
RemotePort:                           Any
Action:                               Allow
"""
    aces, _ = parse_winfw(cfg)
    permits = [a for a in aces if a.action == "permit" and a.proto == "tcp"]
    # LocalIP concrete v4 -> family pinned to v4 -> exactly two per-port ACEs.
    assert {a.dst_port.lo for a in permits} == {80, 443}
    assert all(a.dst_port.lo == a.dst_port.hi for a in permits)
    assert all(a.imprecise is False for a in permits)


def test_ip_range_expands_to_exact_cidrs():
    cfg = """\
Rule Name:                            Allow Range
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.5
RemoteIP:                             10.0.0.0-10.0.0.255
Protocol:                             TCP
LocalPort:                            443
RemotePort:                           Any
Action:                               Allow
"""
    aces, _ = parse_winfw(cfg)
    permit = _by([a for a in aces if a.action == "permit"], proto="tcp")
    # 10.0.0.0-10.0.0.255 summarizes to the exact CIDR 10.0.0.0/24 (src, inbound).
    assert str(permit.src) == "10.0.0.0/24"
    assert permit.imprecise is False


def test_keyword_scope_widens_to_any_imprecise():
    cfg = """\
Rule Name:                            Allow LocalSubnet
Enabled:                              Yes
Direction:                            In
LocalIP:                              Any
RemoteIP:                             LocalSubnet
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Action:                               Allow
"""
    aces, notes = parse_winfw(cfg)
    permits = [a for a in aces if a.action == "permit"]
    # RemoteIP=LocalSubnet is not a concrete CIDR -> src widened to ANY + imprecise.
    assert permits and all(a.src_any and a.imprecise for a in permits)
    assert any("LocalSubnet" in n and "imprecise" in n for n in notes)


def test_malformed_block_missing_action_is_skipped_not_crash():
    cfg = """\
Rule Name:                            No Action Here
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.5
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            443
RemotePort:                           Any
"""
    aces, notes = parse_winfw(cfg)   # must not raise
    assert aces == []
    assert any("Action" in n and "skipped" in n for n in notes)


# --------------------------------------------------------------------------- #
# 5. mapping — inbound host=dst, outbound host=src; port mapping
# --------------------------------------------------------------------------- #

def test_inbound_maps_local_to_dst_remote_to_src():
    aces, _ = parse_winfw(_INBOUND_SQL)
    permit = _by([a for a in aces if a.action == "permit"], proto="tcp")
    # Inbound: host is the destination -> LocalIP is dst, RemoteIP is src.
    assert str(permit.dst) == "10.0.0.5/32"        # LocalIP -> dst
    assert str(permit.src) == "10.20.0.0/16"       # RemoteIP -> src
    # LocalPort is the DESTINATION-side port for inbound; RemotePort the source.
    assert permit.dst_port.lo == 1433 and permit.dst_port.hi == 1433
    assert permit.src_port.is_any()                # RemotePort Any -> src_port ANY
    assert permit.acl == "Inbound"


def test_outbound_maps_local_to_src_remote_to_dst():
    aces, _ = parse_winfw(_OUTBOUND_HTTPS)
    permit = _by([a for a in aces if a.action == "permit" and a.proto == "tcp"],
                 proto="tcp")
    # Outbound: host is the source -> LocalIP is src, RemoteIP is dst.
    assert str(permit.src) == "10.0.0.7/32"        # LocalIP -> src
    assert str(permit.dst) == "10.20.0.0/16"       # RemoteIP -> dst
    # RemotePort is the DESTINATION-side port for outbound; LocalPort the source.
    assert permit.dst_port.lo == 443 and permit.dst_port.hi == 443
    assert permit.src_port.is_any()                # LocalPort Any -> src_port ANY
    assert permit.acl == "Outbound"


def test_multi_value_remoteip_continuation_lines_expand():
    # netsh lists multiple RemoteIP values one per indented continuation line.
    cfg = """\
Rule Name:                            Allow two nets
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.5
RemoteIP:                             10.20.0.0/24
                                      10.30.0.0/24
Protocol:                             TCP
LocalPort:                            443
RemotePort:                           Any
Action:                               Allow
"""
    aces, _ = parse_winfw(cfg)
    srcs = {str(a.src) for a in aces if a.action == "permit"}
    assert srcs == {"10.20.0.0/24", "10.30.0.0/24"}


# --------------------------------------------------------------------------- #
# 6. soundness — an imprecise (widened) ACE never proves another rule dead
# --------------------------------------------------------------------------- #

def test_imprecise_ace_never_covers_a_narrower_rule():
    aces, _ = parse_winfw(_BLOCK_AND_ALLOW)
    # Build an imprecise permit (RPC widened to ANY ports) and confirm covers()
    # refuses to use it as a coverer even though its modeled port space is ANY.
    rpc_cfg = """\
Rule Name:                            Allow RPC
Enabled:                              Yes
Direction:                            In
LocalIP:                              10.0.0.10
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Action:                               Allow
"""
    rpc_aces, _ = parse_winfw(rpc_cfg)
    rpc_permit = _by([a for a in rpc_aces if a.action == "permit"], proto="tcp")
    assert rpc_permit.imprecise is True
    concrete_permit = _by([a for a in aces if a.action == "permit"], proto="tcp")
    # rpc_permit's modeled space (any->10.0.0.10/32, tcp, ANY ports) is a numeric
    # superset of concrete_permit, yet covers() must return False: an imprecise
    # rule can never prove another rule dead.
    assert covers(rpc_permit, concrete_permit) is False


def test_icmpv4_and_icmpv6_proto_families():
    cfg = """\
Rule Name:                            Allow ping v4
Enabled:                              Yes
Direction:                            In
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             ICMPv4
LocalPort:                            Any
RemotePort:                           Any
Action:                               Allow

Rule Name:                            Allow ping v6
Enabled:                              Yes
Direction:                            In
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             ICMPv6
LocalPort:                            Any
RemotePort:                           Any
Action:                               Allow
"""
    aces, _ = parse_winfw(cfg)
    protos = {a.proto for a in aces if a.action == "permit"}
    assert protos == {"icmp", "icmpv6"}
    v4 = _by([a for a in aces if a.proto == "icmp"], action="permit")
    v6 = _by([a for a in aces if a.proto == "icmpv6"], action="permit")
    assert v4.src.version == 4 and v6.src.version == 6
