"""Tests for the Microsoft (Windows Server) DNS client-subnet frontend.

Covers the L3/L4 slice this frontend models — "which client networks may
resolve via this DNS server on udp/tcp 53" — and proves the verdicts are SOUND
end-to-end through ``rulehawk.segcheck.check_segmentation``:

  * detect fires on the DNS cmdlets and NOT on the Windows *Firewall* (netsh /
    Rule Name: / Direction:) format, Cisco, iptables, or a JSON policy;
  * an ordered ALLOW Corp / DENY Guest pair -> Corp reaches DNS/53
    (connectivity-ok) and Guest is isolated from DNS/53 (segmentation-ok);
  * a ``NE,`` negated policy and an undefined client-subnet reference both
    over-approximate to imprecise -> segmentation-INDETERMINATE, never a false
    PASS;
  * the trailing fail-closed default marker makes an UNMATCHED forbidden flow
    indeterminate (not a clean isolation PASS), matching the Windows
    default-ALLOW behavior.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.model import ANY_PORTS, PortRange  # noqa: E402
from rulehawk.parse_msdns import detect, parse_msdns  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# The canonical target format from the frontend contract.
_CFG = (
    'Add-DnsServerClientSubnet -Name "CorpSubnet" -IPv4Subnet "10.20.0.0/16"\n'
    'Add-DnsServerClientSubnet -Name "GuestSubnet" '
    '-IPv4Subnet "10.70.0.0/16","10.71.0.0/16"\n'
    'Add-DnsServerQueryResolutionPolicy -Name "BlockGuest" -Action DENY '
    '-ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1\n'
    'Add-DnsServerQueryResolutionPolicy -Name "AllowCorp" -Action ALLOW '
    '-ClientSubnet "EQ,CorpSubnet" -ProcessingOrder 2\n'
)

_ZONES = {
    "CORP": ["10.20.0.0/16"],
    "GUEST": ["10.70.0.0/16"],
    "GUEST2": ["10.71.0.0/16"],
    "DNS": ["10.99.0.1/32"],   # the resolver; dst=ANY in the model covers it
}


def _kinds(aces, policy):
    return [f.kind for f in check_segmentation(aces, policy)]


# --------------------------------------------------------------------------- #
# detect
# --------------------------------------------------------------------------- #

def test_detect_true_on_cmdlet_text():
    assert detect(_CFG) is True


def test_detect_true_on_set_get_variants_and_casing_and_indent():
    assert detect("Set-DnsServerQueryResolutionPolicy -Name X -Action ALLOW")
    assert detect("Get-DnsServerClientSubnet")
    assert detect("REMOVE-DNSSERVERQUERYRESOLUTIONPOLICY -Name X")   # casing
    assert detect('    Add-DnsServerClientSubnet -Name X -IPv4Subnet "1.0.0.0/8"')


def test_detect_false_on_windows_firewall_netsh_format():
    # The Windows *Firewall* frontend's markers — must NOT be captured here.
    netsh = ('netsh advfirewall firewall add rule name="Allow DNS" '
             'dir=in action=allow protocol=UDP localport=53')
    show = ("Rule Name:  Allow DNS\n"
            "----------------------------------------------------------\n"
            "Direction:  In\n"
            "Action:     Allow\n"
            "Protocol:   UDP\n")
    assert detect(netsh) is False
    assert detect(show) is False


def test_detect_false_on_other_vendors_and_json():
    cisco = ("ip access-list extended DNS\n"
             " permit udp any any eq 53\n deny ip any any\n")
    iptables = "-A FORWARD -s 10.0.0.0/8 -p udp --dport 53 -j ACCEPT\n"
    js = '{"zones": {"CORP": ["10.0.0.0/8"]}, "must_not_reach": []}'
    assert detect(cisco) is False
    assert detect(iptables) is False
    assert detect(js) is False


# --------------------------------------------------------------------------- #
# ACE mapping shape
# --------------------------------------------------------------------------- #

def test_mapping_shape_ordered_udp_and_tcp_53_dst_any_plus_default_marker():
    aces, notes = parse_msdns(_CFG)
    # All in one first-match context.
    assert {a.acl for a in aces} == {"dns-query-policy"}

    # Every non-default ACE targets dst=ANY on port 53, both transports.
    policy_aces = [a for a in aces if not (a.proto == "ip" and a.imprecise)]
    for a in policy_aces:
        assert a.dst.prefixlen == 0                  # dst = ANY (superset)
        assert a.dst_port == PortRange(53, 53)
        assert a.src_port == ANY_PORTS
        assert a.proto in ("udp", "tcp")
        assert a.transit is True

    # First-match ORDER: BlockGuest (order 1, DENY) precedes AllowCorp (order 2).
    denies = [a for a in policy_aces if a.action == "deny"]
    permits = [a for a in policy_aces if a.action == "permit"]
    assert denies and permits
    assert max(a.seq for a in denies) < min(a.seq for a in permits)
    # Guest has TWO member CIDRs -> two src nets, each udp+tcp = 4 deny ACEs.
    assert {str(a.src) for a in denies} == {"10.70.0.0/16", "10.71.0.0/16"}
    assert len(denies) == 4
    # Corp is one member -> udp+tcp = 2 permit ACEs.
    assert {str(a.src) for a in permits} == {"10.20.0.0/16"}
    assert len(permits) == 2

    # Trailing fail-closed default marker: imprecise permit ip any any (both
    # families), LAST in the list.
    tail = aces[-2:]
    assert all(a.proto == "ip" and a.action == "permit" and a.imprecise
               for a in tail)
    assert {str(a.src) for a in tail} == {"0.0.0.0/0", "::/0"}
    # No parse warnings on the clean canonical config.
    assert notes == []


# --------------------------------------------------------------------------- #
# End-to-end sound verdicts: ALLOW Corp / DENY Guest ordered pair
# --------------------------------------------------------------------------- #

def test_corp_reaches_dns_and_guest_is_isolated():
    aces, _ = parse_msdns(_CFG)
    policy = {
        "zones": _ZONES,
        "must_reach": [
            {"src": "CORP", "dst": "DNS", "proto": "tcp", "ports": [53]},
            {"src": "CORP", "dst": "DNS", "proto": "udp", "ports": [53]},
        ],
        "must_not_reach": [
            {"src": "GUEST", "dst": "DNS", "proto": "tcp", "ports": [53]},
            {"src": "GUEST2", "dst": "DNS", "proto": "udp", "ports": [53]},
        ],
    }
    findings = check_segmentation(aces, policy)
    kinds = [f.kind for f in findings]
    # Corp reaches the resolver on both transports; both Guest CIDRs isolated.
    assert kinds.count("connectivity-ok") == 2
    assert kinds.count("segmentation-ok") == 2
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds

    # The connectivity witness is a real Corp -> resolver packet on :53.
    ok = next(f for f in findings if f.kind == "connectivity-ok")
    assert ok.witness.startswith("10.20.") and ":53" in ok.witness


def test_ignore_action_is_modeled_as_deny_isolation():
    # IGNORE drops the query -> same reachability effect as DENY.
    cfg = (
        'Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Drop" -Action IGNORE '
        '-ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1\n'
    )
    aces, _ = parse_msdns(cfg)
    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "udp", "ports": [53]}]}
    assert _kinds(aces, policy) == ["segmentation-ok"]


def test_param_order_and_casing_variance_tolerated():
    # Parameters reordered, lower-case action/operator, unquoted CIDR.
    cfg = (
        "add-dnsserverclientsubnet -ipv4subnet 10.20.0.0/16 -name CorpSubnet\n"
        'Add-DnsServerQueryResolutionPolicy -ProcessingOrder 5 '
        '-ClientSubnet "eq,CorpSubnet" -Action allow -Name AllowCorp\n'
    )
    aces, _ = parse_msdns(cfg)
    policy = {"zones": _ZONES,
              "must_reach": [{"src": "CORP", "dst": "DNS",
                              "proto": "tcp", "ports": [53]}]}
    assert _kinds(aces, policy) == ["connectivity-ok"]


# --------------------------------------------------------------------------- #
# Fail-closed over-approximations (never a false PASS)
# --------------------------------------------------------------------------- #

def test_negated_NE_policy_is_imprecise_not_a_false_pass():
    # DENY every client EXCEPT Corp. Guest IS denied in reality, but the
    # complement is not one rectangle -> widen to ANY + imprecise so the verdict
    # is INDETERMINATE (honest), never a clean PASS certified from a widened src.
    cfg = (
        'Add-DnsServerClientSubnet -Name "CorpSubnet" -IPv4Subnet "10.20.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "OnlyCorp" -Action DENY '
        '-ClientSubnet "NE,CorpSubnet" -ProcessingOrder 1\n'
    )
    aces, notes = parse_msdns(cfg)
    # The NE policy widened its src to ANY and flagged imprecise.
    ne_aces = [a for a in aces if not (a.proto == "ip")]
    assert ne_aces and all(a.imprecise and a.src.prefixlen == 0 for a in ne_aces)
    assert any("negated client-subnet" in n for n in notes)

    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    kinds = _kinds(aces, policy)
    assert kinds == ["segmentation-indeterminate"]
    assert "segmentation-ok" not in kinds        # never a false PASS


def test_undefined_client_subnet_reference_is_imprecise():
    cfg = (
        'Add-DnsServerQueryResolutionPolicy -Name "P" -Action ALLOW '
        '-ClientSubnet "EQ,NoSuchSubnet" -ProcessingOrder 1\n'
    )
    aces, notes = parse_msdns(cfg)
    assert any("undefined client-subnet" in n for n in notes)
    non_default = [a for a in aces if not (a.proto == "ip")]
    assert non_default and all(a.imprecise and a.src.prefixlen == 0
                               for a in non_default)

    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    assert _kinds(aces, policy) == ["segmentation-indeterminate"]


def test_fail_closed_default_unmatched_flow_is_indeterminate_not_ok():
    # Only Corp is allowed; Guest matches NO policy. Windows default = ALLOW, so
    # certifying Guest isolation would be a FALSE PASS. The trailing imprecise
    # marker forces INDETERMINATE instead.
    cfg = (
        'Add-DnsServerClientSubnet -Name "CorpSubnet" -IPv4Subnet "10.20.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "AllowCorp" -Action ALLOW '
        '-ClientSubnet "EQ,CorpSubnet" -ProcessingOrder 1\n'
    )
    aces, _ = parse_msdns(cfg)
    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    kinds = _kinds(aces, policy)
    assert kinds == ["segmentation-indeterminate"]
    assert "segmentation-ok" not in kinds        # the fail-closed guarantee


def test_extra_criterion_narrows_match_so_deny_is_imprecise():
    # A DENY with an AND-combined TimeOfDay criterion matches a NARROWER space
    # than "all Guest on 53"; modeling it at full width would over-subtract and
    # false-PASS. It must therefore be imprecise -> indeterminate.
    cfg = (
        'Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "BG" -Action DENY '
        '-ClientSubnet "EQ,GuestSubnet" -TimeOfDay "EQ,09:00-17:00" '
        '-ProcessingOrder 1\n'
    )
    aces, notes = parse_msdns(cfg)
    assert any("unmodeled criterion" in n for n in notes)
    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    assert _kinds(aces, policy) == ["segmentation-indeterminate"]


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #

def test_malformed_lines_do_not_crash_and_surface_notes():
    cfg = (
        "Add-DnsServerClientSubnet\n"                         # no -Name
        'Add-DnsServerQueryResolutionPolicy -Name "Broken"\n'  # no action/subnet
        "Add-DnsServerClientSubnet -Name Bad -IPv4Subnet 999.999.0.0/16\n"  # bad CIDR
        "this is not a cmdlet at all\n"
    )
    aces, notes = parse_msdns(cfg)
    # Never crashes; always emits at least the fail-closed default markers.
    assert any(a.proto == "ip" and a.imprecise for a in aces)
    assert notes  # degraded with surfaced notes rather than silently


# --------------------------------------------------------------------------- #
# Soundness regressions — Windows would REJECT or ORDER these differently than
# the config text implies, so a CONFIDENT deny would over-cover and false-PASS.
# Each must instead be imprecise -> segmentation-INDETERMINATE.
# --------------------------------------------------------------------------- #

def test_processingorder_collision_is_imprecise_not_order_dependent():
    # Two policies share -ProcessingOrder 1 with overlapping src and OPPOSITE
    # actions. Windows keeps ProcessingOrder unique at runtime (an insert shifts
    # existing ones), so the config text does NOT fix their relative first-match
    # order. The verdict must be INDETERMINATE regardless of authoring order —
    # it must never flip (deny-first PASS / allow-first violation).
    deny_first = (
        'Add-DnsServerClientSubnet -Name "CorpSubnet" -IPv4Subnet "10.20.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Deny" -Action DENY '
        '-ClientSubnet "EQ,CorpSubnet" -ProcessingOrder 1\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Allow" -Action ALLOW '
        '-ClientSubnet "EQ,CorpSubnet" -ProcessingOrder 1\n'
    )
    allow_first = (
        'Add-DnsServerClientSubnet -Name "CorpSubnet" -IPv4Subnet "10.20.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Allow" -Action ALLOW '
        '-ClientSubnet "EQ,CorpSubnet" -ProcessingOrder 1\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Deny" -Action DENY '
        '-ClientSubnet "EQ,CorpSubnet" -ProcessingOrder 1\n'
    )
    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "CORP", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    for cfg in (deny_first, allow_first):
        aces, notes = parse_msdns(cfg)
        assert any("share -ProcessingOrder" in n for n in notes)
        # Every colliding policy's ACEs are imprecise.
        policy_aces = [a for a in aces if a.proto in ("udp", "tcp")]
        assert policy_aces and all(a.imprecise for a in policy_aces)
        kinds = _kinds(aces, policy)
        assert kinds == ["segmentation-indeterminate"]
        assert "segmentation-ok" not in kinds
        assert "segmentation-violation" not in kinds


def test_set_policy_with_no_prior_add_is_imprecise_reaches_default_allow():
    # Set-DnsServerQueryResolutionPolicy on a policy that was never Add-ed:
    # Windows errors (no rule is created) and the client falls through to the
    # default-ALLOW. Synthesizing a confident DENY would falsely certify Guest
    # isolation; it must be imprecise -> INDETERMINATE.
    cfg = (
        'Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/16"\n'
        'Set-DnsServerQueryResolutionPolicy -Name "Block" -Action DENY '
        '-ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1\n'
    )
    aces, notes = parse_msdns(cfg)
    assert any("no prior Add" in n for n in notes)
    policy_aces = [a for a in aces if a.proto in ("udp", "tcp")]
    assert policy_aces and all(a.imprecise for a in policy_aces)
    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    kinds = _kinds(aces, policy)
    assert kinds == ["segmentation-indeterminate"]
    assert "segmentation-ok" not in kinds


def test_duplicate_add_client_subnet_is_imprecise_not_a_false_pass():
    # First Add is the smaller (real) subnet; a second Add with a BIGGER CIDR is
    # REJECTED by Windows (the first definition stays). A confident deny of the
    # over-broad last definition would certify isolation of the whole /16 that
    # the server does not enforce — it must be imprecise -> INDETERMINATE.
    cfg = (
        'Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/24"\n'
        'Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Block" -Action DENY '
        '-ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1\n'
    )
    aces, notes = parse_msdns(cfg)
    assert any("Add-ed more than once" in n for n in notes)
    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    kinds = _kinds(aces, policy)
    assert kinds == ["segmentation-indeterminate"]
    assert "segmentation-ok" not in kinds


def test_set_client_subnet_action_remove_is_imprecise_not_a_false_pass():
    # Set -Action REMOVE shrinks the subnet: removed members leave the group and
    # are NOT denied. Treating it as REPLACE (the old behavior) denied exactly
    # the removed CIDR and false-passed its isolation. It must be imprecise so a
    # deny cannot over-cover -> INDETERMINATE.
    zones = dict(_ZONES)
    zones["REMOVED"] = ["10.70.5.0/24"]
    cfg = (
        'Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.70.0.0/16"\n'
        'Set-DnsServerClientSubnet -Name "GuestSubnet" -Action REMOVE '
        '-IPv4Subnet "10.70.5.0/24"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Block" -Action DENY '
        '-ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1\n'
    )
    aces, notes = parse_msdns(cfg)
    assert any("-Action REMOVE" in n for n in notes)
    policy = {"zones": zones,
              "must_not_reach": [{"src": "REMOVED", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    kinds = _kinds(aces, policy)
    assert kinds == ["segmentation-indeterminate"]
    assert "segmentation-ok" not in kinds


def test_set_client_subnet_action_replace_stays_precise():
    # The DEFAULT Set action is REPLACE, which IS exactly modelable — a plain
    # Set (or -Action REPLACE) must NOT be flagged imprecise, so a legitimate
    # DENY still certifies isolation (guards against over-flagging).
    cfg = (
        'Add-DnsServerClientSubnet -Name "GuestSubnet" -IPv4Subnet "10.99.0.0/16"\n'
        'Set-DnsServerClientSubnet -Name "GuestSubnet" -Action REPLACE '
        '-IPv4Subnet "10.70.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "Block" -Action DENY '
        '-ClientSubnet "EQ,GuestSubnet" -ProcessingOrder 1\n'
    )
    aces, _ = parse_msdns(cfg)
    policy = {"zones": _ZONES,
              "must_not_reach": [{"src": "GUEST", "dst": "DNS",
                                  "proto": "tcp", "ports": [53]}]}
    assert _kinds(aces, policy) == ["segmentation-ok"]


def test_compound_boolean_client_subnet_note_names_operator_not_undefined():
    # "EQ,Corp,NE,Guest" is a compound boolean criterion; the "NE" is an
    # OPERATOR, not a subnet name. The RESULT was already sound (widened to ANY +
    # imprecise); assert the NOTE is now accurate and no longer claims an
    # undefined subnet named 'NE'.
    cfg = (
        'Add-DnsServerClientSubnet -Name "Corp" -IPv4Subnet "10.20.0.0/16"\n'
        'Add-DnsServerClientSubnet -Name "Guest" -IPv4Subnet "10.70.0.0/16"\n'
        'Add-DnsServerQueryResolutionPolicy -Name "P" -Action DENY '
        '-ClientSubnet "EQ,Corp,NE,Guest" -ProcessingOrder 1\n'
    )
    aces, notes = parse_msdns(cfg)
    assert any("compound/boolean" in n and "operator 'NE'" in n for n in notes)
    assert not any("undefined client-subnet 'NE'" in n for n in notes)
    # Still sound: src widened to ANY + imprecise.
    policy_aces = [a for a in aces if a.proto in ("udp", "tcp")]
    assert policy_aces and all(a.imprecise and a.src.prefixlen == 0
                               for a in policy_aces)
