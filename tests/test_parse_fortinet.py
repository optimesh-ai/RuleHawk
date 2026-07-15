"""End-to-end tests for the Fortinet FortiGate (FortiOS) frontend.

These assert SOUND downstream verdicts (segmentation / connectivity / hygiene)
through `check_segmentation` and `analyze`, not just ACE shapes — the parser's
job is to feed the existing engine a superset-correct IR so those verdicts hold.
"""

from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze                       # noqa: E402
from rulehawk.model import PortRange                       # noqa: E402
from rulehawk.parse_fortinet import detect, parse_fortinet  # noqa: E402
from rulehawk.segcheck import check_segmentation           # noqa: E402


# Shared object definitions (addresses, a group, custom services, a service
# group). Each test appends its own `config firewall policy` block.
BASE = """
config firewall address
    edit "corp-net"
        set subnet 10.20.0.0 255.255.0.0
    next
    edit "pci-net"
        set subnet 10.10.0.0 255.255.0.0
    next
    edit "proxy-net"
        set subnet 185.46.212.0 255.255.254.0
    next
    edit "db-range"
        set type iprange
        set start-ip 10.30.0.10
        set end-ip 10.30.0.13
    next
    edit "bad-fqdn"
        set type fqdn
        set fqdn "evil.example.com"
    next
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config firewall addrgrp
    edit "internal"
        set member "corp-net" "pci-net"
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
    edit "SMB"
        set tcp-portrange 445
    next
end
config firewall service group
    edit "web-svcs"
        set member "HTTPS" "HTTP"
    next
end
"""

# CORP must not reach PCI on tcp/445.
_SEG = {"zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
        "must_not_reach": [{"src": "CORP", "dst": "PCI",
                            "proto": "tcp", "ports": [445]}]}


def _policy(body: str) -> str:
    return BASE + "config firewall policy\n" + body + "end\n"


def _seg(cfg: str, policy=_SEG):
    aces, _ = parse_fortinet(cfg)
    return check_segmentation(aces, policy)


def _kinds(findings):
    return [f.kind for f in findings]


# --------------------------------------------------------------------------- #
# detect()
# --------------------------------------------------------------------------- #

def test_detect_fires_on_firewall_policy():
    cfg = _policy('    edit 1\n        set srcaddr "all"\n'
                  '        set dstaddr "all"\n        set action deny\n    next\n')
    assert detect(cfg) is True


def test_detect_fires_on_address_table_markers():
    # No `config firewall policy` block, but the address-table markers combo.
    assert detect(BASE) is True


def test_detect_false_on_cisco_and_iptables():
    cisco = ("ip access-list extended CORP\n"
             " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"
             " deny ip any any\n")
    iptables = ("*filter\n:FORWARD DROP [0:0]\n"
                "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -j ACCEPT\nCOMMIT\n")
    junos = ("firewall {\n  family inet {\n    filter CORP {\n"
             "      term t1 { then accept; }\n    }\n  }\n}\n")
    panos = ("set rulebase security rules r from any to any source any "
             "destination any application any service any action allow\n")
    for other in (cisco, iptables, junos, panos):
        assert detect(other) is False


# --------------------------------------------------------------------------- #
# object / group / service resolution -> ACE shapes
# --------------------------------------------------------------------------- #

def test_address_and_service_resolution():
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    permits = [a for a in aces if a.action == "permit"]
    assert len(permits) == 1
    a = permits[0]
    assert a.proto == "tcp"
    assert a.src == ipaddress.ip_network("10.20.0.0/16")
    assert a.dst == ipaddress.ip_network("10.10.0.0/16")
    assert a.dst_port == PortRange(445, 445)
    assert a.imprecise is False
    assert a.acl == "firewall-policy"
    assert a.transit is True


def test_addrgrp_and_service_group_union_expands_cross_product():
    # dst group internal = {corp-net, pci-net}; service web-svcs = {tcp/443
    # (custom HTTPS), tcp/80 (predefined HTTP)}. Expect the 2x2 exact union.
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "internal"\n        set action accept\n'
                  '        set service "web-svcs"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    permits = [a for a in aces if a.action == "permit"]
    assert len(permits) == 4
    dsts = {str(a.dst) for a in permits}
    ports = {a.dst_port.lo for a in permits}
    assert dsts == {"10.20.0.0/16", "10.10.0.0/16"}
    assert ports == {80, 443}
    assert all(a.proto == "tcp" and not a.imprecise for a in permits)


def test_iprange_object_summarizes_to_exact_cidrs():
    # 10.30.0.10-10.30.0.13 -> 10.30.0.10/31 + 10.30.0.12/31 (exact, not widened).
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "db-range"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    permits = [a for a in aces if a.action == "permit"]
    assert {str(a.dst) for a in permits} == {"10.30.0.10/31", "10.30.0.12/31"}
    assert all(not a.imprecise for a in permits)


# --------------------------------------------------------------------------- #
# segmentation verdicts
# --------------------------------------------------------------------------- #

def test_accept_policy_produces_segmentation_violation_with_witness():
    cfg = _policy('    edit 1\n        set srcintf "any"\n        set dstintf "any"\n'
                  '        set srcaddr "corp-net"\n        set dstaddr "pci-net"\n'
                  '        set action accept\n        set service "SMB"\n'
                  '        set schedule "always"\n        set status enable\n    next\n')
    f = _seg(cfg)
    viol = [x for x in f if x.kind == "segmentation-violation"]
    assert len(viol) == 1
    assert viol[0].severity == "critical"
    assert viol[0].witness.startswith("10.20.")
    assert ":445 (tcp)" in viol[0].witness
    assert "10.10." in viol[0].witness


def test_deny_above_permit_yields_segmentation_ok():
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action deny\n'
                  '        set service "SMB"\n    next\n'
                  '    edit 2\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    f = _seg(cfg)
    assert "segmentation-violation" not in _kinds(f)
    assert "segmentation-ok" in _kinds(f)


def test_implicit_default_deny_is_appended():
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    last = aces[-1]
    assert last.action == "deny"
    assert last.proto == "ip"
    assert last.src == ipaddress.ip_network("0.0.0.0/0")
    assert last.dst == ipaddress.ip_network("0.0.0.0/0")
    assert last.acl == "firewall-policy"
    # A config with NO policy at all is still isolated by the appended deny.
    empty = BASE + "config firewall policy\nend\n"
    assert "segmentation-ok" in _kinds(_seg(empty))


def test_unresolvable_fqdn_widens_to_any_imprecise_never_false_pass():
    cfg = _policy('    edit 1\n        set srcaddr "bad-fqdn"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    permits = [a for a in aces if a.action == "permit"]
    # src widened to ANY (superset), marked imprecise — never the empty/subset set.
    assert permits and all(a.src == ipaddress.ip_network("0.0.0.0/0")
                           and a.imprecise for a in permits)
    k = _kinds(_seg(cfg))
    assert "segmentation-ok" not in k          # must NOT false-PASS
    assert "segmentation-indeterminate" in k   # fail-closed instead


def test_specific_interface_is_over_approximation_indeterminate():
    # A specific srcintf/dstintf narrows the match (like a PAN-OS from/to zone):
    # over-approximated + imprecise -> indeterminate, never a confident verdict.
    cfg = _policy('    edit 1\n        set srcintf "port1"\n        set dstintf "port2"\n'
                  '        set srcaddr "corp-net"\n        set dstaddr "pci-net"\n'
                  '        set action accept\n        set service "SMB"\n    next\n')
    k = _kinds(_seg(cfg))
    assert "segmentation-ok" not in k
    assert "segmentation-violation" not in k
    assert "segmentation-indeterminate" in k


def test_srcaddr_negate_widens_to_any_not_subset():
    # negate matches the COMPLEMENT — widened to ANY + imprecise, so a CORP->PCI
    # probe (outside the listed corp-net) is not silently skipped (no false PASS).
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set srcaddr-negate enable\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    permits = [a for a in aces if a.action == "permit"]
    assert permits and all(a.src == ipaddress.ip_network("0.0.0.0/0")
                           and a.imprecise for a in permits)
    assert "segmentation-ok" not in _kinds(_seg(cfg))


# --------------------------------------------------------------------------- #
# disabled policies are skipped (exact — empty match space)
# --------------------------------------------------------------------------- #

def test_disabled_deny_no_longer_masks_a_leak():
    # The deny that would block CORP->PCI is disabled -> the accept below leaks.
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action deny\n'
                  '        set service "SMB"\n        set status disable\n    next\n'
                  '    edit 2\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    assert "segmentation-violation" in _kinds(_seg(cfg))


def test_disabled_permit_no_longer_opens_a_leak():
    # The only permit is disabled -> nothing opens the flow -> isolated.
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n        set status disable\n    next\n')
    aces, _ = parse_fortinet(cfg)
    assert not [a for a in aces if a.action == "permit"]   # emitted no ACE
    assert "segmentation-ok" in _kinds(_seg(cfg))


# --------------------------------------------------------------------------- #
# must_reach connectivity
# --------------------------------------------------------------------------- #

_REACH = {"zones": {"USERS": ["10.20.0.0/16"], "PROXY": ["185.46.212.0/23"]},
          "must_reach": [{"src": "USERS", "dst": "PROXY",
                          "proto": "tcp", "ports": [80, 443]}]}


def test_must_reach_connectivity_ok():
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "proxy-net"\n        set action accept\n'
                  '        set service "ALL"\n    next\n')
    f = check_segmentation(parse_fortinet(cfg)[0], _REACH)
    assert _kinds(f) == ["connectivity-ok"]
    assert f[0].witness.startswith("10.20.") and "185.46.212." in f[0].witness


def test_must_reach_connectivity_broken():
    # A permit exists, but not to PROXY -> the required flow is dropped.
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    f = check_segmentation(parse_fortinet(cfg)[0], _REACH)
    assert _kinds(f) == ["connectivity-broken"]
    assert f[0].severity == "high"


# --------------------------------------------------------------------------- #
# hygiene (analyze)
# --------------------------------------------------------------------------- #

def test_redundant_rule_hygiene():
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n'
                  '    edit 2\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    findings = analyze(parse_fortinet(cfg)[0])
    kinds = _kinds(findings)
    assert "redundant" in kinds
    red = [f for f in findings if f.kind == "redundant"][0]
    assert red.severity == "low"
    assert red.rule_id == "firewall-policy:2"   # the 2nd (later) permit is dead


# --------------------------------------------------------------------------- #
# robustness — never crash on malformed input
# --------------------------------------------------------------------------- #

def test_malformed_and_truncated_blocks_do_not_crash():
    for junk in (
        "config firewall policy\n    edit 1\n        set srcaddr",   # truncated
        'config firewall address\n    edit "x"\n        set subnet 999.1\n',
        "config firewall policy\n    edit 1\n",                      # no next/end
        'config firewall policy\n    edit 1\n        set service "NOPE"\n'
        '        set srcaddr "undefined-obj"\n        set action accept\n    next\nend\n',
        "",
    ):
        aces, notes = parse_fortinet(junk)
        assert isinstance(aces, list) and isinstance(notes, list)
        # always at least the trailing default deny
        assert aces and aces[-1].action == "deny"


# --------------------------------------------------------------------------- #
# regression: 5 confirmed soundness defects (each asserts the SOUND end-to-end
# verdict — a fix must turn a FALSE-PASS / false dead-claim into indeterminate,
# a violation, or a preserved live rule; never back into segmentation-ok).
# --------------------------------------------------------------------------- #

# IPv6 zones for the family-threading defect.
_SEG6 = {"zones": {"CORP6": ["2001:db8:20::/48"], "PCI6": ["2001:db8:10::/48"]},
         "must_not_reach": [{"src": "CORP6", "dst": "PCI6",
                             "proto": "tcp", "ports": [445]}]}


def test_ipv6_policy6_all_to_all_is_not_false_pass():
    # DEFECT 1: a `config firewall policy6` permitting all -> all was modeled
    # as v4 (all -> 0.0.0.0/0), so a v6 flow touched NO ACE and read as
    # isolated. `all` must resolve to ::/0 in a v6 policy, and a v6 implicit
    # deny-all must exist — so the v6 leak is caught, never segmentation-ok.
    cfg = ("config firewall policy6\n    edit 1\n        set srcaddr \"all\"\n"
           "        set dstaddr \"all\"\n        set action accept\n"
           "        set service \"ALL\"\n    next\nend\n")
    aces, _ = parse_fortinet(cfg)
    # An exact v6 permit (all -> all) exists over ::/0.
    permits = [a for a in aces if a.action == "permit"]
    assert permits and all(a.src == ipaddress.ip_network("::/0")
                           and a.dst == ipaddress.ip_network("::/0")
                           for a in permits)
    # A v6 implicit deny-all is appended alongside the v4 one.
    assert any(a.action == "deny" and a.src == ipaddress.ip_network("::/0")
               for a in aces)
    k = _kinds(check_segmentation(aces, _SEG6))
    assert "segmentation-ok" not in k          # must NOT false-PASS the v6 flow
    assert "segmentation-violation" in k

    # Same soundness for a UNIFIED policy that filters v6 via srcaddr6/dstaddr6.
    uni = ('config firewall policy\n    edit 1\n        set srcaddr6 "all"\n'
           '        set dstaddr6 "all"\n        set action accept\n'
           '        set service "ALL"\n    next\nend\n')
    assert "segmentation-ok" not in _kinds(check_segmentation(
        parse_fortinet(uni)[0], _SEG6))
    # v4 assurance preserved: a v4 all->all is still exact (not widened away).
    assert any(a.action == "deny" and a.src == ipaddress.ip_network("0.0.0.0/0")
               for a in aces)


def test_service_negate_widens_service_dim_not_false_pass():
    # DEFECT 2: `set service-negate enable` matches the COMPLEMENT of {tcp/445},
    # so a must_not_reach on tcp/3389 lives in the matched (permitted) space.
    # The service dim must widen to ANY proto/port + imprecise, so tcp/3389 is
    # indeterminate — never a segmentation-ok that ignores the negation.
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n        set service-negate enable\n'
                  '    next\n')
    aces, _ = parse_fortinet(cfg)
    permits = [a for a in aces if a.action == "permit"]
    assert permits and all(a.imprecise for a in permits)
    seg3389 = {"zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
               "must_not_reach": [{"src": "CORP", "dst": "PCI",
                                   "proto": "tcp", "ports": [3389]}]}
    assert "segmentation-ok" not in _kinds(check_segmentation(aces, seg3389))


def test_vdoms_are_independent_first_match_contexts():
    # DEFECT 3: two independent VDOMs — vdom_A denies CORP->PCI, vdom_B permits
    # it. Merged into one list the deny would (wrongly) mask the permit
    # (false-PASS) and analyze() would call the live permit dead. Scoped per
    # VDOM: vdom_B's permit is a real leak, and it is never dead.
    cfg = (
        "config vdom\n"
        "edit vdom_A\n"
        "    config firewall address\n"
        '        edit "corp-net"\n            set subnet 10.20.0.0 255.255.0.0\n        next\n'
        '        edit "pci-net"\n            set subnet 10.10.0.0 255.255.0.0\n        next\n'
        "    end\n"
        "    config firewall service custom\n"
        '        edit "SMB"\n            set tcp-portrange 445\n        next\n'
        "    end\n"
        "    config firewall policy\n"
        '        edit 1\n            set srcaddr "corp-net"\n            set dstaddr "pci-net"\n'
        '            set action deny\n            set service "SMB"\n        next\n'
        "    end\n"
        "next\n"
        "edit vdom_B\n"
        "    config firewall address\n"
        '        edit "corp-net"\n            set subnet 10.20.0.0 255.255.0.0\n        next\n'
        '        edit "pci-net"\n            set subnet 10.10.0.0 255.255.0.0\n        next\n'
        "    end\n"
        "    config firewall service custom\n"
        '        edit "SMB"\n            set tcp-portrange 445\n        next\n'
        "    end\n"
        "    config firewall policy\n"
        '        edit 1\n            set srcaddr "corp-net"\n            set dstaddr "pci-net"\n'
        '            set action accept\n            set service "SMB"\n        next\n'
        "    end\n"
        "next\n"
        "end\n")
    aces, _ = parse_fortinet(cfg)
    # Each VDOM is its own first-match context (not one merged "firewall-policy").
    assert {"firewall-policy:vdom_A", "firewall-policy:vdom_B"} <= {a.acl for a in aces}
    k = _kinds(check_segmentation(aces, _SEG))
    assert "segmentation-violation" in k       # vdom_B's permit leaks
    assert "segmentation-ok" not in k          # vdom_A's deny must not mask it
    # analyze() must NOT declare vdom_B's live permit dead from vdom_A's deny.
    assert "intent-inversion-permit-dead" not in _kinds(analyze(aces))


def test_forwarding_action_ipsec_is_permit_not_deny():
    # DEFECT 4: `set action ipsec` FORWARDS matched traffic — modeling it as a
    # hard deny both false-PASSes a must_not_reach AND kills the later live
    # permit as dead. It must be permit + imprecise: the flow is not provably
    # isolated, and covers() refuses the imprecise coverer so nothing is dead.
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action ipsec\n'
                  '        set service "SMB"\n    next\n'
                  '    edit 2\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    fwd = [a for a in aces if a.action == "permit"
           and a.src == ipaddress.ip_network("10.20.0.0/16")]
    # The ipsec rule is a permit (never a deny) and marked imprecise.
    assert fwd and any(a.imprecise for a in fwd)
    assert "segmentation-ok" not in _kinds(_seg(cfg))          # not false-PASS
    assert "intent-inversion-permit-dead" not in _kinds(analyze(aces))  # not dead


def test_edit_without_next_does_not_drop_a_permit():
    # DEFECT 5: `edit 1` (a PERMIT) with no closing `next` before `edit 2`
    # (a deny) used to be silently overwritten — the leak vanished and the
    # config false-PASSed. The pending edit must be committed implicitly so the
    # permit survives and its leak surfaces.
    cfg = _policy('    edit 1\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action accept\n'
                  '        set service "SMB"\n'
                  '    edit 2\n        set srcaddr "corp-net"\n'
                  '        set dstaddr "pci-net"\n        set action deny\n'
                  '        set service "SMB"\n    next\n')
    aces, _ = parse_fortinet(cfg)
    assert [a for a in aces if a.action == "permit"]   # the permit was not dropped
    k = _kinds(_seg(cfg))
    assert "segmentation-violation" in k               # its leak surfaces
    assert "segmentation-ok" not in k
