"""`must_reach` — positive connectivity proofs for deployment prechecks.

The mirror of `must_not_reach`, on the same exact search: "hosts must be able
to reach the vendor/proxy egress ranges" (the Zscaler-style rollout check).
A permitted packet is the PROOF (connectivity-ok, info, concrete witness); a
provably all-denied flow is connectivity-broken (high — blocks the gate at the
default threshold, because a declared deployment flow that the filter drops IS
a deployment blocker); anything touching an imprecise rule is
connectivity-indeterminate (fail-closed: never upgraded to an OK).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.parse_iptables import parse_iptables  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# "Workstations must reach the proxy egress range on 80/443" — the shape of a
# Zscaler/vendor-cloud rollout precheck.
_POLICY = {
    "zones": {"USERS": ["10.20.0.0/16"], "PROXY": ["185.46.212.0/23"]},
    "must_reach": [{"src": "USERS", "dst": "PROXY", "proto": "tcp",
                    "ports": [80, 443]}],
}


def _run(acl, policy=_POLICY, parser=parse_acls):
    aces, _ = parser(acl)
    return check_segmentation(aces, policy)


def test_permitted_flow_proves_connectivity_with_witness():
    acl = ("ip access-list extended EGRESS\n"
           " permit tcp 10.20.0.0 0.0.255.255 185.46.212.0 0.0.1.255 eq 80 443\n"
           " deny ip any any\n")
    f = _run(acl)
    assert [x.kind for x in f] == ["connectivity-ok"]
    ok = f[0]
    assert ok.severity == "info"
    # Auditor-grade: a concrete witness packet inside the asserted flow.
    assert ok.witness.startswith("10.20.") and ":80 (tcp)" in ok.witness
    assert "185.46.212." in ok.witness


def test_denied_flow_is_connectivity_broken_high():
    acl = ("ip access-list extended EGRESS\n"
           " permit tcp 10.20.0.0 0.0.255.255 host 10.20.5.5 eq 443\n"
           " deny ip any any\n")
    f = _run(acl)
    assert [x.kind for x in f] == ["connectivity-broken"]
    assert f[0].severity == "high"          # blocks the gate by default
    assert "dropped at the filter layer" in f[0].message


def test_one_blocked_port_fails_the_whole_assertion():
    # The proof must hold for EVERY listed port: 443 working is not evidence
    # for 80. A deny on one asserted port -> connectivity-broken naming it.
    acl = ("ip access-list extended EGRESS\n"
           " deny tcp any 185.46.212.0 0.0.1.255 eq 80\n"
           " permit tcp 10.20.0.0 0.0.255.255 185.46.212.0 0.0.1.255 eq 443\n"
           " deny ip any any\n")
    f = _run(acl)
    assert [x.kind for x in f] == ["connectivity-broken"]
    assert ":80" in f[0].message            # names the failing combination


def test_multi_port_partial_permit_is_not_a_false_ok():
    # Regression for the short-circuit bug: udp 500 permitted, 4500 dropped —
    # attesting "ok" off port 500 would green-light a rollout whose IPsec
    # NAT-T is dead. Every (subnet pair x port) combination must be proven.
    pol = {"zones": {"RTR": ["192.0.2.0/29"], "ZEN": ["185.46.212.0/23"]},
           "must_reach": [{"src": "RTR", "dst": "ZEN", "proto": "udp",
                           "ports": [500, 4500]}]}
    acl = ("ip access-list extended EGRESS\n"
           " permit udp 192.0.2.0 0.0.0.7 185.46.212.0 0.0.1.255 eq 500\n"
           " deny ip any any\n")
    f = _run(acl, pol)
    assert [x.kind for x in f] == ["connectivity-broken"]
    assert ":4500" in f[0].message
    # ...and with both ports permitted, the proof covers all combinations.
    acl_ok = acl.replace(
        " deny ip any any\n",
        " permit udp 192.0.2.0 0.0.0.7 185.46.212.0 0.0.1.255 eq 4500\n"
        " deny ip any any\n")
    f_ok = _run(acl_ok, pol)
    assert [x.kind for x in f_ok] == ["connectivity-ok"]
    assert "all 2 flow combination(s)" in f_ok[0].message


def test_every_zone_subnet_pair_is_required():
    # Two dst subnets declared, only one reachable -> broken (a proof over
    # half the declared egress ranges is not a proof).
    pol = {"zones": {"USERS": ["10.20.0.0/16"],
                     "PROXY": ["185.46.212.0/23", "104.129.192.0/20"]},
           "must_reach": [{"src": "USERS", "dst": "PROXY", "proto": "tcp",
                           "ports": [443]}]}
    acl = ("ip access-list extended EGRESS\n"
           " permit tcp 10.20.0.0 0.0.255.255 185.46.212.0 0.0.1.255 eq 443\n"
           " deny ip any any\n")
    f = _run(acl, pol)
    assert [x.kind for x in f] == ["connectivity-broken"]
    assert "104.129.192.0/20" in f[0].message


def test_empty_zone_list_fails_closed_both_directions():
    # A defined-but-empty zone must never produce a vacuous verdict.
    for key in ("must_reach", "must_not_reach"):
        pol = {"zones": {"USERS": ["10.20.0.0/16"], "PROXY": []},
               key: [{"src": "USERS", "dst": "PROXY"}]}
        f = _run("ip access-list extended E\n permit ip any any\n", pol)
        assert [x.kind for x in f] == ["segmentation-error"], key


def test_imprecise_rule_fails_closed_to_indeterminate_not_ok():
    # An unresolvable form on the path can't prove the flow open OR closed.
    acl = ("ip access-list extended EGRESS\n"
           " permit tcp 10.20.0.0 0.0.255.255 object-group PROXY_NETS eq 443\n")
    f = _run(acl)
    assert [x.kind for x in f] == ["connectivity-indeterminate"]
    assert f[0].severity == "medium"


def test_unknown_zone_fails_closed_not_ok_not_broken():
    pol = {"zones": {"USERS": ["10.20.0.0/16"]},
           "must_reach": [{"src": "USERS", "dst": "PORXY"}]}   # typo
    f = _run("ip access-list extended E\n permit ip any any\n", pol)
    assert [x.kind for x in f] == ["segmentation-error"]
    assert "PORXY" in f[0].message


def test_iptables_transit_semantics_apply():
    # INPUT (host hook, transit=False) permitting the flow must not prove
    # inter-zone connectivity; the FORWARD default DROP decides: broken.
    cfg = ("*filter\n"
           ":INPUT ACCEPT [0:0]\n"
           ":FORWARD DROP [0:0]\n"
           "-A INPUT -s 10.20.0.0/16 -d 185.46.212.0/23 -p tcp --dport 443 -j ACCEPT\n"
           "COMMIT\n")
    f = _run(cfg, parser=parse_iptables)
    assert [x.kind for x in f] == ["connectivity-broken"]


def test_both_directions_coexist_in_one_policy():
    pol = {
        "zones": {"USERS": ["10.20.0.0/16"], "PROXY": ["185.46.212.0/23"],
                  "PCI": ["10.10.0.0/16"]},
        "must_not_reach": [{"src": "USERS", "dst": "PCI", "proto": "tcp",
                            "ports": [445]}],
        "must_reach": [{"src": "USERS", "dst": "PROXY", "proto": "tcp",
                        "ports": [443]}],
    }
    acl = ("ip access-list extended EGRESS\n"
           " permit tcp 10.20.0.0 0.0.255.255 185.46.212.0 0.0.1.255 eq 443\n"
           " deny ip any any\n")
    kinds = sorted(x.kind for x in _run(acl, pol))
    assert kinds == ["connectivity-ok", "segmentation-ok"]


def test_portless_must_reach_witness_is_concrete():
    pol = {"zones": _POLICY["zones"],
           "must_reach": [{"src": "USERS", "dst": "PROXY", "proto": "tcp"}]}
    acl = ("ip access-list extended EGRESS\n"
           " permit tcp 10.20.0.0 0.0.255.255 185.46.212.0 0.0.1.255 range 80 443\n")
    f = _run(acl, pol)
    assert [x.kind for x in f] == ["connectivity-ok"]
    assert "None" not in f[0].witness
    port = int(f[0].witness.split(" -> ")[1].split(" ")[0].rsplit(":", 1)[1])
    assert 80 <= port <= 443
