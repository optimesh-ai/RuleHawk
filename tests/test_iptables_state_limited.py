"""A conntrack-state rule that includes NEW is exact for NEW flows only.

Found by the kernel differential oracle (tools/oracle/iptables_diff.py): with

  -A FORWARD -m conntrack --ctstate NEW -j DROP
  -A FORWARD -p tcp --dport 22 -j ACCEPT
  -A FORWARD -p tcp --dport 80 -j DROP

RuleHawk said rule 2 "NEVER takes effect" and rule 3 is "redundant ... safe to
remove", proving both dead from rule 1. The kernel counted packets on both:
ESTABLISHED / RELATED / INVALID packets are not NEW, pass rule 1 and are
decided by the later rules. Deleting them changes what the firewall does.

A rule restricted to a SUBSET of the conntrack states that includes NEW is
modeled exactly for connection-initiating packets (what segmentation checks
ask about), but it must never prove another rule dead.

The same audit found `--ctstate DNAT` / `SNAT` (or an unknown state word)
read as an unrestricted new-flow rule: a `--ctstate DNAT -j DROP` then blocked
EVERY new flow in the model, so a later ACCEPT's leak was a false PASS. Those
states are now marked imprecise.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.parse_iptables import parse_iptables  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_DEAD = {"redundant", "intent-inversion-permit-dead", "intent-inversion-deny-dead",
         "union-redundant", "union-shadowed-deny-dead", "union-shadowed-permit-dead"}


def _dead(text):
    aces, _ = parse_iptables(text)
    return {f.rule_id for f in analyze(aces) if f.kind in _DEAD}


def test_new_only_drop_does_not_prove_later_rules_dead():
    text = ("*filter\n:FORWARD ACCEPT [0:0]\n"
            "-A FORWARD -m conntrack --ctstate NEW -j DROP\n"
            "-A FORWARD -p tcp --dport 22 -j ACCEPT\n"
            "-A FORWARD -p tcp --dport 80 -j DROP\n"
            "COMMIT\n")
    assert _dead(text) == set()


def test_state_module_new_established_is_also_limited():
    text = ("*filter\n:INPUT DROP [0:0]\n"
            "-A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "COMMIT\n")
    assert _dead(text) == set()


def test_all_states_listed_is_unrestricted():
    text = ("*filter\n:INPUT DROP [0:0]\n"
            "-A INPUT -p tcp --dport 22 -m conntrack "
            "--ctstate NEW,ESTABLISHED,RELATED,INVALID,UNTRACKED -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "COMMIT\n")
    assert _dead(text) == {"INPUT:2"}


def test_new_only_rule_can_still_be_covered():
    # covered BY an unrestricted rule: genuinely dead (real ⊆ modeled ⊆ coverer)
    text = ("*filter\n:INPUT DROP [0:0]\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT\n"
            "COMMIT\n")
    assert _dead(text) == {"INPUT:2"}


def test_new_only_drop_still_blocks_new_flows_in_segcheck():
    text = ("*filter\n:FORWARD ACCEPT [0:0]\n"
            "-A FORWARD -s 10.20.0.0/16 -d 10.10.0.0/16 -m conntrack --ctstate NEW -j DROP\n"
            "COMMIT\n")
    aces, _ = parse_iptables(text)
    pol = {"zones": {"C": ["10.20.0.0/16"], "P": ["10.10.0.0/16"]},
           "must_not_reach": [{"src": "C", "dst": "P", "proto": "tcp", "ports": [445]}]}
    kinds = [f.kind for f in check_segmentation(aces, pol)]
    assert "segmentation-violation" not in kinds
    assert "segmentation-indeterminate" not in kinds


def test_dnat_state_drop_is_not_a_full_deny():
    text = ("*filter\n:FORWARD DROP [0:0]\n"
            "-A FORWARD -m conntrack --ctstate DNAT -j DROP\n"
            "-A FORWARD -j ACCEPT\n"
            "COMMIT\n")
    aces, _ = parse_iptables(text)
    pol = {"zones": {"C": ["10.20.0.0/16"], "P": ["10.10.0.0/16"]},
           "must_not_reach": [{"src": "C", "dst": "P", "proto": "tcp", "ports": [445]}]}
    kinds = [f.kind for f in check_segmentation(aces, pol)]
    assert "segmentation-violation" in kinds or "segmentation-indeterminate" in kinds


def test_state_limited_jump_resolution_keeps_the_limit():
    text = ("*filter\n:FORWARD ACCEPT [0:0]\n:C0 - [0:0]\n"
            "-A FORWARD -m conntrack --ctstate NEW -j C0\n"
            "-A FORWARD -p tcp --dport 22 -j ACCEPT\n"
            "-A C0 -j DROP\n"
            "COMMIT\n")
    assert "FORWARD:2" not in _dead(text)
