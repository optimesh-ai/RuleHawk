"""Custom-chain rules are not a separate transit path when FORWARD is present.

Found by the kernel differential oracle (tools/oracle/iptables_diff.py, 40
random rulesets): all 51 segmentation witnesses the kernel refused came from a
user-defined chain searched ON ITS OWN, as if every forwarded packet entered
it. A packet only reaches a user chain through a jump from FORWARD, and the
FORWARD model already carries those jumps (resolved precisely, or as an
imprecise fail-closed placeholder). Searching the user chain standalone only
adds violations whose witness never reaches the chain — noise:

  :FORWARD DROP
  -A FORWARD -s 10.0.0.0/8 -j C0
  -A C0 -s 192.168.1.0/24 -j ACCEPT
      reported "192.168.1.1 -> ... via C0" — the kernel drops it (FORWARD
      never jumps to C0 for 192.168.1.0/24).

When the file has NO FORWARD chain (e.g. `iptables -S DOCKER-USER`), nothing
anchors the user chain, so it stays in the search (fail-safe over-report).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse_iptables import parse_iptables  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POL = {"zones": {"BR": ["192.168.1.0/24"], "LAN": ["10.0.0.0/24"]},
        "must_not_reach": [{"src": "BR", "dst": "LAN", "proto": "ip"}]}


def _kinds(text):
    aces, _ = parse_iptables(text)
    return [f.kind for f in check_segmentation(aces, _POL)]


def test_unreached_custom_chain_permit_is_not_a_violation():
    text = ("*filter\n:FORWARD DROP [0:0]\n:C0 - [0:0]\n"
            "-A FORWARD -s 10.0.0.0/8 -j C0\n"
            "-A C0 -s 192.168.1.0/24 -j ACCEPT\n"
            "COMMIT\n")
    assert "segmentation-violation" not in _kinds(text)


def test_reached_custom_chain_permit_is_still_a_violation():
    text = ("*filter\n:FORWARD DROP [0:0]\n:C0 - [0:0]\n"
            "-A FORWARD -s 192.168.0.0/16 -j C0\n"
            "-A C0 -s 192.168.1.0/24 -j ACCEPT\n"
            "COMMIT\n")
    assert "segmentation-violation" in _kinds(text)


def test_unresolvable_jump_stays_indeterminate_not_pass():
    # C0 holds a RETURN, so the jump cannot be resolved: FORWARD keeps an
    # imprecise placeholder and the verdict must be INDETERMINATE, never PASS.
    text = ("*filter\n:FORWARD DROP [0:0]\n:C0 - [0:0]\n"
            "-A FORWARD -s 192.168.0.0/16 -j C0\n"
            "-A C0 -p tcp --dport 22 -j RETURN\n"
            "-A C0 -s 192.168.1.0/24 -j ACCEPT\n"
            "COMMIT\n")
    k = _kinds(text)
    assert "segmentation-violation" in k or "segmentation-indeterminate" in k


def test_custom_chain_without_forward_is_still_searched():
    text = ("-N DOCKER-USER\n"
            "-A DOCKER-USER -s 192.168.1.0/24 -j ACCEPT\n")
    assert "segmentation-violation" in _kinds(text)


def test_custom_chain_aces_stay_in_hygiene_analysis():
    from rulehawk.analyze import analyze
    aces, _ = parse_iptables("*filter\n:FORWARD DROP [0:0]\n:C0 - [0:0]\n"
                             "-A FORWARD -s 10.0.0.0/8 -j C0\n"
                             "-A C0 -s 192.168.1.0/24 -j ACCEPT\n"
                             "-A C0 -s 192.168.1.0/24 -j ACCEPT\n"
                             "COMMIT\n")
    assert any(f.kind == "redundant" and f.rule_id.startswith("C0:")
               for f in analyze(aces))
