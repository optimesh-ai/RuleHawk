"""Inside an `ip access-list` block (IOS / IOS-XR / NX-OS / EOS — never ASA)
a dotted mask is ALWAYS a wildcard, even when it looks like a netmask.

Found by the Batfish oracle on a public STIG config:
    deny ip 100.64.0.0 0.63.255.255 any log
    ...
    deny ip 100.64.0.0 255.192.0.0 any log      <- RuleHawk: dead (shadowed)
RuleHawk auto-read 255.192.0.0 as a /10 netmask, so the second line looked
like a duplicate of the first and was reported dead. On IOS it is the
non-contiguous wildcard 255.192.0.0 (any first octet, ...): it matches
packets the first line does not, and Batfish proves the line reachable."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.parse import parse_acls  # noqa: E402

_T = """ip access-list extended E
 deny ip 100.64.0.0 0.63.255.255 any log
 deny ip 100.64.0.0 255.192.0.0 any log
 permit ip any any
"""


def test_netmask_looking_wildcard_is_not_proven_dead():
    aces, _ = parse_acls(_T)
    assert aces[1].imprecise                         # non-contiguous wildcard
    assert aces[1].src.prefixlen == 0                # covering superset
    dead = [f for f in analyze(aces) if f.rule_id == "E:2"]
    assert not dead, dead


def test_asa_flat_netmask_unchanged():
    aces, _ = parse_acls("access-list O extended deny ip any 10.0.0.0 255.0.0.0\n")
    assert str(aces[0].dst) == "10.0.0.0/8" and not aces[0].imprecise
