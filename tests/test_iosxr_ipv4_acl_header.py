"""IOS-XR `ipv4 access-list NAME` starts a new ACL.

Found by the Batfish oracle on the public corpus: the header was not
recognised, so every IOS-XR ACL in a file was merged into one "(unnamed)"
list and, being sequence-numbered, re-sorted by sequence — entries of ACL B
landed between entries of ACL A, changing first-match verdicts and producing
dead-rule claims Batfish refuted."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls  # noqa: E402

_T = """ipv4 access-list A
 10 deny ipv4 10.0.0.0 0.255.255.255 any
 20 permit ipv4 any any
ipv4 access-list B
 10 deny tcp any any eq 22
"""


def test_each_ipv4_access_list_is_its_own_acl():
    aces, _ = parse_acls(_T)
    by = {}
    for a in aces:
        by.setdefault(a.acl, []).append(a)
    assert set(by) == {"A", "B"}
    assert [a.action for a in by["A"]] == ["deny", "permit"]
    assert [a.dst_port.lo for a in by["B"]] == [22]
