"""One explicit sequence number is one ACL entry on the device.

Found by the Batfish oracle on 3 NX-OS and 1 EOS corpus configs that carry
the same ACL twice (two `show running-config` sections in one file):
    ip access-list copp-system-acl-eigrp
      10 permit eigrp any 224.0.0.10/32
    ...
    ip access-list copp-system-acl-eigrp
      10 permit eigrp any 224.0.0.10/32
RuleHawk appended the second copy as a new entry and reported it redundant
(dead); the device has one entry, and Batfish finds nothing unreachable."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.parse import parse_acls  # noqa: E402

_DUP = """ip access-list A
  10 permit eigrp any 224.0.0.10/32
  20 deny ip any any
!
ip access-list A
  10 permit eigrp any 224.0.0.10/32
"""


def test_identical_reentry_is_one_entry():
    aces, notes = parse_acls(_DUP)
    assert [a.raw.strip() for a in aces] == ["10 permit eigrp any 224.0.0.10/32", "20 deny ip any any"]
    assert not [f for f in analyze(aces) if f.kind == "redundant"]
    assert any("identical text" in n for n in notes)


def test_conflicting_entries_under_one_number_are_imprecise():
    aces, notes = parse_acls("ip access-list B\n  10 permit tcp any any eq 22\n"
                             "  20 deny ip any any\n  10 permit tcp any any eq 23\n")
    tens = [a for a in aces if a.raw.strip().startswith("10 ")]
    assert len(tens) == 2 and all(a.imprecise for a in tens)
    assert any("different entries" in n for n in notes)
