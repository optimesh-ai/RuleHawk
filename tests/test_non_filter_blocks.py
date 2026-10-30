"""Lines that merely contain permit/deny are not packet filters.

Measured on a 437-file public corpus: 480 of 868 IOS notes and 511 of 655 EOS
notes were route-map / prefix-list / community-list lines, marking files
"partial" with nothing to review. Worse, the entries of an NX-OS/EOS
`mac access-list` were appended to the PREVIOUS IP ACL as opaque fail-closed
rules (56 in 4 files), and an EOS `ip prefix-list` block's `seq N permit ...`
lines were reported under the last IP ACL.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls  # noqa: E402

CFG = """ip access-list E1
   10 permit tcp any any eq 22
ip prefix-list P1
   seq 10 permit 10.0.0.0/8 le 24
ip prefix-list P2 seq 5 deny 2.0.0.0/8 le 32
route-map RM permit 10
 match ip address prefix-list P1
ip community-list standard C permit 65000:1
mac access-list M1
  10 permit any any
  20 deny any any
ip access-list E2
   10 deny ip any any
same-security-traffic permit inter-interface
xlate per-session deny tcp any4 any4
no arp permit-nonconnected
"""


def test_only_ip_acl_entries_are_rules():
    aces, notes = parse_acls(CFG)
    assert [(a.acl, a.raw) for a in aces] == [("E1", "10 permit tcp any any eq 22"),
                                             ("E2", "10 deny ip any any")]


def test_only_the_mac_acl_is_noted():
    _, notes = parse_acls(CFG)
    assert len(notes) == 1 and "mac access-list M1" in notes[0], notes


def test_acl_after_a_block_is_still_parsed_unindented():
    aces, _ = parse_acls("route-map RM permit 10\n match tag 5\n"
                         "access-list 101 permit tcp any any eq 80\n")
    assert [a.acl for a in aces] == ["101"]
