"""ASA `name ADDRESS ALIAS` aliases are resolved in ACLs and objects.

9 of 43 public ASA configs in the measured corpus use `names`; every ACE
naming an alias failed closed as imprecise (INDETERMINATE). Aliases bound to a
literal address are substituted for address operands only — never for an
ACL, object or group name that happens to be spelled the same.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.parse import parse_acls  # noqa: E402

CFG = """ASA Version 9.8(4)
names
name 10.20.0.0 corp-net
name 10.10.0.5 pci-db
name 10.99.0.1 web
object network web
 host 10.10.0.7
access-list corp-net extended permit tcp corp-net 255.255.0.0 host pci-db eq 1433
access-list corp-net extended permit ip corp-net 255.255.0.0 object web
"""


def test_aliases_resolve_to_exact_aces():
    aces, notes = parse_acls(CFG)
    assert [(a.acl, str(a.src), str(a.dst), a.imprecise) for a in aces] == [
        ("corp-net", "10.20.0.0/16", "10.10.0.5/32", False),
        ("corp-net", "10.20.0.0/16", "10.10.0.7/32", False),
    ], notes


def test_unknown_word_still_fails_closed():
    aces, _ = parse_acls("access-list A extended permit ip nosuchname 255.255.0.0 any\n")
    assert all(a.imprecise for a in aces)
