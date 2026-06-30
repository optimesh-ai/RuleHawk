"""Parse Cisco NX-OS IP access-lists into RuleHawk ``ACE``s.

NX-OS ACL syntax is a superset of IOS extended ACL syntax: the same
``ip access-list NAME`` / ``permit`` / ``deny`` structure, with optional
per-entry sequence numbers (10, 20, 30 …) and NX-OS-specific keywords
(``statistics per-entry``, ``fragments``, ``log``, ``dscp``) that the
existing IOS parser already handles as trailing non-type tokens.

This module is therefore a *thin detection wrapper* around ``parse_acls``
from the IOS/ASA frontend: it contributes a reliable NX-OS heuristic so the
auto-detect path routes NX-OS configs here instead of lumping them in with
``ios-asa``.  The vendor label is emitted as ``nxos`` so output clearly
identifies the platform without changing any analysis logic.

NX-OS distinguishing markers (all absent from plain IOS/ASA dumps):
  * ``version X.Y(Z)``          — NXOS version line (parens in version string)
  * ``feature ...``             — NX-OS feature enable commands
  * ``interface Ethernet``      — NX-OS Ethernet port naming convention
  * ``statistics per-entry``    — NX-OS ACL statistics keyword
  * ``vlan configuration``      — NX-OS VLAN config block keyword

We require at least ONE NX-OS marker alongside an ``ip access-list`` entry
to avoid misrouting IOS configs that share individual keywords.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .model import ACE
from .parse import parse_acls

# NX-OS-specific pattern: version with parens (7.0(3)I7(9)), feature lines,
# NX-OS Ethernet naming, per-entry statistics, or vlan configuration block.
_NXOS_MARKERS = re.compile(
    r"(?:^version\s+\d+\.\d+\(\d+\))"           # version 9.3(10)
    r"|(?:^feature\s+\S)"                         # feature interface-vlan
    r"|(?:^interface\s+Ethernet\d+/\d)"           # interface Ethernet1/1
    r"|(?:\bstatistics\s+per-entry\b)"            # statistics per-entry
    r"|(?:^vlan\s+configuration\b)",              # vlan configuration 10
    re.MULTILINE | re.IGNORECASE,
)

_ACL_HEADER = re.compile(r"(?i)^ip\s+access-list\s+\S", re.MULTILINE)


def detect(text: str) -> bool:
    """Heuristic: does ``text`` look like a Cisco NX-OS ACL config?

    Requires both a NX-OS-specific marker AND an ``ip access-list`` header.
    Plain IOS configs share the ACL syntax but lack the NX-OS markers; plain
    NX-OS show-tech dumps without ACLs are uninteresting and rightly fall
    through to ``ios-asa`` (which will produce ``no_rules_parsed``).
    """
    return bool(_NXOS_MARKERS.search(text) and _ACL_HEADER.search(text))


def parse_nxos(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse NX-OS IP access-lists.  Delegates entirely to ``parse_acls``
    (the IOS/ASA frontend): NX-OS ACL syntax is a strict superset of IOS
    extended-ACL syntax, so every ACE form already parses correctly.  The
    vendor label is set by the ``gate`` layer (``audit_file`` stores
    ``vlabel`` from ``_pick_parser``); this function just returns the same
    ``(aces, notes)`` tuple as every other frontend.
    """
    return parse_acls(text)
