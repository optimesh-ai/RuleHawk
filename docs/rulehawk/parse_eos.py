"""Parse Arista EOS IP access-lists into RuleHawk ``ACE``s.

Arista EOS uses IOS-like ACL syntax with a few cosmetic differences:
  * Config headers produced by ``show running-config`` start with a
    ``! Command: show running-config`` comment block and ``! device: HOSTNAME``
    lines — unique to EOS.
  * ``show ip access-lists`` output prepends ``IP Access List NAME``.
  * Sequence numbers appear on each ACE line (``10 permit tcp ...``).
  * Remark lines use ``remark`` (same as IOS).
  * EOS uses ``match ip`` / ``match ipv6`` in route-maps, but ACLs remain
    ``ip access-list NAME``.

All of these are already handled by the IOS/ASA frontend (``parse_acls``):
sequence numbers are stripped by ``_entry_tokens``; remark lines are skipped;
``ip access-list NAME`` sets the current ACL context.  EOS-specific show-format
headers (``IP Access List NAME``) look like plain text lines to the parser and
are silently skipped (no ``permit``/``deny`` keyword).

This module contributes a reliable EOS detection heuristic so the auto-detect
path labels the vendor as ``eos`` in reports, making it immediately clear to
the operator that EOS config was processed (not generic ``ios-asa``).

EOS distinguishing markers:
  * ``! device: HOSTNAME (EOS-...)``  — show-output header with EOS version tag
  * ``! Command: show``               — EOS show-command provenance comment
  * ``EOS`` in the ``! boot system``  line or boot-image path
  * ``management api http-commands``  — EOS-only management API block
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .model import ACE
from .parse import parse_acls

# EOS-specific text patterns that do not appear in IOS/ASA or NX-OS configs.
_EOS_MARKERS = re.compile(
    r"(?:^!\s*device:\s*\S+.*?EOS)"              # ! device: HOSTNAME (EOS-4.29.2F)
    r"|(?:^!\s*Command:\s*show\b)"                # ! Command: show running-config
    r"|(?:^management\s+api\s+http-commands\b)"   # management api http-commands
    r"|(?:boot\s+system\s+flash:\S*EOS)",         # boot system flash:EOS64-4.29.img
    re.MULTILINE | re.IGNORECASE,
)

_ACL_HEADER = re.compile(
    r"(?i)(?:^ip\s+access-list\s+\S|^IP\s+Access\s+List\s+\S)",
    re.MULTILINE,
)

# EOS ``show ip access-lists`` uses ``IP Access List NAME`` as the header line.
# Rewrite it into the ``ip access-list NAME`` form that ``parse_acls`` recognises.
_EOS_ACL_HDR_RE = re.compile(r"(?im)^IP\s+Access\s+List\s+(\S+)")


def detect(text: str) -> bool:
    """Heuristic: does ``text`` look like Arista EOS ACL output?

    Requires a EOS-specific marker AND an ACL header.  IOS/ASA and NX-OS
    configs share the ACL syntax but lack the EOS markers.
    """
    return bool(_EOS_MARKERS.search(text) and _ACL_HEADER.search(text))


def parse_eos(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse Arista EOS IP access-lists.

    Normalises EOS ``show ip access-lists`` headers (``IP Access List NAME``)
    to the canonical ``ip access-list NAME`` form that ``parse_acls`` already
    handles, then delegates — EOS ACE syntax is a strict subset of IOS extended
    ACL syntax and requires no additional parsing logic.
    """
    normalised = _EOS_ACL_HDR_RE.sub(r"ip access-list \1", text)
    return parse_acls(normalised)
