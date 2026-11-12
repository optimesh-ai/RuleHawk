"""The checker's own byte splitter (v2 section 7): line feed only, and
every other byte printable ASCII. Anything else is unreadable (None)."""
from __future__ import annotations

from typing import List, Optional


def split_bytes(raw: bytes) -> Optional[List[str]]:
    if not raw:
        return None
    for b in raw:
        if b != 10 and not 32 <= b <= 126:
            return None
    out = raw.decode("ascii").split("\n")
    if out[-1] == "":
        out.pop()
    if not out or any(s == "" for s in out):
        return None
    return out
