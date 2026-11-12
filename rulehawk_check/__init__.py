"""The independent checker for the allowlist certificate record (#42
design v2 section 1.3, v4 section 5).

It imports only the standard library and `rulehawk/citations.py`, which it
loads by file path so that no engine module (not even the `rulehawk`
package) is imported; a test checks the whole closure. From the raw input
bytes it re-derives every field of the record with its own byte splitter
and its own reader per dialect, and checks the hash, the assertions, the
engine version, the declaration and every citation. It takes the raw
policy and resolves the zones itself, and from its own reading it
re-derives the pending rows and rows the file rests on and checks the
scope sentence and the blockers (review of #52-#57, G10, G11). Any
difference, or anything it cannot read, is `checker-disagrees`.

`evaluate` is its own evaluation of each assertion from its own reading
(slice 7, second part); see `evaluate.py`.
"""
from __future__ import annotations

from .evaluate import evaluate
from .verify import CHECKER_DISAGREES, check

__all__ = ["CHECKER_DISAGREES", "check", "evaluate"]
