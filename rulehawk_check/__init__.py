"""The independent checker for the allowlist certificate record (#42
design v2 section 1.3, v4 section 5).

It imports only the standard library and `rulehawk/citations.py`, which it
loads by file path so that no engine module (not even the `rulehawk`
package) is imported; a test checks the whole closure. From the raw input
bytes it re-derives every field of the record with its own byte splitter
and its own reader per dialect, and checks the hash, the assertions, the
engine version, the declaration and every citation. Any difference, or
anything it cannot read, is `checker-disagrees`.

`evaluate` is its own evaluation of each assertion from its own reading
(slice 7, second part); see `evaluate.py`.
"""
from __future__ import annotations

from .evaluate import evaluate
from .verify import CHECKER_DISAGREES, check

__all__ = ["CHECKER_DISAGREES", "check", "evaluate"]
