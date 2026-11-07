"""The one gate every all-clear goes through (design v4 section 13, with the
v4 errata R4-M2 and R4-L5).

An all-clear is a PASS, a VERIFIED claim, a NO_NEW_RISK compare, a
`segmentation-ok` / `connectivity-ok` finding, `coverage.state = complete`,
`passed: true` or exit 0 on an enforced run. Every site in rulehawk/ that
would give one asks this module through `emit()`, `exit_code()`, `passed()`
or `certified()`. While RULEHAWK_CERT is 0 they
give the fail-closed stopgap's answer (UNKNOWN, INDETERMINATE, exit 3), which
is what 0.4.1 already reports.

RULEHAWK_CERT is a compiled-in module constant. It is not read from the
environment and nothing overrides it at run time: slice 9 (the phase-3 flip)
changes the line below in source. Even then nothing passes until a
certificate verifies, and no certificate exists before slice 7.

tests/test_exitcodes_allclear.py scans rulehawk/ for all-clear literals
outside this module, against a pinned exemption list.
"""

from __future__ import annotations

from typing import Optional

from . import exitcodes

RULEHAWK_CERT = 0

# The all-clear vocabulary. Other modules name these only as the first
# argument of emit(), never as string literals.
PASS = "PASS"
VERIFIED = "VERIFIED"
NO_NEW_RISK = "NO_NEW_RISK"
SEG_OK = "segmentation-ok"
REACH_OK = "connectivity-ok"
COMPLETE = "complete"         # MCP coverage.state: every file is file-certified

# What each one is while it is not certified (the 0.4.1 stopgap's answers).
_STOPGAP = {
    PASS: "UNKNOWN",
    NO_NEW_RISK: "UNKNOWN",
    VERIFIED: "INDETERMINATE",
    SEG_OK: "segmentation-unknown",
    REACH_OK: "connectivity-unknown",
    COMPLETE: "partial",
}


def _require_certified(cert: object) -> bool:
    """The certificate check. It arrives with the independent checker (slice
    7); until then no certificate verifies."""
    return False


def certified(cert: Optional[object] = None) -> bool:
    """True only when RULEHAWK_CERT is 1 and `cert` verifies. False today."""
    return RULEHAWK_CERT == 1 and cert is not None and _require_certified(cert)


def emit(verdict: str, cert: Optional[object] = None) -> str:
    """`verdict` if it is certified, else the stopgap's answer for it. Only an
    all-clear verdict may be passed in; anything else is a programming error."""
    if verdict not in _STOPGAP:
        raise ValueError(f"allclear.emit takes an all-clear verdict, not {verdict!r}")
    return verdict if certified(cert) else _STOPGAP[verdict]


def passed(cert: Optional[object] = None) -> bool:
    """`passed: true` only for a certified PASS."""
    return emit(PASS, cert) == PASS


def exit_code(cert: Optional[object] = None) -> int:
    """The exit code of an enforced run with nothing at the threshold: 0 for a
    certified PASS, else 3 (UNKNOWN)."""
    return exitcodes.PASS if passed(cert) else exitcodes.UNKNOWN
