"""Vendor-sync guard: docs/rulehawk/ must be byte-identical to rulehawk/.

The public hosted tool (docs/) runs the engine client-side via Pyodide from a
VENDORED copy of the rulehawk package (docs/rulehawk/).  If that copy drifts
from the canonical engine (rulehawk/) the hosted page silently serves a stale
parser — potentially the pre-soundness-fix parser that was live at launch while
the CLI had already been repaired.

This test is the pytest-enforced, stdlib-only, network-free form of
``scripts/check_vendor_sync.py``.  It fires on every ``python -m pytest`` run
and in CI — no rsync required, no network.

To fix a failure: run ``make sync-web`` then re-commit.
"""

from __future__ import annotations

import os
import sys

# Import the check function from the standalone script so both surfaces
# (pytest and direct invocation) share a single code path.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from check_vendor_sync import find_drifted_files  # noqa: E402


def test_vendored_engine_files_are_byte_identical():
    """Every .py file in rulehawk/ must have a byte-identical twin in docs/rulehawk/.

    Checked directly against the filesystem — not via worker.js ENGINE_MODULES —
    so a new engine module added to rulehawk/ but not yet synced to docs/rulehawk/
    is caught immediately, regardless of whether worker.js has been updated.

    Drift categories reported (any causes failure):
      MISSING  — file in rulehawk/ absent from docs/rulehawk/
      EXTRA    — file in docs/rulehawk/ absent from rulehawk/
      DRIFTED  — file present in both but bytes differ

    Fix: ``make sync-web`` re-syncs the vendored copy from the canonical source.
    """
    problems = find_drifted_files(_ROOT)
    assert problems == [], (
        "Vendored engine (docs/rulehawk/) has drifted from canonical (rulehawk/).\n"
        "Run 'make sync-web' to fix, then re-commit.\n\n"
        + "\n".join(f"  {p}" for p in problems)
    )
