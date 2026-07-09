"""Deterministic guard: rulehawk/ and docs/rulehawk/ must be byte-identical.

The public hosted tool (docs/rulehawk/) is a vendored copy of the canonical
engine (rulehawk/).  If they drift the hosted page silently serves a stale
parser — potentially a pre-soundness-fix build while the CLI is already fixed.

This guard is stdlib-only, deterministic, and network-free.  It is called by
``tests/test_vendor_sync.py`` (so pytest enforces it in CI) and can also be
invoked directly by developers:

    python scripts/check_vendor_sync.py          # from repo root
    python scripts/check_vendor_sync.py --root /path/to/rulehawk-repo

After any engine change, run ``make sync-web`` to bring the vendored copy
back into sync, then run this script (or pytest) to confirm it passed.

Exit codes
----------
    0  — every engine .py file is byte-identical; vendored copy is in sync.
    1  — one or more files have drifted or are missing; run ``make sync-web``.
"""

from __future__ import annotations

import argparse
import os
import sys


def find_drifted_files(root: str) -> list[str]:
    """Return a sorted list of problem descriptions, empty when fully in sync.

    Checks every .py file in <root>/rulehawk/ against <root>/docs/rulehawk/:
      - MISSING  — file exists in canonical but is absent from the vendor copy.
      - EXTRA    — file exists in the vendor copy but is absent from canonical.
      - DRIFTED  — file exists in both but the bytes differ.

    Args:
        root: absolute path to the repository root (parent of rulehawk/ and docs/).

    Returns:
        Sorted list of human-readable problem strings; empty list means in sync.
    """
    canonical_dir = os.path.join(root, "rulehawk")
    vendored_dir = os.path.join(root, "docs", "rulehawk")

    canonical_files: set[str] = {
        f for f in os.listdir(canonical_dir) if f.endswith(".py")
    }
    vendored_files: set[str] = {
        f for f in os.listdir(vendored_dir) if f.endswith(".py")
    }

    problems: list[str] = []

    # Files in canonical but absent from the vendored copy.
    for name in sorted(canonical_files - vendored_files):
        problems.append(
            f"MISSING  docs/rulehawk/{name}  (present in rulehawk/ but absent from docs/rulehawk/)"
        )

    # Extra files in the vendored copy that have no canonical counterpart.
    for name in sorted(vendored_files - canonical_files):
        problems.append(
            f"EXTRA    docs/rulehawk/{name}  (present in docs/rulehawk/ but absent from rulehawk/)"
        )

    # Files present in both — assert byte-for-byte identity.
    for name in sorted(canonical_files & vendored_files):
        canon_path = os.path.join(canonical_dir, name)
        vendor_path = os.path.join(vendored_dir, name)
        with open(canon_path, "rb") as fh:
            canon_bytes = fh.read()
        with open(vendor_path, "rb") as fh:
            vendor_bytes = fh.read()
        if canon_bytes != vendor_bytes:
            problems.append(
                f"DRIFTED  docs/rulehawk/{name}  (content differs from rulehawk/{name})"
            )

    return sorted(problems)


def main(argv: list[str] | None = None) -> int:
    """Entry point: print results and return 0 (in sync) or 1 (drifted)."""
    parser = argparse.ArgumentParser(
        description="Assert docs/rulehawk/ is byte-identical to rulehawk/.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--root",
        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        help="Repo root directory (default: parent of scripts/)",
    )
    args = parser.parse_args(argv)

    problems = find_drifted_files(args.root)
    if problems:
        print(
            "FAIL: vendored engine (docs/rulehawk/) has drifted from canonical "
            "(rulehawk/) — run 'make sync-web' to fix:"
        )
        for p in problems:
            print(f"  {p}")
        return 1

    py_count = len(
        [f for f in os.listdir(os.path.join(args.root, "rulehawk")) if f.endswith(".py")]
    )
    print(f"OK: {py_count} engine .py files are byte-identical in docs/rulehawk/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
