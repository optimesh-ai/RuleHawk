#!/usr/bin/env python3
"""Path-grounding false-positive suppression measurement harness.

Stdlib-only.  Takes a snapshot directory (one config file per router), a
segmentation-policy JSON, and optionally the hammerhead binary path.  For
every config in the snapshot the script:

  1. Auto-detects the vendor and parses ACLs.
  2. Extracts the device hostname (used as ``--from`` in reachability queries).
  3. Runs segcheck (baseline, no path-grounding) and records violations.
  4. Initialises ``HammerheadReachOracle`` with the full snapshot dir + device
     hostname and runs ``path_ground`` on the baseline violations.
  5. Classifies each finding as PATH-CONFIRMED, SUPPRESSED (infeasible), or
     INDETERMINATE.

After all configs are processed the script:

  * Aggregates and prints a structured report with per-router breakdown.
  * Asserts the soundness invariant: post-grounding critical rule_ids are a
    strict subset of pre-grounding critical rule_ids (loudly fails otherwise).
  * Exits 0 on success, 2 on bad arguments, 3 on soundness failure.

Usage (from products/rulehawk/):
    python3 scripts/measure_pathground.py \\
        scripts/corpus/ten_router_acl \\
        scripts/corpus/policy_corp_pci.json \\
        [/path/to/hammerhead]

Reproducibility: the only non-determinism is the Hammerhead binary itself,
which is deterministic (BTreeMap throughout, byte-identical across runs for the
same snapshot).  The file-list hash printed in the header pins the corpus
identity.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

# Allow `from rulehawk.xxx import yyy` whether invoked from the repo root,
# from scripts/, or from an arbitrary cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.parse_iptables import detect as _det_ipt, parse_iptables  # noqa: E402
from rulehawk.parse_junos import detect as _det_jun, parse_junos  # noqa: E402
from rulehawk.parse_panos import detect as _det_pan, parse_panos  # noqa: E402
from rulehawk.pathground import HammerheadReachOracle, path_ground  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HOSTNAME_IOS_RE = re.compile(r"^hostname\s+(\S+)", re.MULTILINE)
_HOSTNAME_JUN_RE = re.compile(r"host-name\s+(\S+?)\s*;", re.MULTILINE)

# Config file extensions to consider (policy JSON, README etc. are excluded).
_CFG_EXTS = {".cfg", ".conf", ".txt", ".rules"}


def _extract_hostname(text: str) -> str | None:
    """Best-effort: IOS `hostname X`, then Junos `host-name X;`."""
    m = _HOSTNAME_IOS_RE.search(text) or _HOSTNAME_JUN_RE.search(text)
    return m.group(1) if m else None


def _parse_config(text: str):
    """Auto-detect vendor and parse; return (aces, notes)."""
    if _det_jun(text):
        return parse_junos(text)
    if _det_pan(text):
        return parse_panos(text)
    if _det_ipt(text):
        return parse_iptables(text)
    return parse_acls(text)


def _corpus_hash(files: list[Path]) -> str:
    """Stable SHA-256 (first 16 hex chars) over the sorted file-name list.

    This pins corpus *identity* (which configs are present) without hashing
    content — adding or renaming a file changes the hash, catching silent drift.
    The full content hash would be stronger but is overkill for a measurement
    harness where the snapshot is committed to the repo and visible in git log.
    """
    names = sorted(p.name for p in files)
    return hashlib.sha256("\n".join(names).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Core measurement loop
# ---------------------------------------------------------------------------

def measure(
    snapshot_dir: Path,
    policy: dict,
    hh_binary: str,
) -> tuple[list[dict], set[str], set[str]]:
    """Process every config in snapshot_dir.  Return (rows, pre_ids, post_ids).

    ``rows`` is a list of per-router dicts.
    ``pre_ids`` / ``post_ids`` track scoped rule_ids of critical findings
    before / after grounding — used for the soundness check.
    """
    cfg_files = sorted(
        p for p in snapshot_dir.iterdir()
        if p.is_file() and p.suffix in _CFG_EXTS
    )
    if not cfg_files:
        raise ValueError(f"no config files found in {snapshot_dir}")

    rows: list[dict] = []
    pre_critical_ids: set[str] = set()
    post_critical_ids: set[str] = set()

    for cfg_path in cfg_files:
        text = cfg_path.read_text(encoding="utf-8", errors="ignore")
        hostname = _extract_hostname(text)
        if hostname is None:
            # Can't determine from_device -> oracle would be indeterminate for
            # every witness.  Skip and note; don't silently eat results.
            rows.append({
                "device": f"(no-hostname:{cfg_path.name})",
                "file": cfg_path.name,
                "violations": 0,
                "confirmed": 0,
                "suppressed": 0,
                "indeterminate": 0,
                "skipped": True,
            })
            continue

        aces, _ = _parse_config(text)
        if not aces:
            continue  # empty / pure-comment file

        baseline = check_segmentation(aces, policy)
        violations = [f for f in baseline if f.kind == "segmentation-violation"]
        if not violations:
            # A clean router (segcheck says OK) — no FP to suppress; skip.
            continue

        # Track pre-grounding critical scope: "filename::rule_id" to avoid
        # collisions across routers that share ACL names.
        for f in violations:
            scoped = f"{cfg_path.name}::{f.rule_id}"
            pre_critical_ids.add(scoped)

        oracle = HammerheadReachOracle(
            snapshot_dir=str(snapshot_dir),
            from_device=hostname,
            binary=hh_binary,
        )
        grounded = path_ground(violations, oracle)

        confirmed = sum(
            1 for f in grounded
            if f.kind == "segmentation-violation" and "PATH-CONFIRMED" in f.message
        )
        suppressed = sum(
            1 for f in grounded if f.kind == "segmentation-infeasible-path"
        )
        indeterminate = sum(
            1 for f in grounded if "INDETERMINATE" in f.message
        )

        for f in grounded:
            if f.severity == "critical":
                post_critical_ids.add(f"{cfg_path.name}::{f.rule_id}")

        rows.append({
            "device": hostname,
            "file": cfg_path.name,
            "violations": len(violations),
            "confirmed": confirmed,
            "suppressed": suppressed,
            "indeterminate": indeterminate,
            "skipped": False,
        })

    return rows, pre_critical_ids, post_critical_ids


# ---------------------------------------------------------------------------
# Report + soundness assertion
# ---------------------------------------------------------------------------

def report_and_check(
    rows: list[dict],
    pre_critical_ids: set[str],
    post_critical_ids: set[str],
    snapshot_dir: Path,
    policy_file: Path,
    hh_binary: str,
    cfg_files: list[Path],
) -> int:
    """Print the measurement report.  Return 0 on PASS, 3 on soundness failure."""

    # Soundness: post-grounding critical ⊆ pre-grounding critical.
    unsound = post_critical_ids - pre_critical_ids
    soundness_ok = len(unsound) == 0

    total_violations = sum(r["violations"] for r in rows if not r.get("skipped"))
    total_confirmed  = sum(r["confirmed"]  for r in rows if not r.get("skipped"))
    total_suppressed = sum(r["suppressed"] for r in rows if not r.get("skipped"))
    total_indet      = sum(r["indeterminate"] for r in rows if not r.get("skipped"))
    routers_with_findings = sum(
        1 for r in rows if not r.get("skipped") and r["violations"] > 0
    )
    fp_rate = (
        total_suppressed / total_violations * 100.0 if total_violations > 0 else 0.0
    )

    w = 72
    print("=" * w)
    print("PATH-GROUNDING FALSE-POSITIVE SUPPRESSION MEASUREMENT")
    print("=" * w)
    print(f"Snapshot:         {snapshot_dir}")
    print(f"Corpus identity:  {len(cfg_files)} config file(s), "
          f"sha256-filelist={_corpus_hash(cfg_files)}")
    print(f"Policy:           {policy_file}")
    print(f"Hammerhead:       {hh_binary}")
    print()

    active = [r for r in rows if not r.get("skipped") and r["violations"] > 0]
    if active:
        hdr = f"  {'Device':<20} {'File':<20} {'Base':>5} {'Conf':>6} {'Supp':>6} {'Ind':>5}"
        print("Per-router breakdown:")
        print(hdr)
        print(f"  {'-'*20} {'-'*20} {'-'*5} {'-'*6} {'-'*6} {'-'*5}")
        for r in active:
            print(f"  {r['device']:<20} {r['file']:<20} "
                  f"{r['violations']:>5} {r['confirmed']:>6} "
                  f"{r['suppressed']:>6} {r['indeterminate']:>5}")
        print()

    print("Aggregate:")
    print(f"  Config files parsed:          {len(cfg_files)}")
    print(f"  Routers with violations:      {routers_with_findings}")
    print(f"  Baseline violations (total):  {total_violations}")
    print(f"  Path-confirmed  (REACHABLE):  {total_confirmed}")
    print(f"  Suppressed      (UNREACHABLE):{total_suppressed}")
    print(f"  Indeterminate:                {total_indet}")
    print(f"  FP-suppression rate:          {fp_rate:.1f}%"
          f"  ({total_suppressed}/{total_violations})")
    print()

    if soundness_ok:
        print("Soundness: post-grounding critical ⊆ pre-grounding critical — PASS")
    else:
        print("Soundness: FAIL — post-grounding introduced new critical(s):")
        for sid in sorted(unsound):
            print(f"    {sid}")

    print("=" * w)

    if not soundness_ok:
        print("SOUNDNESS FAILURE: aborting with exit code 3", file=sys.stderr)
        return 3
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "usage: measure_pathground.py SNAPSHOT_DIR POLICY_FILE [HH_BINARY]",
            file=sys.stderr,
        )
        return 2

    snapshot_dir = Path(argv[0]).resolve()
    policy_file  = Path(argv[1]).resolve()
    hh_binary    = argv[2] if len(argv) > 2 else "hammerhead"

    if not snapshot_dir.is_dir():
        print(f"error: snapshot dir not found: {snapshot_dir}", file=sys.stderr)
        return 2
    if not policy_file.is_file():
        print(f"error: policy file not found: {policy_file}", file=sys.stderr)
        return 2

    try:
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot read policy: {exc}", file=sys.stderr)
        return 2

    cfg_files = sorted(
        p for p in snapshot_dir.iterdir()
        if p.is_file() and p.suffix in _CFG_EXTS
    )
    if not cfg_files:
        print(f"error: no config files found in {snapshot_dir}", file=sys.stderr)
        return 2

    try:
        rows, pre_ids, post_ids = measure(snapshot_dir, policy, hh_binary)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return report_and_check(
        rows, pre_ids, post_ids,
        snapshot_dir, policy_file, hh_binary, cfg_files,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
