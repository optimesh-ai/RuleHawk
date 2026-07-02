"""Pinning test: measure_pathground.py on the ten_router_acl corpus.

This test exercises the full measurement harness end-to-end with the real
Hammerhead binary and the committed synthetic corpus, asserting the EXACT
numbers produced by the 2026-W27 corpus run.  Any regression in the parser,
segcheck, path_ground logic, or Hammerhead reachability output will be caught
here.

The test is skipped (not failed) when the Hammerhead binary is not present,
so CI that lacks the binary stays green — the numbers are pinned for local
developer and pre-release runs.

Expected numbers (ten_router_acl / policy_corp_pci.json):
  - 10 config files, 10 routers with violations
  - 10 baseline violations (all critical, witness 10.20.0.1->10.10.0.1:445)
  -  5 path-confirmed  (hub-r1..r5  — CORP+PCI both locally connected)
  -  5 suppressed      (isle-r1..r5 — isolated, no route to 10.10.0.0/16)
  -  0 indeterminate   (no NAT in snapshot)
  - 50.0 % FP-suppression rate
  - soundness: post-grounding critical ⊆ pre-grounding critical
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make `from rulehawk.xxx` and `import scripts.measure_pathground` work.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts.measure_pathground import _corpus_hash, measure  # noqa: E402

_SNAPSHOT = _REPO_ROOT / "scripts" / "corpus" / "ten_router_acl"
_POLICY_FILE = _REPO_ROOT / "scripts" / "corpus" / "policy_corp_pci.json"
_HH_BINARY = (
    Path(__file__).resolve().parents[2]  # products/
    / "hammerhead" / "target" / "debug" / "hammerhead"
)

_POLICY = {
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}


def _hh_available() -> bool:
    return _HH_BINARY.is_file() and os.access(_HH_BINARY, os.X_OK)


@pytest.mark.skipif(not _hh_available(), reason="hammerhead binary not present")
def test_corpus_measurement_exact_numbers():
    """Pinned corpus run: exact counts must match the 2026-W27 measurement."""
    rows, pre_ids, post_ids = measure(_SNAPSHOT, _POLICY, str(_HH_BINARY))

    active = [r for r in rows if not r.get("skipped") and r["violations"] > 0]
    total_violations = sum(r["violations"] for r in active)
    total_confirmed  = sum(r["confirmed"]  for r in active)
    total_suppressed = sum(r["suppressed"] for r in active)
    total_indet      = sum(r["indeterminate"] for r in active)

    # Exact aggregate counts — any regression surfaces here first.
    assert total_violations == 10, f"expected 10 baseline violations, got {total_violations}"
    assert total_confirmed  == 5,  f"expected 5 path-confirmed, got {total_confirmed}"
    assert total_suppressed == 5,  f"expected 5 suppressed, got {total_suppressed}"
    assert total_indet      == 0,  f"expected 0 indeterminate, got {total_indet}"

    fp_rate = total_suppressed / total_violations * 100.0
    assert abs(fp_rate - 50.0) < 0.01, f"expected 50.0 % FP-suppression, got {fp_rate:.2f}%"

    # Hub routers: each must be path-confirmed (REACHABLE), not suppressed.
    hub_rows = {r["device"]: r for r in active if r["device"].startswith("hub-")}
    assert len(hub_rows) == 5, f"expected 5 hub routers, got {len(hub_rows)}"
    for dev, r in hub_rows.items():
        assert r["confirmed"] == 1, f"{dev}: expected confirmed=1, got {r['confirmed']}"
        assert r["suppressed"] == 0, f"{dev}: expected suppressed=0, got {r['suppressed']}"

    # Isle routers: each must be suppressed (UNREACHABLE), not confirmed.
    isle_rows = {r["device"]: r for r in active if r["device"].startswith("isle-")}
    assert len(isle_rows) == 5, f"expected 5 isle routers, got {len(isle_rows)}"
    for dev, r in isle_rows.items():
        assert r["suppressed"] == 1, f"{dev}: expected suppressed=1, got {r['suppressed']}"
        assert r["confirmed"] == 0, f"{dev}: expected confirmed=0, got {r['confirmed']}"

    # Soundness invariant: post-grounding critical ⊆ pre-grounding critical.
    unsound = post_ids - pre_ids
    assert not unsound, (
        f"SOUNDNESS FAILURE: {len(unsound)} post-grounding criticals have no "
        f"pre-grounding counterpart: {sorted(unsound)}"
    )


@pytest.mark.skipif(not _hh_available(), reason="hammerhead binary not present")
def test_corpus_hash_is_stable():
    """Corpus identity hash must stay constant for the committed file set."""
    cfg_files = sorted(
        p for p in _SNAPSHOT.iterdir()
        if p.is_file() and p.suffix == ".cfg"
    )
    assert len(cfg_files) == 10, f"expected 10 .cfg files, got {len(cfg_files)}"
    h = _corpus_hash(cfg_files)
    # This hash pins the exact file-name set.  Change it if you intentionally
    # add/rename corpus files and update the deliverable accordingly.
    assert h == "2bba9034b0a9e46e", (
        f"corpus file-list hash changed: got {h!r}; "
        "update this assertion AND the deliverable if the change is intentional"
    )
