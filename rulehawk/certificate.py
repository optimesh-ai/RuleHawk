"""The certificate record for the allowlist (#42 design v2 sections 1.1 and
1.2, v4 sections 5 and 13), built in shadow only: nothing here changes a
verdict.

For a file the grammar parses, the record holds:
- `config_sha256`, the hash of the exact input bytes, before any lexing;
- `assertions`, each policy assertion as canonical JSON, its zones
  resolved to their CIDRs;
- `engine_version` and `declaration` (no platform declaration exists
  yet, so it is None);
- `subs`, one sub-record per reading (one dialect, no platform or release
  alternatives yet): the final model, the cited rows the grammar used, its
  pending rows, and the placement's scope assumptions;
- `blockers`, every reason the record cannot stand yet.

The independent checker (`rulehawk_check`) re-derives the final model
from the raw bytes and checks every field; the engine never reads its own
record as proof.

Blockers (v2 section 1.1 and the slices before this one): each pending row
(`pending:<id>`), a dual-read mismatch, a placement reason, every legacy
reason code and any legacy parse note, and always
`checker-verdict-deferred`: the checker's own evaluation of each assertion
is not built in this slice (decided by agent, unattended: it is the step
that could make `would_pass` true, so it waits for review). A record with
any blocker is not eligible, so no record is eligible in this slice.
"""
from __future__ import annotations

import hashlib
import json
from typing import List, Optional

from . import __version__

CHECKER_VERDICT_DEFERRED = "checker-verdict-deferred"
_KINDS = ("must_not_reach", "must_reach")


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def assertions(policy: Optional[dict]) -> List[str]:
    """Each policy assertion as canonical JSON, zones resolved to CIDRs (a
    zone the policy does not define resolves to None)."""
    if not isinstance(policy, dict):
        return []
    zones = policy.get("zones") if isinstance(policy.get("zones"), dict) else {}
    out = []
    for kind in _KINDS:
        items = policy.get(kind)
        for a in items if isinstance(items, list) else []:
            if not isinstance(a, dict):
                out.append(_canonical({"kind": kind, "raw": a}))
                continue
            r = dict(a)
            r["kind"] = kind
            for side in ("src", "dst"):
                if side in a:
                    r[side + "_cidrs"] = zones.get(a[side]) if isinstance(a[side], str) else None
            out.append(_canonical(r))
    return out


def build(raw: bytes, grammar: dict, model: dict, dual: Optional[dict],
          placement: Optional[dict], policy: Optional[dict],
          legacy: Optional[dict]) -> dict:
    """The record for one file the grammar parses."""
    blockers = [f"pending:{p}" for p in grammar.get("pending", [])]
    if not dual or dual.get("reason") == "reading-mismatch":
        blockers.append("dual-read:reading-mismatch")
    if placement and placement.get("reason"):
        blockers.append(f"placement:{placement['reason']}")
    if placement and placement.get("strict_reason"):
        blockers.append(f"placement-strict:{placement['strict_reason']}")
    if legacy is None:
        blockers.append("legacy:unread")
    else:
        blockers += [f"legacy:{c}" for c in sorted(set(legacy.get("reasons", [])))]
        if legacy.get("notes"):
            blockers.append("legacy:parse-notes")
    blockers.append(CHECKER_VERDICT_DEFERRED)
    return {
        "config_sha256": hashlib.sha256(raw).hexdigest(),
        "assertions": assertions(policy),
        "engine_version": __version__,
        "declaration": None,
        "subs": [{
            "dialect": model.get("dialect"),
            "model": model,
            "rows": list(grammar.get("rows", [])),
            "pending": list(grammar.get("pending", [])),
            "scope_assumptions": list((placement or {}).get("scope_assumptions", [])),
        }],
        "blockers": blockers,
    }


def eligible(record: dict) -> bool:
    """A record with any blocker cannot stand (none can, in this slice)."""
    return not record.get("blockers")
