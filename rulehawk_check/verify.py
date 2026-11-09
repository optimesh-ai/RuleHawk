"""`check`: the checker's answer for one record, the file's bytes, the
policy's assertions and the engine version."""
from __future__ import annotations

import hashlib
from typing import List, Optional

from .derive import derive
from .rows import registry
from .split import split_bytes

CHECKER_DISAGREES = "checker-disagrees"


def _no(detail: str) -> dict:
    return {"agrees": False, "reason": CHECKER_DISAGREES, "detail": detail}


def _flat(model: dict):
    out = {}
    for o in model["objects"]:
        p = tuple(o["path"])
        if p in out:
            return None
        out[p] = (dict(o["values"]), list(o["ordered"]))
    return out


def _first(a: dict, b: dict) -> str:
    for p in sorted(set(a) | set(b)):
        if a.get(p) != b.get(p):
            return "/".join(p) or "(root)"
    return "?"


def _sub(sub: dict, lines: List[str], reg) -> Optional[str]:
    dialect = sub.get("dialect")
    model = sub.get("model") or {}
    if model.get("dialect") != dialect:
        return "dialect"
    for cid in sub.get("rows", []):
        try:
            reg.resolve(cid)
        except KeyError:
            return "row does not resolve: " + str(cid)
    for cid in sub.get("pending", []):
        if cid not in reg.PENDING:
            return "not a pending row: " + str(cid)
    mine = derive(dialect, lines)
    if mine is None:
        return "the checker cannot read the file as " + str(dialect)
    theirs = _flat(model)
    if theirs is None:
        return "an object listed twice"
    if mine != theirs:
        return "model differs at " + _first(mine, theirs)
    return None


def check(record: dict, raw: bytes, assertions: List[str], engine_version: str) -> dict:
    """Whether the checker reads the file as the record states it."""
    try:
        if record.get("config_sha256") != hashlib.sha256(raw).hexdigest():
            return _no("hash")
        if record.get("assertions") != list(assertions):
            return _no("assertions")
        if record.get("engine_version") != engine_version:
            return _no("engine version")
        if record.get("declaration") is not None:
            return _no("declaration")
        subs = record.get("subs")
        if not isinstance(subs, list) or not subs:
            return _no("no reading")
        lines = split_bytes(raw)
        if lines is None:
            return _no("bytes the checker does not split")
        reg = registry()
        for sub in subs:
            why = _sub(sub, lines, reg)
            if why:
                return _no(why)
    except Exception as e:  # anything unexpected: no agreement
        return _no("checker error: " + type(e).__name__)
    return {"agrees": True, "reason": None, "detail": None}
