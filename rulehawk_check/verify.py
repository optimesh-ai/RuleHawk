"""`check`: the checker's answer for one record, the file's bytes, the
policy and the engine version.

Review of #52-#57, G10 and G11: the checker takes the policy itself and
writes each assertion's canonical form, with its zones resolved, on its
own. From its own reading of the file it re-derives the pending rows the
file's constructs rest on and the rows every reading of them cites, and
checks the sub-record lists at least those; it checks the scope sentence,
and that the blockers name every pending row and the deferral. A record
with any of these emptied or thinned is `checker-disagrees`.
"""
from __future__ import annotations

import hashlib
import json
from typing import List, Optional

from .derive import derive
from .rows import registry
from .split import split_bytes

CHECKER_DISAGREES = "checker-disagrees"
DEFERRAL = "checker-verdict-deferred"

# The sentence every record of a run with zones carries (a test pins it to
# the engine's).
SCOPE_SENTENCE = ("RuleHawk checked the interfaces this file configures; it read no "
                  "static route; zones not attached in this file are assumed not to "
                  "share a segment with another asserted zone.")

# Pending rows any file of the dialect rests on.
_FILE_PENDING = {
    "junos": ("junos-evolved-scope", "junos-lexing"),
    "panos": ("panos-release-scope", "panos-lexing", "panos-list-semantics",
              "panos-default-rules", "panos-any-meaning", "panos-rule-type-default",
              "panos-session-semantics", "panos-rule-order", "panos-one-line-order",
              "panos-rule-name-chars"),
    "iptables": ("iptables-lexing", "iptables-release-scope", "iptables-script-scope"),
}
# Rows every PAN-OS rule line cites: the one-line template and its keywords.
_PANOS_ROWS = ("panos-cli-create-rule", "panos-rule-name", "panos-source-zone",
               "panos-set-from-any", "panos-destination-zone", "panos-set-to-any",
               "panos-source-address", "panos-set-source-any",
               "panos-destination-address", "panos-application",
               "panos-set-application-any", "panos-service-any",
               "panos-set-service-any", "panos-action", "panos-one-line-form")
_IPTABLES_ROWS = ("iptables-accept-drop", "iptables-filter-default", "iptables-filter-chains")
_MATCH = ("source-address", "destination-address")


def _needed(dialect: str, mine: dict):
    """The pending rows and the cited rows the checker's own reading of
    the file rests on (none for a file with nothing in it)."""
    paths = list(mine)
    pending, rows = set(), set()
    if dialect == "junos" and paths:
        pending |= set(_FILE_PENDING["junos"])
        for p in paths:
            if p[0] == "interfaces" and len(p) >= 2:
                pending.add("junos-interface-name")
                rows.add("junos-top-interfaces")
            if p[0] == "interfaces" and len(p) >= 3:
                pending.add("junos-unit-number")
            if p[0] == "firewall":
                rows.add("junos-top-firewall")
            if len(p) >= 4 and p[0] == "firewall" and p[3].startswith("term "):
                rows |= {"junos-term-statement", "junos-term-order"}
            if len(p) >= 7 and p[5] in _MATCH:
                pending |= {"junos-v4-prefix", "junos-address-list-or"}
    elif dialect == "panos" and any(len(p) == 2 for p in paths):
        pending |= set(_FILE_PENDING["panos"])
        rows |= set(_PANOS_ROWS)
        for p, (values, _) in mine.items():
            if len(p) == 2 and any(values.get(k) != "any" for k in ("source", "destination")):
                pending.add("panos-v4-prefix")
    elif dialect == "iptables" and paths:
        pending |= set(_FILE_PENDING["iptables"])
        rows |= set(_IPTABLES_ROWS)
    return pending, rows


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _assertions(policy) -> List[str]:
    """Each assertion of the policy as canonical JSON, its zones resolved
    to the policy's CIDRs (a zone the policy does not name is None)."""
    if not isinstance(policy, dict):
        return []
    zones = policy.get("zones")
    if not isinstance(zones, dict):
        zones = {}
    out = []
    for kind in ("must_not_reach", "must_reach"):
        group = policy.get(kind)
        if not isinstance(group, list):
            continue
        for item in group:
            if not isinstance(item, dict):
                out.append(_canon({"kind": kind, "raw": item}))
                continue
            entry = dict(item)
            entry["kind"] = kind
            for end in ("src", "dst"):
                if end in item:
                    name = item[end]
                    entry[end + "_cidrs"] = zones.get(name) if isinstance(name, str) else None
            out.append(_canon(entry))
    return out


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


def _sub(sub: dict, lines: List[str], reg, zoned: bool) -> Optional[str]:
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
    pending, rows = _needed(dialect, mine)
    if not isinstance(sub.get("pending"), list) or not pending <= set(sub["pending"]):
        return "pending rows missing: " + ",".join(sorted(pending - set(sub.get("pending") or [])))
    if not isinstance(sub.get("rows"), list) or not rows <= set(sub["rows"]):
        return "rows missing: " + ",".join(sorted(rows - set(sub.get("rows") or [])))
    if sub.get("scope_assumptions") != ([SCOPE_SENTENCE] if zoned else []):
        return "scope assumptions"
    return None


def check(record: dict, raw: bytes, policy, engine_version: str) -> dict:
    """Whether the checker reads the file as the record states it."""
    try:
        if record.get("config_sha256") != hashlib.sha256(raw).hexdigest():
            return _no("hash")
        if record.get("assertions") != _assertions(policy):
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
        zoned = isinstance(policy, dict) and isinstance(policy.get("zones"), dict)
        for sub in subs:
            why = _sub(sub, lines, reg, zoned)
            if why:
                return _no(why)
        blockers = record.get("blockers")
        if not isinstance(blockers, list) or not all(isinstance(b, str) for b in blockers):
            return _no("blockers")
        want = {DEFERRAL} | {"pending:" + p for sub in subs for p in sub["pending"]}
        if not want <= set(blockers):
            return _no("blockers missing: " + ",".join(sorted(want - set(blockers))))
    except Exception as e:  # anything unexpected: no agreement
        return _no("checker error: " + type(e).__name__)
    return {"agrees": True, "reason": None, "detail": None}
