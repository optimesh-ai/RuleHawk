"""`check`: the checker's answer for one record, the file's bytes, the
policy and the engine version.

Review of #52-#57, G10 and G11: the checker takes the policy itself and
writes each assertion's canonical form, with its zones resolved, on its
own. From its own reading of the file it re-derives the pending rows the
file's constructs rest on (the sub-record must list at least those) and,
in full, the cited rows (the sub-record must list exactly those; review
r2, G10b); it checks the scope sentence,
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
# The cited rows each construct of the checker's own reading rests on
# (review r2 of #52-#59, G10b: derived in full, so a dropped row is seen).
_BRACES = "junos-config-braces"
_LEAF = "junos-config-leaf-semicolon"
_J_TOP = {
    "interfaces": ("junos-top-statements", "junos-top-interfaces-keyword",
                   "junos-top-interfaces", "junos-interface-address-inet", _BRACES),
    "firewall": ("junos-top-statements", "junos-top-firewall-keyword",
                 "junos-top-firewall", _BRACES),
}
_J_THEN = {"accept": ("junos-then-statement", "junos-accept-terminating",
                      "junos-terminating-action"),
           "discard": ("junos-then-statement", "junos-discard-term",
                       "junos-terminating-action")}
_J_MATCH = {"source-address": ("junos-match-source-address", _BRACES),
            "destination-address": ("junos-match-destination-address", _BRACES)}
_PANOS_ROWS = ("panos-cli-create-rule", "panos-rule-name", "panos-source-zone",
               "panos-set-from-any", "panos-destination-zone", "panos-set-to-any",
               "panos-source-address", "panos-set-source-any",
               "panos-destination-address", "panos-application",
               "panos-set-application-any", "panos-service-any",
               "panos-set-service-any", "panos-action", "panos-one-line-form")
_IPT_TABLE = ("iptables-filter-default", "iptables-filter-chains")
_IPT_POLICY = ("iptables-synopsis-policy", "iptables-policy", "iptables-policy-end",
               "iptables-accept-drop") + _IPT_TABLE
_IPT_APPEND = ("iptables-synopsis-append", "iptables-rule-specification",
               "iptables-append", "iptables-first-match", "iptables-jump",
               "iptables-accept-drop") + _IPT_TABLE
_MATCH = ("source-address", "destination-address")


def _junos_rows(p, values) -> set:
    rows = set()
    n = len(p)
    if p[0] == "interfaces":
        if n == 1:
            rows |= set(_J_TOP["interfaces"])
        elif n == 2:
            rows |= {"junos-interface-address-inet", _BRACES}
        elif n == 3:
            rows |= {"junos-interface-family-hierarchy", _BRACES}
        elif n == 4:
            rows |= {"junos-interface-family-hierarchy", "junos-interface-address-inet"}
            if "address" in values:
                rows |= {"junos-interface-address", "junos-interface-address-inet", _LEAF}
        elif n == 5:
            rows |= {"junos-interface-filter-hierarchy", _BRACES}
            if "input" in values:
                rows |= {"junos-filter-input", "junos-filter-name", _LEAF}
    elif p[0] == "firewall":
        if n == 1:
            rows |= set(_J_TOP["firewall"])
        elif n == 2:
            rows |= {"junos-firewall-family-inet", "junos-firewall-family-inet-equivalent"}
        elif n == 3:
            rows |= {"junos-filter-statement", "junos-filter-name", _BRACES}
        elif n == 4:
            rows |= {"junos-term-statement", "junos-term-name", "junos-term-order"}
            if "then" in values:
                rows |= set(_J_THEN[values["then"]])
        elif n == 5:
            rows |= {"junos-from-statement", _BRACES}
        elif n == 6:
            rows |= set(_J_MATCH[p[5]])
        elif n == 7:
            rows.add(_LEAF)
    return rows


def _needed(dialect: str, mine: dict):
    """The pending rows and the cited rows the checker's own reading of
    the file rests on (none for a file with nothing in it)."""
    paths = list(mine)
    pending, rows = set(), set()
    if dialect == "junos" and paths:
        pending |= set(_FILE_PENDING["junos"])
        rows.add("junos-config-indent")
        for p, (values, _) in mine.items():
            rows |= _junos_rows(p, values)
            if p[0] == "interfaces" and len(p) >= 2:
                pending.add("junos-interface-name")
            if p[0] == "interfaces" and len(p) >= 3:
                pending.add("junos-unit-number")
            # G10a: any IPv4 prefix, an interface address included.
            if p[0] == "interfaces" and "address" in values:
                pending.add("junos-v4-prefix")
            if len(p) >= 7 and p[5] in _MATCH:
                pending |= {"junos-v4-prefix", "junos-address-list-or"}
    elif dialect == "panos" and any(len(p) == 2 for p in paths):
        pending |= set(_FILE_PENDING["panos"])
        for p, (values, _) in mine.items():
            if len(p) != 2:
                continue
            rows |= set(_PANOS_ROWS)
            if values.get("destination") == "any":
                rows.add("panos-set-destination-any")
            if values.get("action") == "allow":
                rows.add("panos-set-action-allow")
            if any(values.get(k) != "any" for k in ("source", "destination")):
                pending.add("panos-v4-prefix")
    elif dialect == "iptables" and paths:
        pending |= set(_FILE_PENDING["iptables"])
        for p, (values, _) in mine.items():
            if len(p) == 2 and "policy" in values:
                rows |= set(_IPT_POLICY)
            if len(p) == 3:
                rows |= set(_IPT_APPEND)
                w = p[2].split(" ")
                if "-s" in w:
                    rows |= {"iptables-source", "iptables-mask"}
                if "-d" in w:
                    rows |= {"iptables-destination", "iptables-source", "iptables-mask"}
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
    if not isinstance(sub.get("rows"), list) or set(sub["rows"]) != rows:
        got = set(sub.get("rows") or [])
        return ("rows differ: missing " + ",".join(sorted(rows - got)) +
                "; extra " + ",".join(sorted(got - rows)))
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
