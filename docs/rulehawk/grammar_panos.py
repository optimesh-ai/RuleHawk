"""The PAN-OS token language and its productions for the allowlist (#42
design v2 sections 6-8, v3 sections 6.1, 7, 8 and 9.2, v4 sections 3 and
12-14). Shadow only: nothing here changes a verdict.

A production exists only for a row cited in `citations.py`; each names the
rows it rests on, and every one must resolve (a pending row cannot). What the
grammar reads:
- the set form only, and of it only whole security rules on one line, in
  the order of the knowledge-base template (`panos-cli-create-rule`) with
  `source` in the place the set-format article prints it
  (`panos-set-source-any`):
  `set rulebase security rules NAME from any to any source ADDR
  destination ADDR application any service any action allow|deny`;
- zones, application and service `any` only; an address `any` or one IPv4
  prefix; no object name, list, range, negation, log or profile setting;
- rule names of letters, digits and hyphens, starting with a letter or
  digit, up to 63 characters (`panos-rule-name` states the length only, so
  the set is narrowed), never a keyword;
- LF line ends only, printable ASCII only, no indentation, tokens separated
  by single spaces with no trailing space, keywords in their exact
  lowercase spelling. A quote, a `[ ]` list, a comment or a blank line is
  off: `panos-lexing` is pending;
- each rule name once: setting a rule again adds to its list attributes,
  and `panos-list-semantics` is pending (v3 section 6.1). `move`, `delete`,
  `rename`, `override` and `disabled` have no production.

Each line must match exactly one production: none is
`line-not-allowlisted`, two is `parse-ambiguous` (v3 section 8). No
production names an object or a zone, so nothing can be `config-incomplete`
yet (v3 section 9.2).

Parsing a file is not a certificate: `panos-rule-order` and
`panos-release-scope` are pending, and the certificate comes in slice 7.
"""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

from .citations import resolve
from .grammar_junos import (_TOKEN, _V4PREFIX, LINE_NOT_ALLOWLISTED,
                            PARSE_AMBIGUOUS, Klass, Production)

_PRINTABLE = re.compile(r"[\x20-\x7e]*")
MODE = "line"

# Rows every production rests on: the one-line template, its keywords, and
# the `any` values the set-format article prints.
_COMMON = (
    "panos-cli-create-rule", "panos-rule-name",
    "panos-source-zone", "panos-set-from-any",
    "panos-destination-zone", "panos-set-to-any",
    "panos-source-address", "panos-set-source-any",
    "panos-destination-address",
    "panos-application", "panos-set-application-any",
    "panos-service-any", "panos-set-service-any",
    "panos-action",
)


def _table() -> Tuple[Tuple[Tuple[str, ...], Tuple[str, ...]], ...]:
    out = []
    for src in ("any", "V4PREFIX"):
        for dst in ("any", "V4PREFIX"):
            for act in ("allow", "deny"):
                slots = ("set", "rulebase", "security", "rules", "RULENAME",
                         "from", "any", "to", "any", "source", src,
                         "destination", dst, "application", "any",
                         "service", "any", "action", act)
                cites = _COMMON
                if dst == "any":
                    cites += ("panos-set-destination-any",)
                if act == "allow":
                    cites += ("panos-set-action-allow",)
                out.append((slots, cites))
    return tuple(out)


_PRODUCTION_TABLE = _table()

KEYWORDS: FrozenSet[str] = frozenset(
    s for slots, _ in _PRODUCTION_TABLE for s in slots if not s.isupper())

CLASSES: Dict[str, Klass] = {
    "RULENAME": Klass(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", KEYWORDS),
    "V4PREFIX": Klass(_V4PREFIX, KEYWORDS),
}

PRODUCTIONS: Tuple[Production, ...] = tuple(
    Production(MODE, slots, None, cites) for slots, cites in _PRODUCTION_TABLE)

# Every production's rows resolve at import: a pending row raises here.
for _p in PRODUCTIONS:
    for _cid in _p.cites:
        resolve(_cid)


def shape_problems(prods: Iterable[Production], classes: Dict[str, Klass]) -> List[str]:
    """Every production is a non-empty fixed token sequence: each slot a
    literal over the token alphabet or a known class that holds no space."""
    out = []
    for p in prods:
        if not p.slots:
            out.append("empty production")
            continue
        for s in p.slots:
            if s in classes:
                if re.search(r"(?<!\\) |\\s", classes[s].pattern):
                    out.append(f"{p.slots}: class {s} can hold a space")
            elif s.isupper():
                out.append(f"{p.slots}: {s!r} is no known class")
            elif not _TOKEN.fullmatch(s):
                out.append(f"{p.slots}: {s!r} is no literal")
    return out


def _result(reason: Optional[str], line: Optional[int], rows) -> dict:
    return {"accepted": reason is None, "reason": reason, "line": line,
            "rows": sorted(rows), "tags": []}


def _match(toks: List[str]) -> List[Production]:
    out = []
    for p in PRODUCTIONS:
        if len(p.slots) != len(toks):
            continue
        if all((CLASSES[s].matches(t) if s in CLASSES else s == t)
               for s, t in zip(p.slots, toks)):
            out.append(p)
    return out


def parse(raw: bytes) -> dict:
    """The grammar result for one file's raw bytes."""
    lines = raw.decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]          # the LF that ends the last line
    if not lines:
        return _result(LINE_NOT_ALLOWLISTED, None, ())
    rows = set()
    names = set()
    for n, ln in enumerate(lines, 1):
        if not ln or not _PRINTABLE.fullmatch(ln):
            return _result(LINE_NOT_ALLOWLISTED, n, rows)
        toks = ln.split(" ")
        if not all(_TOKEN.fullmatch(t) for t in toks):
            return _result(LINE_NOT_ALLOWLISTED, n, rows)
        hits = _match(toks)
        if not hits:
            return _result(LINE_NOT_ALLOWLISTED, n, rows)
        if len(hits) > 1:
            return _result(PARSE_AMBIGUOUS, n, rows)
        name = toks[hits[0].slots.index("RULENAME")]
        if name in names:
            return _result(LINE_NOT_ALLOWLISTED, n, rows)
        names.add(name)
        rows.update(hits[0].cites)
    return _result(None, None, rows)
