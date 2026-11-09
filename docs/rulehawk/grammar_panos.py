"""The PAN-OS token language and its productions for the allowlist (#42
design v2 sections 6-8, v3 sections 6.1, 7, 8 and 9.2, v4 sections 3 and
12-14). Shadow only: nothing here changes a verdict.

A production exists only for a row cited in `citations.py`; each names the
rows it rests on, and every one must resolve (a pending row cannot). What the
grammar reads:
- the set form only, and of it only one whole security rule per file, on
  one line. The create template (`panos-cli-create-rule`) has no `source`;
  the set-format article sets `source` on a line of its own
  (`panos-set-source-any`), and another article sets several attributes,
  `source` among them, on one line in another order
  (`panos-one-line-form`). Reading `source` after `to` is an inference
  from those rows (review of #52/#53, F3), so `panos-one-line-order` is
  pending (review of #52-#57, G2):
  `set rulebase security rules NAME from any to any source ADDR
  destination ADDR application any service any action allow|deny`;
- zones, application and service `any` only; an address `any` or one IPv4
  prefix; no object name, list, range, negation, log or profile setting;
- rule names of letters, digits and hyphens, starting with a letter or
  digit, up to 63 characters (`panos-rule-name` states the length only, so
  the set is narrowed), never a keyword, and never `intrazone-default` or
  `interzone-default` in any case (review of #52/#53, F2);
- LF line ends only, printable ASCII only, no indentation, tokens separated
  by single spaces with no trailing space, keywords in their exact
  lowercase spelling. A quote, a `[ ]` list, a comment or a blank line is
  off: `panos-lexing` is pending;
- each rule name once: setting a rule again adds to its list attributes,
  and `panos-list-semantics` is pending (v3 section 6.1), so a second line
  for one name is `write-merge-uncited` (as in the Junos grammar, review of
  #51, F1); a second rule of another name is `line-not-allowlisted`: the
  default rules' fall-through, the meaning of `any`, the rule-type default
  and session semantics are pending, and order between rules is not read
  (review of #52/#53, F2). `move`, `delete`, `rename`, `override` and
  `disabled` have no production;
- an address prefix with host bits set is off.

The rule-name character set and the IPv4 prefix form are pending rows
(review of #51, F4), and so are the file-level rows (release scope,
lexing, list semantics, default rules, `any`, rule type, sessions; review
of #52/#53, F1, F2): each production lists them in `needs`, and the result
under `pending`.

Each line must match exactly one production: none is
`line-not-allowlisted`, two is `parse-ambiguous` (v3 section 8). No
production names an object or a zone, so nothing can be `config-incomplete`
yet (v3 section 9.2).

Parsing a file is not a certificate: `panos-rule-order` (unversioned, and
evaluation order only), `panos-one-line-order` and `panos-release-scope` are
pending (review of #52-#57, G1, G2), and the certificate comes in slice 7.
"""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

from .citations import PENDING, resolve
from .grammar_junos import (_TOKEN, _V4PREFIX, LINE_NOT_ALLOWLISTED,
                            PARSE_AMBIGUOUS, Fold, Klass, Production,
                            _host_bits)

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
    # review of #52/#53, F3: the one-line form
    "panos-one-line-form",
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
    # The predefined default rules' names are never a user rule's name
    # (review of #52/#53, F2), in any case.
    "RULENAME": Klass(r"(?!(?i:intrazone-default|interzone-default)$)"
                      r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", KEYWORDS),
    "V4PREFIX": Klass(_V4PREFIX, KEYWORDS),
}

_CLASS_NEEDS = {"RULENAME": "panos-rule-name-chars", "V4PREFIX": "panos-v4-prefix"}
# Slice 5: a rule is appended to the rulebase in order; no cited row states
# where a new rule lands (`panos-rule-order` is pending), so every production
# records it (review of #52-#57, G1: the order block is back).
_ORDER_NEEDS = ("panos-rule-order",)
_WRITE = ("rules", "append-in-order")
# The model's values for a rule: the keyword before each value slot.
_VALUE_KEYS = ("from", "to", "source", "destination", "application", "service",
               "action")
# File-level rows every production rests on (review of #52/#53, F1, F2).
_FILE_NEEDS = ("panos-release-scope", "panos-lexing", "panos-list-semantics",
               "panos-default-rules", "panos-any-meaning", "panos-rule-type-default",
               "panos-session-semantics",
               # review of #52-#57, G1 and G2: rule order and the token order
               "panos-rule-order", "panos-one-line-order")

PRODUCTIONS: Tuple[Production, ...] = tuple(
    Production(MODE, slots, None, cites,
               tuple(sorted({_CLASS_NEEDS[s] for s in slots if s in _CLASS_NEEDS}
                            | set(_FILE_NEEDS) | set(_ORDER_NEEDS))),
               _WRITE)
    for slots, cites in _PRODUCTION_TABLE)

# Every production's rows resolve at import: a pending row raises here. Its
# needs must be pending rows.
for _p in PRODUCTIONS:
    for _cid in _p.cites:
        resolve(_cid)
    for _cid in _p.needs:
        if _cid not in PENDING:
            raise KeyError(f"{_cid} is not a pending row")


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


def _result(reason: Optional[str], line: Optional[int], rows, pending=()) -> dict:
    return {"parses": reason is None, "reason": reason, "line": line,
            "rows": sorted(rows), "tags": [], "pending": sorted(pending)}


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
    return parse_model(raw)[0]


def parse_model(raw: bytes) -> Tuple[dict, Optional[dict]]:
    """The grammar result, and the final model when the file parses: each
    rule an object under `rulebase security`, appended in text order. A
    rule name written twice is `write-merge-uncited` (the fold)."""
    lines = raw.decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]          # the LF that ends the last line
    rows: set = set()
    pending: set = set()

    def off(reason: str, line: Optional[int]) -> Tuple[dict, None]:
        return _result(reason, line, rows, pending), None

    if not lines:
        return off(LINE_NOT_ALLOWLISTED, None)
    fold = Fold("panos")
    base = ("rulebase security",)
    fold.ensure(base)
    first: Optional[str] = None
    for n, ln in enumerate(lines, 1):
        if not ln or not _PRINTABLE.fullmatch(ln):
            return off(LINE_NOT_ALLOWLISTED, n)
        toks = ln.split(" ")
        if not all(_TOKEN.fullmatch(t) for t in toks):
            return off(LINE_NOT_ALLOWLISTED, n)
        hits = _match(toks)
        if not hits:
            return off(LINE_NOT_ALLOWLISTED, n)
        if len(hits) > 1:
            return off(PARSE_AMBIGUOUS, n)
        (p,) = hits
        if any(s == "V4PREFIX" and _host_bits(t) for s, t in zip(p.slots, toks)):
            return off(LINE_NOT_ALLOWLISTED, n)
        name = toks[p.slots.index("RULENAME")]
        if first is not None and name != first:
            # One rule per file (review of #52/#53, F2): a second rule needs
            # the default rules' fall-through and name case, uncited. The
            # same name again goes to the fold: write-merge-uncited.
            return off(LINE_NOT_ALLOWLISTED, n)
        first = name
        values = {k: toks[i + 1] for i, k in enumerate(toks[:-1]) if k in _VALUE_KEYS
                  and i >= p.slots.index("RULENAME")}
        refused = fold.write(n, base, f"rules {name}", p.write[1], values)
        if refused:
            return off(refused, n)
        rows.update(p.cites)
        pending.update(p.needs)
    return _result(None, None, rows, pending), fold.model()
