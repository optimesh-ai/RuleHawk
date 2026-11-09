"""The Junos token language and its productions for the allowlist (#42
design v2 sections 6-8, v3 sections 7-9.2, v4 sections 4, 8 and 12-14).
Shadow only: nothing here changes a verdict.

A production exists only for a row cited in `citations.py`; each names the
rows it rests on, and every one must resolve (a pending row cannot). What the
grammar reads:
- the brace form only. Set-form commands have no cited production;
- LF line ends only, printable ASCII only. A CR, TAB, NBSP or any other
  byte is off until a lexing row is cited (v2 section 7);
- leading indentation is structure: four spaces per open level
  (`junos-config-indent`), one less on a line that starts with `}`;
- after the indentation, tokens separated by single spaces, with no
  trailing space. `{` and `}` stand alone; `;` ends the last token of a leaf
  (`junos-config-braces`, `junos-config-leaf-semicolon`);
- a statement starts and ends on one line, and a container is never empty;
- keywords in their exact lowercase spelling (`junos-lexing` is pending:
  no case row, no abbreviation, no quoting);
- a comment only as a whole line at its level: `# ...` or `/* ... */`
  (`junos-comments`);
- no Junos tag: a token ending in `:` matches no production, and the line
  is also recorded as a patch marker (v4 section 4).

Each statement must match exactly one production of the mode it is in: none
is `line-not-allowlisted`, two is `parse-ambiguous` (v3 section 8). A file
that ends inside a stanza is `config-incomplete` (v3 section 9.2).

Productions are fixed token sequences and every class is one space-free
token, so a statement splits into tokens one way only. `overlaps` checks
that the productions of each mode are pairwise disjoint and `shape_problems`
that every production has that fixed shape; both run in CI.

Parsing a file is not a certificate: `junos-evolved-scope` is pending, and
the certificate comes in slice 7.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from .citations import resolve

LINE_NOT_ALLOWLISTED = "line-not-allowlisted"
PARSE_AMBIGUOUS = "parse-ambiguous"
CONFIG_INCOMPLETE = "config-incomplete"

INDENT = 4
# The token alphabet after lexing. Anything else on a line is off.
_TOKEN = re.compile(r"[A-Za-z0-9._/:-]+")
_PRINTABLE = re.compile(r"[\x20-\x7e]*")


@dataclass(frozen=True)
class Klass:
    """A slot class: one token, a regular language over the token alphabet,
    minus the grammar's keywords (v3 section 8: name classes exclude the
    mode's keywords; here, every keyword)."""
    pattern: str
    exclude: FrozenSet[str] = field(default_factory=frozenset)

    def matches(self, tok: str) -> bool:
        return tok not in self.exclude and re.fullmatch(self.pattern, tok) is not None


@dataclass(frozen=True)
class Production:
    mode: str
    slots: Tuple[str, ...]        # literals, or class names in CLASSES
    child: Optional[str]          # the mode a container opens, None for a leaf
    cites: Tuple[str, ...]


_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
_V4PREFIX = rf"{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}/(?:3[0-2]|[12][0-9]|[0-9])"

# Terminators and keywords: every literal slot of a production.
_PRODUCTION_TABLE: Tuple[Tuple[str, Tuple[str, ...], Optional[str], Tuple[str, ...]], ...] = (
    # [edit]
    ("top", ("interfaces", "{"), "interfaces",
     ("junos-top-interfaces", "junos-interface-address-inet", "junos-config-braces")),
    ("top", ("firewall", "{"), "firewall",
     ("junos-top-firewall", "junos-config-braces")),
    # [edit interfaces interface-name unit number family inet]
    ("interfaces", ("IFNAME", "{"), "ifd",
     ("junos-interface-address-inet", "junos-config-braces")),
    ("ifd", ("unit", "UNIT", "{"), "ifl",
     ("junos-interface-family-hierarchy", "junos-config-braces")),
    ("ifl", ("family", "inet", "{"), "ifl-inet",
     ("junos-interface-family-hierarchy", "junos-interface-address-inet")),
    ("ifl-inet", ("address", "V4PREFIX", ";"), None,
     ("junos-interface-address", "junos-interface-address-inet",
      "junos-config-leaf-semicolon")),
    ("ifl-inet", ("filter", "{"), "ifl-filter",
     ("junos-interface-filter-hierarchy", "junos-config-braces")),
    ("ifl-filter", ("input", "FILTER", ";"), None,
     ("junos-filter-input", "junos-filter-name", "junos-config-leaf-semicolon")),
    # [edit firewall family inet filter filter-name term term-name]
    ("firewall", ("family", "inet", "{"), "fw-inet",
     ("junos-firewall-family-inet", "junos-firewall-family-inet-equivalent")),
    ("fw-inet", ("filter", "FILTER", "{"), "filter",
     ("junos-filter-statement", "junos-filter-name", "junos-config-braces")),
    ("filter", ("term", "TERM", "{"), "term",
     ("junos-term-statement", "junos-term-name", "junos-term-order")),
    ("term", ("from", "{"), "from",
     ("junos-from-statement", "junos-config-braces")),
    ("term", ("then", "accept", ";"), None,
     ("junos-then-statement", "junos-accept-terminating", "junos-terminating-action")),
    ("term", ("then", "discard", ";"), None,
     ("junos-then-statement", "junos-discard-term", "junos-terminating-action")),
    ("from", ("source-address", "{"), "addrs",
     ("junos-match-source-address", "junos-config-braces")),
    ("from", ("destination-address", "{"), "addrs",
     ("junos-match-destination-address", "junos-config-braces")),
    ("addrs", ("V4PREFIX", ";"), None,
     ("junos-config-leaf-semicolon",)),
)

_PUNCT = ("{", ";", "}")


def _keywords(table) -> FrozenSet[str]:
    return frozenset(s for _, slots, _, _ in table for s in slots
                     if not s.isupper() and s not in _PUNCT)


KEYWORDS: FrozenSet[str] = _keywords(_PRODUCTION_TABLE)

CLASSES: Dict[str, Klass] = {
    # Only the Gigabit Ethernet `ge-fpc/pic/port` names: no interface-naming
    # row is cited, so the class is narrowed to the one form the controls use.
    "IFNAME": Klass(r"ge-(?:0|[1-9][0-9]?)/(?:0|[1-9][0-9]?)/(?:0|[1-9][0-9]{0,2})",
                    KEYWORDS),
    "UNIT": Klass(r"0|[1-9][0-9]{0,4}", KEYWORDS),
    "V4PREFIX": Klass(_V4PREFIX, KEYWORDS),
    # junos-filter-name and junos-term-name: letters, numbers and hyphens,
    # up to 64 characters.
    "FILTER": Klass(r"[A-Za-z0-9-]{1,64}", KEYWORDS),
    "TERM": Klass(r"[A-Za-z0-9-]{1,64}", KEYWORDS),
}

PRODUCTIONS: Tuple[Production, ...] = tuple(
    Production(m, slots, child, cites) for m, slots, child, cites in _PRODUCTION_TABLE)

# Every production's rows resolve at import: a pending row raises here.
for _p in PRODUCTIONS:
    for _cid in _p.cites:
        resolve(_cid)
_COMMENT_ROWS = ("junos-comments", "junos-config-indent")
for _cid in _COMMENT_ROWS:
    resolve(_cid)


# ----------------------------------------------------------- CI shape checks

def _is_class(slot: str, classes: Dict[str, Klass]) -> bool:
    return slot.isupper() or slot in classes


def _slots_disjoint(a: str, b: str, classes: Dict[str, Klass]) -> bool:
    ca, cb = _is_class(a, classes), _is_class(b, classes)
    if not ca and not cb:
        return a != b
    if ca and cb:
        # Two class languages are never compared: they count as
        # overlapping. This only over-reports.
        return False
    lit, cls = (b, a) if ca else (a, b)
    return not classes[cls].matches(lit)


def overlaps(prods: Iterable[Production], classes: Dict[str, Klass]) -> List[Tuple[Production, Production]]:
    """Pairs of productions in one mode whose languages may intersect. With
    fixed shapes and one-token classes, two productions are disjoint when
    their lengths differ or some position holds two disjoint slots."""
    prods = list(prods)
    out = []
    for i, p in enumerate(prods):
        for q in prods[i + 1:]:
            if p.mode != q.mode or len(p.slots) != len(q.slots):
                continue
            if not any(_slots_disjoint(a, b, classes) for a, b in zip(p.slots, q.slots)):
                out.append((p, q))
    return out


def shape_problems(prods: Iterable[Production], classes: Dict[str, Klass]) -> List[str]:
    """Every slot is a literal over the token alphabet, a punctuation token,
    or a known class that holds no space and no punctuation; every
    production ends in `{` or `;` and has no other punctuation."""
    out = []
    for p in prods:
        if not p.slots or p.slots[-1] not in ("{", ";"):
            out.append(f"{p.slots}: must end in {{ or ;")
        for s in p.slots[:-1]:
            if s in _PUNCT:
                out.append(f"{p.slots}: punctuation inside")
            elif s.isupper() or not _TOKEN.fullmatch(s):
                if s not in classes:
                    out.append(f"{p.slots}: {s!r} is no literal or known class")
                    continue
                pat = classes[s].pattern
                for probe in (" ", "{", "}", ";", "a b", "x;"):
                    if re.fullmatch(pat, probe) or re.search(r"(?<!\\) |\\s", pat):
                        out.append(f"{p.slots}: class {s} can hold a space or punctuation")
                        break
        if (p.child is None) != (p.slots[-1] == ";"):
            out.append(f"{p.slots}: a container opens a mode, a leaf does not")
    return out


# ------------------------------------------------------------------- parsing

def _result(reason: Optional[str], line: Optional[int], rows, tags) -> dict:
    return {"accepted": reason is None, "reason": reason, "line": line,
            "rows": sorted(rows), "tags": sorted(tags)}


def _tag_lines(lines: Sequence[str]) -> List[int]:
    """Lines holding a Junos tag: a `word:` token (v4 section 4)."""
    return [n for n, ln in enumerate(lines, 1)
            if any(re.fullmatch(r"[a-z-]+:", w) for w in ln.split())]


def _lex(body: str) -> Optional[List[str]]:
    """The tokens of one line's body (after the indentation), or None when
    the body is off: a double or trailing space, or a character outside
    the token alphabet."""
    toks: List[str] = []
    for w in body.split(" "):
        if w in ("{", "}"):
            toks.append(w)
        elif w.endswith(";") and _TOKEN.fullmatch(w[:-1]):
            toks += [w[:-1], ";"]
        elif _TOKEN.fullmatch(w):
            toks.append(w)
        else:
            return None
    return toks


def _is_comment(body: str) -> bool:
    if body.startswith("#"):
        return True
    return (body.startswith("/*") and body.endswith("*/") and len(body) >= 4
            and "*/" not in body[2:-2])


def _match(mode: str, stmt: List[str]) -> List[Production]:
    out = []
    for p in PRODUCTIONS:
        if p.mode != mode or len(p.slots) != len(stmt):
            continue
        if all((CLASSES[s].matches(t) if s in CLASSES else s == t)
               for s, t in zip(p.slots, stmt)):
            out.append(p)
    return out


def parse(raw: bytes) -> dict:
    """The grammar result for one file's raw bytes."""
    lines = raw.decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]          # the LF that ends the last line
    tags = _tag_lines(lines)
    rows = set()
    # The stack of open containers: (mode, child statements seen).
    stack: List[List] = []
    statements = 0
    for n, ln in enumerate(lines, 1):
        if not _PRINTABLE.fullmatch(ln):
            return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
        body = ln.lstrip(" ")
        indent = len(ln) - len(body)
        if not body:
            return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
        depth = len(stack)
        if _is_comment(body):
            if indent != INDENT * depth:
                return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
            rows.update(_COMMENT_ROWS)
            continue
        toks = _lex(body)
        if toks is None:
            return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
        want = INDENT * (depth - 1 if toks[0] == "}" else depth)
        if indent != want:
            return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
        rows.add("junos-config-indent")
        stmt: List[str] = []
        for t in toks:
            if t == "}":
                if stmt or not stack or stack[-1][1] == 0:
                    return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
                stack.pop()
                continue
            stmt.append(t)
            if t not in ("{", ";"):
                continue
            mode = stack[-1][0] if stack else "top"
            hits = _match(mode, stmt)
            if not hits:
                return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
            if len(hits) > 1:
                return _result(PARSE_AMBIGUOUS, n, rows, tags)
            (p,) = hits
            rows.update(p.cites)
            if stack:
                stack[-1][1] += 1
            statements += 1
            if p.child is not None:
                stack.append([p.child, 0])
            stmt = []
        if stmt:
            # A statement must end on the line it starts.
            return _result(LINE_NOT_ALLOWLISTED, n, rows, tags)
    if stack:
        return _result(CONFIG_INCOMPLETE, None, rows, tags)
    if statements == 0:
        return _result(LINE_NOT_ALLOWLISTED, None, rows, tags)
    return _result(None, None, rows, tags)
