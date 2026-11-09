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

Forms whose Junos meaning differs from a statement-by-statement reading are
off at their line (review of #51, F1; v4: narrow, never model):
- a second write to one stanza (the same keyword and identifier under one
  parent), or to a single-valued leaf (`then`, `input`, `address`), or the
  same prefix twice in one list: `write-merge-uncited` (v2 section 2.1);
- the same interface address on two units (the two address pages
  disagree), a term with no `then` (off at the `}` that closes it), and a
  match prefix with host bits set: `line-not-allowlisted`;
- `input` naming a filter the file does not define: `config-incomplete`.
A Junos tag anywhere, a comment line included, means the file does not
parse (F2).

The name classes and the meaning of an address list are pending rows (F4):
each production lists those it needs in `needs`, and the result lists them
under `pending`. They do not stop a parse in shadow; they stop a
certificate.

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

from .citations import PENDING, resolve

LINE_NOT_ALLOWLISTED = "line-not-allowlisted"
PARSE_AMBIGUOUS = "parse-ambiguous"
CONFIG_INCOMPLETE = "config-incomplete"
WRITE_MERGE_UNCITED = "write-merge-uncited"

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
    needs: Tuple[str, ...] = ()   # pending rows the production still rests on
    # The write it makes (slice 5, v2 section 2.1): what kind of attribute,
    # and the merge rule (`create`, `append-in-order` or `error`).
    write: Tuple[str, ...] = ()


_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
_V4PREFIX = rf"{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}/(?:3[0-2]|[12][0-9]|[0-9])"

# Terminators and keywords: every literal slot of a production.
_PRODUCTION_TABLE: Tuple[Tuple[str, Tuple[str, ...], Optional[str], Tuple[str, ...]], ...] = (
    # [edit]
    ("top", ("interfaces", "{"), "interfaces",
     ("junos-top-statements", "junos-top-interfaces-keyword", "junos-top-interfaces",
      "junos-interface-address-inet", "junos-config-braces")),
    ("top", ("firewall", "{"), "firewall",
     ("junos-top-statements", "junos-top-firewall-keyword", "junos-top-firewall",
      "junos-config-braces")),
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
    # Only the Gigabit Ethernet `ge-fpc/pic/port` names, in a small range:
    # `junos-interface-name` is pending (review of #51, F1 item 10, F4).
    "IFNAME": Klass(r"ge-[0-9]/[0-3]/(?:[0-9]|[1-3][0-9]|4[0-7])", KEYWORDS),
    # `junos-unit-number` is pending: 0-9999.
    "UNIT": Klass(r"0|[1-9][0-9]{0,3}", KEYWORDS),
    "V4PREFIX": Klass(_V4PREFIX, KEYWORDS),
    # junos-filter-name and junos-term-name: letters, numbers and hyphens,
    # up to 64 characters.
    "FILTER": Klass(r"[A-Za-z0-9-]{1,64}", KEYWORDS),
    "TERM": Klass(r"[A-Za-z0-9-]{1,64}", KEYWORDS),
}

# The pending row each class rests on, and the one an address list rests on.
_CLASS_NEEDS = {"IFNAME": "junos-interface-name", "UNIT": "junos-unit-number",
                "V4PREFIX": "junos-v4-prefix"}
_LIST_MODES = {"addrs": "junos-address-list-or"}


def _needs(mode: str, slots: Tuple[str, ...]) -> Tuple[str, ...]:
    out = {_CLASS_NEEDS[s] for s in slots if s in _CLASS_NEEDS}
    if mode in _LIST_MODES:
        out.add(_LIST_MODES[mode])
    return tuple(sorted(out))


def _write_of(mode: str, slots: Tuple[str, ...], child: Optional[str]) -> Tuple[str, str]:
    """The write a production makes. A list member and a container create
    an object; a term is appended in configuration order
    (`junos-term-order`); a leaf sets a single value, and a second write is
    an error (no `replace` row is cited)."""
    if mode == "addrs":
        return ("member", "create")
    if child is None:
        return (slots[0], "error")
    if slots[0] == "term":
        return ("term", "append-in-order")
    return ("container", "create")


PRODUCTIONS: Tuple[Production, ...] = tuple(
    Production(m, slots, child, cites, _needs(m, slots), _write_of(m, slots, child))
    for m, slots, child, cites in _PRODUCTION_TABLE)

# Every production's rows resolve at import: a pending row raises here. Its
# needs must be pending rows, not cited ones (cited, they belong in cites).
for _p in PRODUCTIONS:
    for _cid in _p.cites:
        resolve(_cid)
    for _cid in _p.needs:
        if _cid not in PENDING:
            raise KeyError(f"{_cid} is not a pending row")
_COMMENT_ROWS = ("junos-comments", "junos-config-indent")
for _cid in _COMMENT_ROWS:
    resolve(_cid)


# ----------------------------------------------------------- CI shape checks

def _is_class(slot: str, classes: Dict[str, Klass]) -> bool:
    # A slot is a class only when it names one: the iptables grammar has
    # upper-case literals (`FORWARD`, `DROP`).
    return slot in classes


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


# ------------------------------------------------------------ the final model

MERGE_RULES = ("create", "append-in-order", "error")


class Fold:
    """The final model (slice 5, v2 section 2.1, v3 section 6.1): every
    write in text order, folded under its merge rule. An object is a path
    of attribute names from the root.
    - `create` makes the child object `path + (attribute,)`;
    - `append-in-order` does the same and lists the child in the parent's
      `ordered`, in text order (an order row must be cited, or pending);
    - `error` sets a single value on the object.
    A second write to one (object, attribute), under any rule, has no cited
    merge rule: `write-merge-uncited`. No rule replaces or deletes."""

    def __init__(self, dialect: str) -> None:
        self.dialect = dialect
        self._objs: Dict[Tuple[str, ...], dict] = {(): {"path": [], "values": {}, "ordered": []}}
        self._paths: List[Tuple[str, ...]] = []
        self._written: set = set()

    def ensure(self, path: Tuple[str, ...]) -> None:
        """Make an object that exists without a write (a built-in chain)."""
        for i in range(1, len(path) + 1):
            if path[:i] not in self._objs:
                self._objs[path[:i]] = {"path": list(path[:i]), "values": {}, "ordered": []}
                self._paths.append(path[:i])

    def values(self, path: Tuple[str, ...]) -> dict:
        return self._objs[path]["values"]

    def write(self, line: int, path: Tuple[str, ...], attribute: str, rule: str,
              value=None) -> Optional[str]:
        """Apply one write; the reason it is refused, or None."""
        if rule not in MERGE_RULES:
            raise ValueError(rule)
        obj = self._objs[path]          # KeyError: no such object
        if (path, attribute) in self._written:
            return WRITE_MERGE_UNCITED
        self._written.add((path, attribute))
        if rule == "error":
            obj["values"][attribute] = value
            return None
        child = path + (attribute,)
        self._objs[child] = {"path": list(child), "values": dict(value or {}), "ordered": []}
        self._paths.append(child)
        if rule == "append-in-order":
            obj["ordered"].append(attribute)
        return None

    def model(self) -> dict:
        return {"dialect": self.dialect,
                "objects": [{"path": list(o["path"]), "values": dict(o["values"]),
                             "ordered": list(o["ordered"])}
                            for o in (self._objs[p] for p in self._paths)]}


# ------------------------------------------------------------------- parsing

def _result(reason: Optional[str], line: Optional[int], rows, tags, pending=()) -> dict:
    return {"parses": reason is None, "reason": reason, "line": line,
            "rows": sorted(rows), "tags": sorted(tags), "pending": sorted(pending)}


def _tag_lines(lines: Sequence[str]) -> List[int]:
    """Lines holding a Junos tag: a `word:` token (v4 section 4), comment
    lines included (review of #51, F2)."""
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


def _attribute(p: Production, stmt: List[str]) -> Tuple[str, object]:
    """The attribute a statement writes in its parent, and its value: a
    leaf by its keyword (value: the rest), anything else by all its
    tokens."""
    words = [t for t in stmt if t not in _PUNCT]
    if p.write[1] == "error":
        return words[0], " ".join(words[1:])
    return " ".join(words), None


def _host_bits(prefix: str) -> bool:
    addr, plen = prefix.split("/")
    value = 0
    for octet in addr.split("."):
        value = value * 256 + int(octet)
    return value & ((1 << (32 - int(plen))) - 1) != 0


class _Frame:
    __slots__ = ("mode", "count", "path")

    def __init__(self, mode: str, path: Tuple[str, ...]) -> None:
        self.mode = mode
        self.count = 0
        self.path = path


def parse(raw: bytes) -> dict:
    """The grammar result for one file's raw bytes."""
    return parse_model(raw)[0]


def parse_model(raw: bytes) -> Tuple[dict, Optional[dict]]:
    """The grammar result, and the final model when the file parses."""
    lines = raw.decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]          # the LF that ends the last line
    tags = _tag_lines(lines)
    rows: set = set()
    pending: set = set()

    def off(reason: str, line: Optional[int]) -> Tuple[dict, None]:
        return _result(reason, line, rows, tags, pending), None

    fold = Fold("junos")
    top = _Frame("top", ())
    stack: List[_Frame] = []
    statements = 0
    addresses: set = set()
    filters: set = set()
    refs: List[Tuple[str, int]] = []
    for n, ln in enumerate(lines, 1):
        if not _PRINTABLE.fullmatch(ln):
            return off(LINE_NOT_ALLOWLISTED, n)
        body = ln.lstrip(" ")
        indent = len(ln) - len(body)
        if not body:
            return off(LINE_NOT_ALLOWLISTED, n)
        depth = len(stack)
        if _is_comment(body):
            if indent != INDENT * depth or n in tags:
                return off(LINE_NOT_ALLOWLISTED, n)
            rows.update(_COMMENT_ROWS)
            continue
        toks = _lex(body)
        if toks is None:
            return off(LINE_NOT_ALLOWLISTED, n)
        want = INDENT * (depth - 1 if toks[0] == "}" else depth)
        if indent != want:
            return off(LINE_NOT_ALLOWLISTED, n)
        rows.add("junos-config-indent")
        stmt: List[str] = []
        for t in toks:
            if t == "}":
                if stmt or not stack or stack[-1].count == 0:
                    return off(LINE_NOT_ALLOWLISTED, n)
                closed = stack.pop()
                if closed.mode == "term" and "then" not in fold.values(closed.path):
                    # A term with no then: the pages disagree on its
                    # meaning (review of #51, F1 item 7).
                    return off(LINE_NOT_ALLOWLISTED, n)
                continue
            stmt.append(t)
            if t not in ("{", ";"):
                continue
            parent = stack[-1] if stack else top
            hits = _match(parent.mode, stmt)
            if not hits:
                return off(LINE_NOT_ALLOWLISTED, n)
            if len(hits) > 1:
                return off(PARSE_AMBIGUOUS, n)
            (p,) = hits
            attribute, value = _attribute(p, stmt)
            refused = fold.write(n, parent.path, attribute, p.write[1], value)
            if refused:
                return off(refused, n)
            if p.mode == "addrs" and _host_bits(stmt[0]):
                return off(LINE_NOT_ALLOWLISTED, n)
            if p.mode == "ifl-inet" and stmt[0] == "address":
                ip = stmt[1].split("/")[0]
                if ip in addresses:
                    return off(LINE_NOT_ALLOWLISTED, n)
                addresses.add(ip)
            if p.mode == "ifl-filter":
                refs.append((stmt[1], n))
            if p.mode == "fw-inet":
                filters.add(stmt[1])
            rows.update(p.cites)
            pending.update(p.needs)
            parent.count += 1
            statements += 1
            if p.child is not None:
                stack.append(_Frame(p.child, parent.path + (attribute,)))
            stmt = []
        if stmt:
            # A statement must end on the line it starts.
            return off(LINE_NOT_ALLOWLISTED, n)
    if stack:
        return off(CONFIG_INCOMPLETE, None)
    if statements == 0:
        return off(LINE_NOT_ALLOWLISTED, None)
    for name, n in refs:
        if name not in filters:
            return off(CONFIG_INCOMPLETE, n)
    if tags:
        return off(LINE_NOT_ALLOWLISTED, tags[0])
    return _result(None, None, rows, tags, pending), fold.model()
