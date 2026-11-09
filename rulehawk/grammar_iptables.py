"""The iptables token language and its productions for the allowlist (#42
design v2 sections 6-8, v3 sections 6.1, 7, 8 and 9.2, v4 sections 3 and
12-14). Shadow only: nothing here changes a verdict.

A production exists only for a row cited in `citations.py` (iptables(8),
1.8.13); each names the rows it rests on, and every one must resolve. What
the grammar reads, one command per line:
- `iptables -P CHAIN ACCEPT|DROP` (`iptables-synopsis-policy`,
  `iptables-policy`);
- `iptables -A CHAIN [-s PREFIX] [-d PREFIX] -j ACCEPT|DROP`
  (`iptables-synopsis-append`, `iptables-rule-specification`: matches
  before the target);
- CHAIN one of the filter table's built-in chains INPUT, FORWARD, OUTPUT,
  with no `-t` (`iptables-filter-default`, `iptables-filter-chains`);
- PREFIX a canonical dotted quad with a length 0-32 (`iptables-source`,
  `iptables-mask`) and no host bits: no hostname, plain address, dotted
  mask, list or `!`;
- LF line ends, printable ASCII, no indentation, single spaces, exact short
  options (`iptables-lexing` is pending: no abbreviation, long option or
  alias).

No shell syntax is read: no shebang, comment, blank line, variable,
quote, function, conditional, heredoc, `exit` or `;`. A script runs
against the rule set already loaded, and `iptables-script-scope` is
pending, so every production records it in `needs`. No `-I`, `-N`, `-F`,
`-X`, `-D`, `-g`, `-m`, `-p` or `-f`, and no iptables-save format
(`iptables-save-format` is pending).

The duplicate and merge forms are off from the start (review of #51, F1):
a second `-P` for one chain replaces the first and is
`write-merge-uncited`; the same rule appended twice is
`line-not-allowlisted`.

Each line must match exactly one production: none is
`line-not-allowlisted`, two is `parse-ambiguous` (v3 section 8). Parsing is
not a certificate: `iptables-script-scope` and `iptables-release-scope`
are pending, and the certificate comes in slice 7.
"""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, List, Optional, Tuple

from .citations import PENDING, resolve
from .grammar_junos import (_TOKEN, _V4PREFIX, LINE_NOT_ALLOWLISTED,
                            PARSE_AMBIGUOUS, WRITE_MERGE_UNCITED, Klass,
                            Production, _host_bits)

_PRINTABLE = re.compile(r"[\x20-\x7e]*")
MODE = "line"
_CHAINS = ("INPUT", "FORWARD", "OUTPUT")
_TARGETS = ("ACCEPT", "DROP")
_NEEDS = ("iptables-script-scope",)
_TABLE_ROWS = ("iptables-filter-default", "iptables-filter-chains")


def _table() -> Tuple[Tuple[Tuple[str, ...], Tuple[str, ...]], ...]:
    out = []
    for chain in _CHAINS:
        for tgt in _TARGETS:
            out.append((("iptables", "-P", chain, tgt),
                        ("iptables-synopsis-policy", "iptables-policy",
                         "iptables-policy-end", "iptables-accept-drop") + _TABLE_ROWS))
    for chain in _CHAINS:
        for src in (False, True):
            for dst in (False, True):
                for tgt in _TARGETS:
                    slots: Tuple[str, ...] = ("iptables", "-A", chain)
                    cites: Tuple[str, ...] = (
                        "iptables-synopsis-append", "iptables-rule-specification",
                        "iptables-append", "iptables-first-match", "iptables-jump",
                        "iptables-accept-drop") + _TABLE_ROWS
                    if src:
                        slots += ("-s", "V4PREFIX")
                        cites += ("iptables-source", "iptables-mask")
                    if dst:
                        slots += ("-d", "V4PREFIX")
                        cites += ("iptables-destination", "iptables-source",
                                  "iptables-mask")
                    slots += ("-j", tgt)
                    out.append((slots, tuple(dict.fromkeys(cites))))
    return tuple(out)


_PRODUCTION_TABLE = _table()

KEYWORDS: FrozenSet[str] = frozenset(
    s for slots, _ in _PRODUCTION_TABLE for s in slots if s != "V4PREFIX")

CLASSES: Dict[str, Klass] = {
    "V4PREFIX": Klass(_V4PREFIX, KEYWORDS),
}

PRODUCTIONS: Tuple[Production, ...] = tuple(
    Production(MODE, slots, None, cites, _NEEDS) for slots, cites in _PRODUCTION_TABLE)

# Every production's rows resolve at import: a pending row raises here. Its
# needs must be pending rows.
for _p in PRODUCTIONS:
    for _cid in _p.cites:
        resolve(_cid)
    for _cid in _p.needs:
        if _cid not in PENDING:
            raise KeyError(f"{_cid} is not a pending row")


def shape_problems(prods, classes: Dict[str, Klass]) -> List[str]:
    """Every production is a non-empty fixed token sequence: each slot a
    known class that holds no space, or else a literal over the token
    alphabet (upper-case literals such as `FORWARD` are literals here)."""
    out = []
    for p in prods:
        if not p.slots:
            out.append("empty production")
            continue
        for s in p.slots:
            if s in classes:
                if re.search(r"(?<!\\) |\\s", classes[s].pattern):
                    out.append(f"{p.slots}: class {s} can hold a space")
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
    lines = raw.decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]          # the LF that ends the last line
    if not lines:
        return _result(LINE_NOT_ALLOWLISTED, None, ())
    rows: set = set()
    pending: set = set()
    policies: set = set()
    rules: set = set()
    for n, ln in enumerate(lines, 1):
        if not ln or not _PRINTABLE.fullmatch(ln):
            return _result(LINE_NOT_ALLOWLISTED, n, rows, pending)
        toks = ln.split(" ")
        if not all(_TOKEN.fullmatch(t) for t in toks):
            return _result(LINE_NOT_ALLOWLISTED, n, rows, pending)
        hits = _match(toks)
        if not hits:
            return _result(LINE_NOT_ALLOWLISTED, n, rows, pending)
        if len(hits) > 1:
            return _result(PARSE_AMBIGUOUS, n, rows, pending)
        (p,) = hits
        if any(s == "V4PREFIX" and _host_bits(t) for s, t in zip(p.slots, toks)):
            return _result(LINE_NOT_ALLOWLISTED, n, rows, pending)
        if toks[1] == "-P":
            if toks[2] in policies:
                return _result(WRITE_MERGE_UNCITED, n, rows, pending)
            policies.add(toks[2])
        else:
            if ln in rules:
                return _result(LINE_NOT_ALLOWLISTED, n, rows, pending)
            rules.add(ln)
        rows.update(p.cites)
        pending.update(p.needs)
    return _result(None, None, rows, pending)
