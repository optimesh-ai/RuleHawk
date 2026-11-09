"""#42 phase 2, slice 4a: the citation registry (design v2 section 1.2, v4
sections 5 and 14).

A grammar production may exist only for a cited row (v4 section 12, row 4).
This slice records the rows, with no engine behaviour: every id resolves to
(URL, title, release, verbatim quote, fetch date), each quote was confirmed
by a second fetch, and `rulehawk/citations.py` imports only the standard
library, because the independent checker may import it (v4 section 5).
Rows of v4 section 14 not yet fetched and confirmed are listed as pending,
and a production must not cite one.
"""
from __future__ import annotations

import ast
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The Junos rows fetched in full and confirmed by a second fetch on 2026-11-09
# (slice 4a, then the slice 4b additions).
_CITED = {
    "junos-term-order", "junos-terminating-action", "junos-terminating-replaced",
    "junos-firewall-family-inet-equivalent", "junos-filter-name",
    "junos-match-destination-address", "junos-filter-input",
    "junos-interface-address",
    # slice 4b
    "junos-match-source-address", "junos-implicit-discard", "junos-comments",
    "junos-config-indent", "junos-config-braces", "junos-config-leaf-semicolon",
    "junos-interface-family-hierarchy", "junos-interface-address-inet",
    "junos-interface-filter-hierarchy", "junos-top-firewall", "junos-top-interfaces",
    "junos-firewall-family-inet", "junos-filter-statement", "junos-term-statement",
    "junos-term-name", "junos-from-statement", "junos-then-statement",
    "junos-accept-terminating", "junos-discard-term",
}
# v4 section 14 Junos rows not yet cited: keyword case has no first-party
# statement found, and no fetched page states its rows for Junos OS Evolved.
_PENDING = {"junos-lexing", "junos-evolved-scope"}


def _mod():
    from rulehawk import citations
    return citations


def test_every_cited_row_is_complete():
    c = _mod()
    assert set(c.ROWS) == _CITED
    for cid, row in c.ROWS.items():
        assert row.id == cid
        assert row.url.startswith("https://www.juniper.net/documentation/"), row
        assert row.title and row.release and row.quote, row
        assert row.fetched == "2026-11-09" and row.confirmed == "2026-11-09", row
        assert "\n" not in row.quote and "  " not in row.quote, row
        # The fetch renders code font as markdown backticks; they are not
        # page text (review of #50, F7).
        assert "`" not in row.quote, row


def test_pending_rows_are_listed_and_not_cited():
    c = _mod()
    assert set(c.PENDING) == _PENDING
    assert not set(c.PENDING) & set(c.ROWS)
    for cid, why in c.PENDING.items():
        assert why, cid


def test_resolve_refuses_a_pending_or_unknown_id():
    c = _mod()
    assert c.resolve("junos-term-order").quote.startswith("Firewall filter terms")
    for bad in ("junos-lexing", "junos-evolved-scope", "no-such-row"):
        with pytest.raises(KeyError):
            c.resolve(bad)


def test_citations_imports_only_the_standard_library():
    """v4 section 5: the checker may import citations.py, and citations.py
    imports only the standard library."""
    for base in ("rulehawk", os.path.join("docs", "rulehawk")):
        src = open(os.path.join(_ROOT, base, "citations.py"), encoding="utf-8").read()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom):
                assert node.level == 0, "no relative import"
                mods = [node.module or ""]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                top = m.split(".")[0]
                # An explicit list (sys.stdlib_module_names is 3.10+).
                assert top in ("__future__", "dataclasses", "typing"), m


def test_no_all_clear_word_in_the_registry():
    src = open(os.path.join(_ROOT, "rulehawk", "citations.py"), encoding="utf-8").read()
    assert not re.search(r"\bPASS\b|\bVERIFIED\b|NO_NEW_RISK", src)
