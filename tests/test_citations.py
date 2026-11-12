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
    # review of #51, F4: the Statement cells of Table 2
    "junos-top-statements", "junos-top-firewall-keyword", "junos-top-interfaces-keyword",
}
# slice 4c: the PAN-OS rows.
_CITED |= {
    "panos-rule-name", "panos-source-zone", "panos-destination-zone",
    "panos-source-address", "panos-destination-address", "panos-application",
    "panos-service-any", "panos-action", "panos-cli-create-rule",
    "panos-set-from-any", "panos-set-to-any", "panos-set-source-any",
    "panos-set-destination-any", "panos-set-application-any",
    "panos-set-service-any", "panos-set-action-allow",
    # review of #52/#53, F3
    "panos-one-line-form",
}
# v4 section 14 Junos rows not yet cited: keyword case has no first-party
# statement found, and no fetched page states its rows for Junos OS Evolved.
_PENDING = {"junos-lexing", "junos-evolved-scope",
            # review of #51, F4: name classes and the address-list meaning
            "junos-unit-number", "junos-interface-name", "junos-v4-prefix",
            "junos-address-list-or",
            # slice 4c: rule order, the release scope, lexing and the set-CLI
            # list semantics have no fetched first-party statement.
            "panos-release-scope", "panos-lexing", "panos-list-semantics",
            # review of #52/#53, F2: what one rule's meaning still rests on
            "panos-default-rules", "panos-any-meaning", "panos-rule-type-default",
            "panos-session-semantics",
            # review of #52-#57, G1 and G2: rule order (an unversioned page,
            # evaluation order only) and the one-line token order
            "panos-rule-order", "panos-one-line-order",
            # review of #51, F4, for PAN-OS: the name class and the prefix form
            "panos-rule-name-chars", "panos-v4-prefix"}
_FIRST_PARTY = ("https://www.juniper.net/documentation/",
                "https://docs.paloaltonetworks.com/",
                "https://knowledgebase.paloaltonetworks.com/")


def _mod():
    from rulehawk import citations
    return citations


def test_every_cited_row_is_complete():
    c = _mod()
    assert set(c.ROWS) == _CITED
    for cid, row in c.ROWS.items():
        assert row.id == cid
        assert row.url.startswith(_FIRST_PARTY), row
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


def test_panos_rule_order_stays_pending_with_its_quote():
    """Review of #52-#57, G1: the Security Policy Rules page is unversioned
    and states evaluation order, not where a new rule lands."""
    r = _mod().PENDING["panos-rule-order"]
    assert "unversioned" in r, r
    assert "evaluated left to right and from top to bottom" in r, r
    assert "append" in r or "lands" in r, r


def test_panos_release_scope_names_every_unversioned_source():
    """Review of #52-#57, G1: the release-scope row names the Security Policy
    Rules page and KB3."""
    r = _mod().PENDING["panos-release-scope"]
    assert "Security Policy Rules" in r and "kA10g000000ClcLCAS" in r, r


def test_panos_one_line_order_is_pending():
    """Review of #52-#57, G2: the grammar's seven-attribute order on one line
    is an inference."""
    r = _mod().PENDING["panos-one-line-order"]
    assert "source" in r and "to" in r, r
