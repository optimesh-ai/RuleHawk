"""#42 phase 2, slice 4b: the review of #51 (F1-F5).

F1: inputs whose Junos meaning differs from a statement-by-statement
reading are off now, at the offending line (v4: narrow, never model):
a second write to a stanza or a single-valued leaf (`write-merge-uncited`,
v2 section 2.1, v3), the same interface address twice, a term with no
`then` (checked when its `}` closes), a match prefix with host bits set,
out-of-range unit and interface names, and a filter reference with no
filter (`config-incomplete`, v3 section 9.2).
F2: a Junos tag anywhere, comment lines included, means the file does not
parse.
F3: the grammars are imported inside the shadow block, so a pending row
cannot break a run with the switch unset, and a shadow run fails closed.
F4: the name classes and the address-list meaning have pending rows, which
the productions record as `needs` and the result lists as `pending`.
F5: the result key is `parses`.
"""
from __future__ import annotations

import ast
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_K00 = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design",
                    "controls", "k00_base.conf")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


_BASE = _read(_K00)
_L = _BASE.split("\n")


def _parse(text):
    from rulehawk import grammar_junos
    return grammar_junos.parse(text.encode("utf-8"))


def _gate_shadow(path):
    d = json.loads(g.to_json(g.run_gate([path], None, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    return f.get("shadow")


def _with(n, new):
    """k00 with line n (1-based) replaced by `new` (which may hold LFs)."""
    lines = list(_L)
    lines[n - 1] = new
    return "\n".join(lines)


def _after(n, new):
    lines = list(_L)
    lines.insert(n, new)
    return "\n".join(lines)


_WM = "write-merge-uncited"
_OFF = "line-not-allowlisted"
_INC = "config-incomplete"

_CASES = {
    # 1. a term name used twice: Junos merges the stanzas
    "duplicate-term": (_after(12, "            term d { then accept; }"), _WM, 13),
    # 2. two actions in one term: the latest replaces the first
    "two-then-one-line": (_with(10, "                then discard; then accept;"), _WM, 10),
    "two-then-two-lines": (_after(10, "                then accept;"), _WM, 11),
    # 3. a match list entered twice: the two merge into one list
    "two-source-address": (_with(9, "                from { source-address { 192.0.2.0/24; } "
                                    "source-address { 10.0.0.0/8; } destination-address "
                                    "{ 198.51.100.0/24; } }"), _WM, 9),
    "two-from": (_after(9, "                from { source-address { 10.0.0.0/8; } }"), _WM, 10),
    "same-prefix-twice": (_with(9, "                from { source-address { 192.0.2.0/24; "
                                   "192.0.2.0/24; } destination-address { 198.51.100.0/24; } }"),
                          _WM, 9),
    # 4. a single-valued leaf set twice
    "filter-twice": (_with(2, "    ge-0/0/0 { unit 0 { family inet { filter { input F; } "
                              "filter { input F; } address 192.0.2.1/24; } } }"), _WM, 2),
    "input-twice": (_with(2, "    ge-0/0/0 { unit 0 { family inet { filter { input F; input F; } "
                             "address 192.0.2.1/24; } } }"), _WM, 2),
    "address-twice": (_with(2, "    ge-0/0/0 { unit 0 { family inet { filter { input F; } "
                               "address 192.0.2.1/24; address 192.0.2.2/24; } } }"), _WM, 2),
    # 5. a stanza entered twice
    "unit-twice": (_with(2, "    ge-0/0/0 { unit 0 { family inet { filter { input F; } "
                            "address 192.0.2.1/24; } } unit 0 { family inet { address "
                            "203.0.113.1/24; } } }"), _WM, 2),
    "family-twice": (_with(2, "    ge-0/0/0 { unit 0 { family inet { filter { input F; } "
                              "address 192.0.2.1/24; } family inet { address 203.0.113.1/24; "
                              "} } }"), _WM, 2),
    "interface-twice": (_with(3, "    ge-0/0/0 { unit 1 { family inet { filter { input F; } "
                                 "address 198.51.100.1/24; } } }"), _WM, 3),
    "interfaces-twice": (_BASE + "interfaces {\n    ge-0/0/2 { unit 0 { family inet { "
                                 "address 203.0.113.1/24; } } }\n}\n", _WM, 16),
    "firewall-twice": (_BASE + "firewall {\n    family inet {\n        filter G { term z "
                               "{ then accept; } }\n    }\n}\n", _WM, 16),
    "filter-stanza-twice": (_after(13, "        filter F { term z { then accept; } }"), _WM, 14),
    # 6. the same address on two interfaces: the address pages disagree
    "same-address-two-interfaces": (_with(3, "    ge-0/0/1 { unit 0 { family inet { filter "
                                             "{ input F; } address 192.0.2.1/24; } } }"), _OFF, 3),
    "same-address-other-length": (_with(3, "    ge-0/0/1 { unit 0 { family inet { filter "
                                           "{ input F; } address 192.0.2.1/25; } } }"), _OFF, 3),
    # 7. a term with from and no then: off when its `}` closes
    "term-no-then-one-line": (_with(12, "            term a { from { source-address "
                                        "{ 203.0.113.0/24; } } }"), _OFF, 12),
    "term-no-then-lines": ("\n".join(ln for i, ln in enumerate(_L, 1) if i != 10), _OFF, 10),
    # 8. a match prefix with host bits set
    "host-bits": (_with(12, "            term a { from { source-address { 203.0.113.1/24; } } "
                            "then accept; }"), _OFF, 12),
    # 9. a filter reference with no filter
    "undefined-filter": (_with(3, "    ge-0/0/1 { unit 0 { family inet { filter { input G; } "
                                  "address 198.51.100.1/24; } } }"), _INC, 3),
    # 10. out-of-range names
    "unit-out-of-range": (_with(2, "    ge-0/0/0 { unit 99999 { family inet { filter { input F; } "
                                   "address 192.0.2.1/24; } } }"), _OFF, 2),
    "fpc-out-of-range": (_with(3, "    ge-99/0/1 { unit 0 { family inet { filter { input F; } "
                                  "address 198.51.100.1/24; } } }"), _OFF, 3),
    "port-out-of-range": (_with(3, "    ge-0/0/999 { unit 0 { family inet { filter { input F; } "
                                   "address 198.51.100.1/24; } } }"), _OFF, 3),
}


@pytest.mark.parametrize("name", sorted(_CASES))
def test_f1_a_form_whose_meaning_differs_is_off_at_its_line(name):
    text, reason, line = _CASES[name]
    r = _parse(text)
    assert r["parses"] is False, (name, r)
    assert (r["reason"], r["line"]) == (reason, line), (name, r)


def test_f1_k00_still_parses():
    r = _parse(_BASE)
    assert r["parses"] is True and r["reason"] is None, r


def test_f1_a_term_with_then_only_still_parses():
    r = _parse(_with(12, "            term a { then accept; }"))
    assert r["parses"] is True, r


def test_f1_one_filter_bound_by_name_from_two_interfaces_still_parses():
    assert _L[1].count("input F;") == 1 and _L[2].count("input F;") == 1
    assert _parse(_BASE)["parses"] is True


# ----------------------------------------------------------------------- F2

@pytest.mark.parametrize("comment,line", [
    ("# inactive: old", 1), ("/* delete: x */", 1)])
def test_f2_a_tag_in_a_comment_does_not_parse(comment, line):
    r = _parse(comment + "\n" + _BASE)
    assert r["parses"] is False, r
    assert r["reason"] == _OFF and r["line"] == line, r
    assert r["tags"] == [line], r


def test_f2_a_result_with_a_tag_never_parses():
    lines = list(_L)
    lines.insert(7, "            # protect: x")
    r = _parse("\n".join(lines))
    assert r["parses"] is False and r["tags"] == [8], r


# ----------------------------------------------------------------------- F3

def test_f3_dialects_imports_no_grammar_at_module_level():
    for base in ("rulehawk", os.path.join("docs", "rulehawk")):
        tree = ast.parse(_read(os.path.join(_ROOT, base, "dialects.py")))
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                names = [a.name for a in node.names] + [node.module or ""]
                assert not any("grammar" in n for n in names), ast.dump(node)


@pytest.fixture
def pending_term_order(monkeypatch):
    """A cited row goes pending: the grammar modules raise on import."""
    import rulehawk
    from rulehawk import citations
    monkeypatch.setitem(citations.PENDING, "junos-term-order", "test: pending")
    for mod in ("grammar_junos", "grammar_panos"):
        monkeypatch.delitem(sys.modules, f"rulehawk.{mod}", raising=False)
        monkeypatch.delattr(rulehawk, mod, raising=False)
    with pytest.raises(KeyError):
        from rulehawk import grammar_junos  # noqa: F401
    monkeypatch.delitem(sys.modules, "rulehawk.grammar_junos", raising=False)


def test_f3_a_pending_row_does_not_touch_a_run_with_the_switch_unset(pending_term_order,
                                                                       monkeypatch):
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    d = json.loads(g.to_json(g.run_gate([_K00], None, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    assert "shadow" not in f, f


def test_f3_a_pending_row_fails_a_shadow_run_closed(pending_term_order, monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")
    sh = _gate_shadow(_K00)
    assert sh["would_pass"] is False, sh
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert "grammar" not in sh, sh
    assert "junos-term-order" in sh["grammar_unavailable"], sh


def test_f3_a_pending_row_keeps_the_cli_exit_code(pending_term_order, monkeypatch, capsys):
    from rulehawk import cli
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    try:
        unset = cli.main([_K00, "--json"])
    except SystemExit as e:
        unset = e.code
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")
    try:
        shadow = cli.main([_K00, "--json"])
    except SystemExit as e:
        shadow = e.code
    capsys.readouterr()
    assert unset == shadow != 1, (unset, shadow)


# ----------------------------------------------------------------------- F4

_NEEDS = {"IFNAME": "junos-interface-name", "UNIT": "junos-unit-number",
          "V4PREFIX": "junos-v4-prefix"}


def test_f4_every_production_records_its_pending_rows():
    from rulehawk import citations, grammar_junos as gm
    for p in gm.PRODUCTIONS:
        want = {_NEEDS[s] for s in p.slots if s in _NEEDS}
        if p.mode == "addrs":
            want.add("junos-address-list-or")
        assert set(p.needs) == want, p
        assert set(p.needs) <= set(citations.PENDING), p


def test_f4_k00_lists_its_pending_rows():
    r = _parse(_BASE)
    assert r["pending"] == ["junos-address-list-or", "junos-interface-name",
                            "junos-unit-number", "junos-v4-prefix"], r


def test_f4_the_top_productions_rest_on_the_statement_cells():
    from rulehawk import grammar_junos as gm
    top = {p.slots[0]: set(p.cites) for p in gm.PRODUCTIONS if p.mode == "top"}
    assert {"junos-top-statements", "junos-top-firewall-keyword"} <= top["firewall"]
    assert {"junos-top-statements", "junos-top-interfaces-keyword"} <= top["interfaces"]
