"""#42 phase 2, slice 4b: the Junos token language and its productions, in
shadow (design v2 sections 6-8, v3 sections 7-9.2, v4 sections 4, 8, 12-14).

A production exists only for a cited row (v4 section 12, row 4): every
production names the `rulehawk/citations.py` rows it rests on, and each one
must resolve. The grammar reads the brace form only, keywords in their exact
cited spelling, single spaces between tokens, leading indentation as
structure (four spaces per level), LF line ends, no Junos tag (`delete:`,
`replace:`, `inactive:`, ...; v4 section 4) and no set-form command. Anything
else is `line-not-allowlisted`, with its raw line.

The result goes only into the shadow block (RULEHAWK_SHADOW=1). k00 parses,
but `would_pass` stays false: no certificate exists before slice 7, and the
`junos-evolved-scope` row is still pending (v3 section 6.3).
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
_V = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants")
_D = os.path.join(_V, "design")
_K00 = os.path.join(_D, "controls", "k00_base.conf")


def _gm():
    from rulehawk import grammar_junos
    return grammar_junos


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _parse(text):
    return _gm().parse(text.encode("utf-8"))


@pytest.fixture
def shadow(monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")


def _gate_shadow(path, vendor="auto"):
    d = json.loads(g.to_json(g.run_gate([path], None, fail_on="high", vendor=vendor)))
    (f,) = d["files"]
    return f.get("shadow")


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return str(p)


# ------------------------------------------------------- productions are cited

def test_every_production_rests_on_cited_rows():
    gm = _gm()
    from rulehawk import citations
    assert gm.PRODUCTIONS, "no productions"
    for p in gm.PRODUCTIONS:
        assert p.cites, p
        for cid in p.cites:
            citations.resolve(cid)      # raises on a pending or unknown id


def test_no_production_rests_on_a_pending_row():
    gm = _gm()
    from rulehawk import citations
    used = {cid for p in gm.PRODUCTIONS for cid in p.cites}
    assert not used & set(citations.PENDING), used & set(citations.PENDING)


def test_the_grammar_module_imports_only_the_standard_library_and_citations():
    """The independent checker may later reuse the token language (v4
    section 5), so the module stays free of the engine."""
    for base in ("rulehawk", os.path.join("docs", "rulehawk")):
        src = _read(os.path.join(_ROOT, base, "grammar_junos.py"))
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    assert node.module == "citations", node.module
                    continue
                mods = [node.module or ""]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert m.split(".")[0] in ("__future__", "dataclasses", "re", "typing"), m


def test_no_all_clear_word_in_the_grammar():
    import re
    src = _read(os.path.join(_ROOT, "rulehawk", "grammar_junos.py"))
    assert not re.search(r"\bPASS\b|\bVERIFIED\b|NO_NEW_RISK|\"certified\"|\"complete\"", src)


# ------------------------------------- overlap and shape checks (v3 section 8)

def test_the_productions_of_every_mode_are_pairwise_disjoint():
    gm = _gm()
    assert gm.overlaps(gm.PRODUCTIONS, gm.CLASSES) == []


def test_every_production_has_a_fixed_shape_and_every_class_is_one_token():
    gm = _gm()
    assert gm.shape_problems(gm.PRODUCTIONS, gm.CLASSES) == []


def test_name_classes_exclude_every_keyword():
    gm = _gm()
    for name, k in gm.CLASSES.items():
        for kw in gm.KEYWORDS:
            assert not k.matches(kw), (name, kw)


def _toy(mode, *slots):
    gm = _gm()
    return gm.Production(mode, tuple(slots), None, ("junos-term-order",))


def _toy_classes():
    gm = _gm()
    return {
        "LOWER": gm.Klass(r"[a-z]+"),
        "ALNUM": gm.Klass(r"[a-z0-9]+"),
        "DIGITS": gm.Klass(r"[0-9]+"),
        "SPACEY": gm.Klass(r"[a-z ]+"),
    }


def test_toy_overlapping_class_pair_is_caught():
    gm = _gm()
    prods = [_toy("m", "filter", "LOWER", "{"), _toy("m", "filter", "ALNUM", "{")]
    assert len(gm.overlaps(prods, _toy_classes())) == 1


def test_toy_keyword_inside_a_class_is_caught():
    gm = _gm()
    prods = [_toy("m", "then", "accept", ";"), _toy("m", "then", "LOWER", ";")]
    assert len(gm.overlaps(prods, _toy_classes())) == 1


def test_toy_disjoint_pairs_pass():
    gm = _gm()
    prods = [_toy("m", "filter", "LOWER", "{"), _toy("m", "filter", "123", "{"),
             _toy("m", "term", "LOWER", "{"), _toy("m", "filter", "LOWER", "LOWER", "{"),
             _toy("n", "filter", "LOWER", "{")]
    assert gm.overlaps(prods, _toy_classes()) == []


def test_toy_two_classes_at_one_position_count_as_overlapping():
    """The check does not compare two class languages: two different
    classes at the same position count as overlapping, even when (as
    here) their languages are disjoint. This only over-reports."""
    gm = _gm()
    prods = [_toy("m", "filter", "LOWER", "{"), _toy("m", "filter", "DIGITS", "{")]
    assert len(gm.overlaps(prods, _toy_classes())) == 1


def test_toy_optional_keyword_and_spacey_class_are_caught():
    """An optional part (`source-address P [except]`) can parse one line two
    ways; the grammar admits fixed-shape productions only, and a class that
    can hold a space would let the token split move."""
    gm = _gm()
    classes = _toy_classes()
    assert gm.shape_problems([_toy("m", "source-address", "LOWER", "except?", ";")], classes)
    assert gm.shape_problems([_toy("m", "description", "SPACEY", ";")], classes)
    assert gm.shape_problems([_toy("m", "filter", "NOCLASS", "{")], classes)


def test_two_productions_matching_one_statement_is_parse_ambiguous(monkeypatch):
    """The run-time second check (v3 section 8): a statement that matches
    two productions gives parse-ambiguous, never a choice."""
    gm = _gm()
    dup = [p for p in gm.PRODUCTIONS if p.slots == ("then", "accept", ";")]
    assert len(dup) == 1
    monkeypatch.setattr(gm, "PRODUCTIONS", tuple(gm.PRODUCTIONS) + tuple(dup))
    r = _parse(_read(_K00))
    assert r["reason"] == "parse-ambiguous" and r["parses"] is False, r
    assert r["line"] == 12, r


# ----------------------------------------------------------------- k00 parses

def test_the_grammar_accepts_k00():
    r = _parse(_read(_K00))
    assert r == {"parses": True, "reason": None, "line": None,
                 "rows": r["rows"], "tags": [], "pending": r["pending"]}, r
    assert {"junos-match-source-address", "junos-match-destination-address",
            "junos-filter-input", "junos-interface-address-inet",
            "junos-term-statement", "junos-discard-term",
            "junos-accept-terminating"} <= set(r["rows"]), r["rows"]
    assert r["rows"] == sorted(set(r["rows"])), r["rows"]


def test_k00_parses_but_would_pass_stays_false(shadow):
    """The brief's pin: the grammar accepts k00, and without a certificate
    (slice 7) the shadow still says file-uncertified."""
    sh = _gate_shadow(_K00)
    assert sh["grammar"]["parses"] is True, sh
    assert sh["would_pass"] is False, sh
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert "certified" not in json.dumps(sh).replace("file-uncertified", ""), sh


# ------------------------------------------------- per-production meaning examples

_BASE = _read(_K00)


@pytest.mark.parametrize("old,new", [
    # keywords match only their exact cited spelling (v3 section 7)
    ("then discard;", "THEN DISCARD;"),
    ("then discard;", "then Discard;"),
    ("then discard;", "then disc;"),            # no abbreviation
    ("then discard;", "then reject;"),          # reject is not cited
    ("then accept;", "then accept; count c;"),  # count is not cited
    ("family inet {\n        filter F {", "family inet6 {\n        filter F {"),
    ("filter { input F; }", "filter { output F; }"),
    ("filter { input F; }", "filter { input-list F; }"),
    ("source-address { 203.0.113.0/24; }", "source-address 203.0.113.0/24;"),
    ("source-address { 203.0.113.0/24; }", "source-address { 203.0.113.0/24 except; }"),
    ("source-address { 203.0.113.0/24; }", "prefix-list { 203.0.113.0/24; }"),
    ("source-address { 203.0.113.0/24; }", "source-address { 203.0.113.0/255.255.255.0; }"),
    ("source-address { 203.0.113.0/24; }", "source-address { 203.0.113.0/33; }"),
    ("source-address { 203.0.113.0/24; }", "source-address { 203.0.113.00/24; }"),
    ("source-address { 203.0.113.0/24; }", "source-address { 203.0.113.0; }"),
    ("ge-0/0/1 {", "xe-0/0/1 {"),               # only the ge- names
    ("ge-0/0/1 {", "irb {"),
    ("unit 0 { family inet { filter { input F; } address 198",
     "unit 00 { family inet { filter { input F; } address 198"),
    ("term a {", "term then {"),                # a name that is a keyword
    ("term a {", "term a_b {"),
    ("filter F {", "filter " + "F" * 65 + " {"),
    ("filter F {", 'filter "F" {'),             # quoting is not cited
    # whitespace: single spaces between tokens, nothing else
    ("then discard;", "then  discard;"),
    ("then discard;", "then\tdiscard;"),
    ("then discard;", "then discard; "),
    ("then discard;", "then discard ;"),
    ("then discard;", "then discard;"),
    # leading indentation is structure: four spaces per level
    ("                then discard;", "               then discard;"),
    ("                then discard;", "\t\t\t\tthen discard;"),
    # a statement ends on its line; a container is never empty
    ("                then discard;", "                then\n                discard;"),
    ("term a { from { source-address { 203.0.113.0/24; } } then accept; }",
     "term a { from { } then accept; }"),
    # Junos tags and set-form commands are off (v4 section 4)
    ("        filter F {", "        inactive: filter F {"),
    ("        filter F {", "        protect: filter F {"),
    ("                then discard;", "                apply-groups g;"),
    # a comment shares no line with a statement
    ("                then discard;", "                then discard; # x"),
    ("                then discard;", "                then discard; /* x */"),
    # a blank line, a CR, a non-ASCII byte
    ("                then discard;", "                then discard;\n"),
    ("                then discard;", "                then discard;\r"),
    ("                then discard;", "                then discard;é"),
])
def test_a_mutation_is_off_at_its_line(old, new):
    assert _BASE.count(old) >= 1, old
    text = _BASE.replace(old, new, 1)
    r = _parse(text)
    assert r["parses"] is False and r["reason"] == "line-not-allowlisted", (new, r)
    first = text.split("\n").index(next(
        ln for ln, base in zip(text.split("\n"), _BASE.split("\n")) if ln != base))
    assert r["line"] == first + 1, (new, r)


@pytest.mark.parametrize("comment", ["# a note", "/* a note */", "#"])
@pytest.mark.parametrize("where", ["top", "inside"])
def test_a_whole_line_comment_at_its_level_is_read(comment, where):
    """junos-comments: `#` before the comment, or `/*` and `*/` around it;
    a comment line sits at the indentation of its level."""
    lines = _BASE.split("\n")
    if where == "top":
        lines.insert(0, comment)
    else:
        lines.insert(7, "            " + comment)     # inside `filter F {`
    r = _parse("\n".join(lines))
    assert r["parses"] is True, r
    assert "junos-comments" in r["rows"], r


def test_a_comment_at_the_wrong_level_is_off():
    lines = _BASE.split("\n")
    lines.insert(7, "    # a note")
    r = _parse("\n".join(lines))
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 8, r


def test_a_file_that_ends_inside_a_stanza_is_incomplete():
    """v3 section 9.2: unbalanced braces, or a file that ends inside a
    stanza, give config-incomplete."""
    text = _BASE.rstrip("\n").rsplit("\n", 1)[0] + "\n"     # drop the last `}`
    r = _parse(text)
    assert r["parses"] is False and r["reason"] == "config-incomplete", r


def test_an_extra_closing_brace_is_off():
    r = _parse(_BASE + "}\n")
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 16, r


def test_a_missing_final_newline_still_parses():
    assert _parse(_BASE.rstrip("\n"))["parses"] is True


def test_an_empty_file_is_not_accepted():
    r = _parse("")
    assert r["parses"] is False, r


# ------------------------------------------------ the slice-4 attack rows

@pytest.mark.parametrize("rel,line", [
    ("cfg3/k05_junos_delete_annotation_binding.conf", 2),   # `delete:`
    ("cfg3/k18_junos_replace_tag_subtree_save.conf", 18),   # `replace:`
    ("cfg3/k19_junos_inactive_binding.conf", 2),            # `inactive:`
])
def test_a_junos_tag_is_off_and_marks_a_patch(rel, line, shadow):
    """v4 section 4: no lexing row strips a `word:` prefix, and a tagged
    file is a patch. The line reason comes first; the tag is recorded."""
    sh = _gate_shadow(os.path.join(_D, rel))
    assert sh["boundary"]["reason"] is None, sh
    assert sh["blocking_reason"] == "line-not-allowlisted", sh
    assert sh["grammar"]["line"] == line, sh
    assert sh["grammar"]["tags"] == [line], sh
    assert sh["would_pass"] is False, sh


def test_set_form_is_off_at_line_one(shadow):
    """k08: set-form commands have no cited production (Exa does not carry
    the set-form syntax blocks), and `deactivate` is a tag verb (v4
    section 4)."""
    sh = _gate_shadow(os.path.join(_D, "cfg3/k08_junos_set_deactivate_term.set"))
    assert sh["blocking_reason"] == "line-not-allowlisted", sh
    assert sh["grammar"]["line"] == 1, sh


def _junos_files():
    out = []
    for sub in ("design/controls", "design/cfg", "design/cfg2", "design/cfg3",
                "design/cfg4", "boundary"):
        for f in os.listdir(os.path.join(_V, sub)):
            out.append(f"{sub}/{f}")
    return sorted(out)


def test_only_the_positive_control_parses(shadow, monkeypatch):
    """Every design and boundary file the boundary lets through as Junos:
    the grammar accepts k00 and nothing else, and none would pass."""
    accepted = []
    for rel in _junos_files():
        sh = _gate_shadow(os.path.join(_V, rel))
        assert sh["would_pass"] is False, (rel, sh)
        if "grammar" not in sh:
            continue
        assert sh["boundary"]["dialects"] == ["junos"], (rel, sh)
        if sh["grammar"]["parses"]:
            accepted.append(rel)
            assert sh["blocking_reason"] == "file-uncertified", (rel, sh)
    assert accepted == ["design/controls/k00_base.conf"], accepted


def test_no_grammar_block_outside_junos(shadow):
    for rel in ("controls/p00_base.set", "controls/i00_base.sh"):
        sh = _gate_shadow(os.path.join(_D, rel))
        assert "grammar" not in sh, sh
        assert sh["blocking_reason"] == "file-uncertified", sh


def test_a_vendor_value_that_is_not_junos_runs_no_grammar(shadow):
    sh = _gate_shadow(_K00, "panos")
    assert sh["blocking_reason"] == "dialect-undetected", sh
    assert "grammar" not in sh, sh


def test_the_grammar_runs_only_after_the_boundary(shadow, tmp_path):
    """A boundary reason comes first: a Cisco line vetoes before any
    production is tried."""
    sh = _gate_shadow(_write(tmp_path, "k.conf", _BASE + "interface Gi0/1\n"))
    assert sh["blocking_reason"] == "dialect-not-exclusive", sh
    assert "grammar" not in sh, sh
