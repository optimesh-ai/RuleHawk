"""#42 phase 2, slice 4d: the iptables token language and its productions,
in shadow (design v2 sections 6-8, v3 sections 6.1, 7, 8, v4 sections 3,
12-14).

Only cited rows get productions, all from iptables(8) (1.8.13, man7.org).
The grammar reads `iptables` commands one per line, in the filter table
(no `-t`) on the built-in INPUT, FORWARD and OUTPUT chains:
`iptables -P CHAIN ACCEPT|DROP` and
`iptables -A CHAIN [-s PREFIX] [-d PREFIX] -j ACCEPT|DROP`, with a prefix
in dotted-quad/length form and no host bits. LF line ends, printable
ASCII, single spaces, exact spelling (no abbreviation, no long option);
no shell syntax at all: no shebang, comment, variable, quote, function,
conditional, heredoc, `exit` or blank line. No `-I`, `-N`, `-F`, `-g`,
`-m`, `-p`, `!`, and no iptables-save format.

The duplicate and merge forms are off from the start (review of #51, F1):
a chain policy set twice is `write-merge-uncited`, and the same rule
appended twice is off.

i00 parses; `would_pass` stays false.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_V = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants")
_D = os.path.join(_V, "design")
_I00 = os.path.join(_D, "controls", "i00_base.sh")


def _gm():
    from rulehawk import grammar_iptables
    return grammar_iptables


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


# ------------------------------------------------------- productions are cited

def test_every_production_rests_on_cited_rows():
    gm = _gm()
    from rulehawk import citations
    assert gm.PRODUCTIONS
    for p in gm.PRODUCTIONS:
        assert p.cites, p
        for cid in p.cites:
            assert cid.startswith("iptables-"), cid
            citations.resolve(cid)


def test_no_production_rests_on_a_pending_row():
    gm = _gm()
    from rulehawk import citations
    used = {cid for p in gm.PRODUCTIONS for cid in p.cites}
    assert not used & set(citations.PENDING)


def test_every_production_records_the_script_scope_as_pending():
    gm = _gm()
    from rulehawk import citations
    for p in gm.PRODUCTIONS:
        assert p.needs == ("iptables-script-scope",), p
        assert set(p.needs) <= set(citations.PENDING), p


def test_the_grammar_module_imports_only_the_standard_library_and_the_grammar_core():
    for base in ("rulehawk", os.path.join("docs", "rulehawk")):
        src = _read(os.path.join(_ROOT, base, "grammar_iptables.py"))
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    assert node.module in ("citations", "grammar_junos"), node.module
                    continue
                mods = [node.module or ""]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert m.split(".")[0] in ("__future__", "re", "typing"), m


def test_no_all_clear_word_in_the_grammar():
    src = _read(os.path.join(_ROOT, "rulehawk", "grammar_iptables.py"))
    assert not re.search(r"\bPASS\b|\bVERIFIED\b|NO_NEW_RISK|\"certified\"|\"complete\"", src)


def test_the_productions_are_pairwise_disjoint_and_fixed_shape():
    gm = _gm()
    from rulehawk import grammar_junos as core
    assert core.overlaps(gm.PRODUCTIONS, gm.CLASSES) == []
    assert gm.shape_problems(gm.PRODUCTIONS, gm.CLASSES) == []


def test_the_shape_check_finds_a_bad_production():
    gm = _gm()
    from rulehawk.grammar_junos import Production
    bad = (Production("line", ("iptables", "a b"), None, ("iptables-append",)),
           Production("line", (), None, ("iptables-append",)))
    assert len(gm.shape_problems(bad, gm.CLASSES)) == 2


def test_classes_exclude_every_keyword():
    gm = _gm()
    for name, k in gm.CLASSES.items():
        for kw in gm.KEYWORDS:
            assert not k.matches(kw), (name, kw)


def test_two_productions_matching_one_line_is_parse_ambiguous(monkeypatch):
    gm = _gm()
    monkeypatch.setattr(gm, "PRODUCTIONS", tuple(gm.PRODUCTIONS) * 2)
    r = _parse(_read(_I00))
    assert r["reason"] == "parse-ambiguous" and r["line"] == 1, r


# ----------------------------------------------------------------- i00 parses

def test_the_grammar_accepts_i00():
    r = _parse(_read(_I00))
    assert r == {"parses": True, "reason": None, "line": None, "rows": r["rows"],
                 "tags": [], "pending": ["iptables-script-scope"]}, r
    assert {"iptables-policy", "iptables-append", "iptables-source",
            "iptables-destination", "iptables-mask", "iptables-jump",
            "iptables-accept-drop", "iptables-first-match",
            "iptables-filter-default", "iptables-filter-chains"} <= set(r["rows"]), r
    assert r["rows"] == sorted(set(r["rows"]))


def test_i00_parses_but_would_pass_stays_false(shadow):
    sh = _gate_shadow(_I00)
    assert sh["grammar"]["parses"] is True, sh
    assert sh["would_pass"] is False, sh
    assert sh["blocking_reason"] == "file-uncertified", sh


@pytest.mark.parametrize("line", [
    "iptables -P INPUT ACCEPT", "iptables -P OUTPUT DROP",
    "iptables -A FORWARD -j ACCEPT", "iptables -A INPUT -s 10.0.0.0/8 -j DROP",
    "iptables -A OUTPUT -d 0.0.0.0/0 -j ACCEPT",
    "iptables -A FORWARD -s 203.0.113.7/32 -d 198.51.100.0/24 -j ACCEPT",
])
def test_every_cited_form_parses(line):
    assert _parse(_read(_I00) + line + "\n")["parses"] is True


# ------------------------------------------------- per-production meaning examples

_BASE = _read(_I00)
_RULE = "iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP"
assert _RULE in _BASE


@pytest.mark.parametrize("old,new", [
    # exact spelling: no case change, abbreviation or long option
    ("iptables -A", "IPTABLES -A"),
    ("-j DROP", "-j drop"),
    ("FORWARD", "forward"),
    ("-A FORWARD", "--append FORWARD"),
    ("-A FORWARD", "--app FORWARD"),
    ("-s 192", "--source 192"),
    ("-s 192", "--src 192"),
    ("-j DROP", "--jump DROP"),
    # other binaries, tables, commands and targets
    ("iptables -A", "ip6tables -A"),
    ("iptables -A", "iptables-legacy -A"),
    ("iptables -A", "/sbin/iptables -A"),
    ("iptables -A", "iptables -t filter -A"),
    ("iptables -A", "iptables -w -A"),
    ("-A FORWARD", "-I FORWARD"),
    ("-A FORWARD", "-A PREROUTING"),
    ("-A FORWARD", "-A CHK"),
    ("-j DROP", "-j REJECT"),
    ("-j DROP", "-j RETURN"),
    ("-j DROP", "-g DROP"),
    ("-j DROP", ""),
    # matches: only -s and -d, in that order, each a prefix
    ("-s 192.0.2.0/24 -d 198.51.100.0/24", "-d 198.51.100.0/24 -s 192.0.2.0/24"),
    ("-s 192.0.2.0/24", "! -s 192.0.2.0/24"),
    ("-s 192.0.2.0/24", "-s 192.0.2.0/24,203.0.113.0/24"),
    ("-s 192.0.2.0/24", "-s 192.0.2.0"),
    ("-s 192.0.2.0/24", "-s 192.0.2.0/255.255.255.0"),
    ("-s 192.0.2.0/24", "-s 192.0.2.1/24"),
    ("-s 192.0.2.0/24", "-s 192.0.2.0/33"),
    ("-s 192.0.2.0/24", "-s corp.example"),
    ("-s 192.0.2.0/24", "-s $CORP"),
    ("-s 192.0.2.0/24", '-s "192.0.2.0/24"'),
    ("-d 198.51.100.0/24", "-d 198.51.100.0/24 -p tcp"),
    ("-d 198.51.100.0/24", "-d 198.51.100.0/24 -m limit --limit 10/second"),
    ("-d 198.51.100.0/24", "-d 198.51.100.0/24 -f"),
    ("-j DROP", "-j DROP -c 0 0"),
    # whitespace and bytes
    ("iptables -A", "iptables  -A"),
    ("iptables -A", "iptables\t-A"),
    ("iptables -A", " iptables -A"),
    ("-j DROP", "-j DROP "),
    ("-j DROP", "-j DROP\r"),
    ("-j DROP", "-j DROP;"),
    ("-j DROP", "-j DROP # note"),
    ("-j DROP", "-j DROP "),
])
def test_a_mutation_is_off_at_its_line(old, new):
    assert old in _RULE, old
    r = _parse(_BASE.replace(_RULE, _RULE.replace(old, new, 1)))
    assert r["parses"] is False and r["reason"] == "line-not-allowlisted", (new, r)
    assert r["line"] == 2, (new, r)


@pytest.mark.parametrize("extra", [
    "", "#!/bin/sh", "# a comment", "exit 0", "set -e", "CORP=192.0.2.0/24",
    "iptables -F", "iptables -F FORWARD", "iptables -N CHK", "iptables -X",
    "iptables -D FORWARD 1", "iptables -Z", "iptables -L",
    "iptables -I FORWARD -s 192.0.2.0/24 -j ACCEPT",
    "iptables-restore < rules.v4", "*filter", ":FORWARD DROP [0:0]", "COMMIT",
    "-A FORWARD -s 192.0.2.0/24 -j DROP",
])
def test_a_line_with_no_production_is_off(extra):
    r = _parse(_BASE + extra + "\n")
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 3, (extra, r)


# ---------------------------------------------------- duplicate and merge forms

def test_a_policy_set_twice_is_write_merge_uncited():
    """The second -P replaces the first; no merge rule is cited (i05)."""
    r = _parse(_BASE + "iptables -P FORWARD ACCEPT\n")
    assert r["reason"] == "write-merge-uncited" and r["line"] == 3, r
    r = _parse(_BASE + "iptables -P FORWARD DROP\n")
    assert r["reason"] == "write-merge-uncited" and r["line"] == 3, r


def test_a_policy_on_another_chain_is_not_a_merge():
    assert _parse(_BASE + "iptables -P INPUT DROP\n")["parses"] is True


def test_the_same_rule_twice_is_off():
    r = _parse(_BASE + _RULE + "\n")
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 3, r


def test_a_missing_final_newline_still_parses():
    assert _parse(_BASE.rstrip("\n"))["parses"] is True


def test_an_empty_file_is_not_accepted():
    assert _parse("")["parses"] is False


# ------------------------------------------------ the design's iptables rows

_OFF = {
    "cfg/i01_iptables_exit_before_drop.sh": ("line-not-allowlisted", 1),
    "cfg3/i02_iptables_goto_falls_to_policy.sh": ("line-not-allowlisted", 2),
    "cfg3/i03_iptables_limit_on_drop.sh": ("line-not-allowlisted", 2),
    "cfg3/i04_iptables_return_in_user_chain.sh": ("line-not-allowlisted", 2),
    "cfg3/i05_iptables_policy_twice.sh": ("write-merge-uncited", 3),
    "cfg3/i06_iptables_ipset_accept_first.sh": ("line-not-allowlisted", 2),
    "cfg3/i08_iptables_fragment_only_drop.sh": ("line-not-allowlisted", 2),
    "cfg3/i09_iptables_restore_noflush.rules": ("line-not-allowlisted", 1),
    "cfg3/i10_iptables_lowercase_chain.sh": ("line-not-allowlisted", 2),
    "cfg3/i12_iptables_time_window_drop.sh": ("line-not-allowlisted", 2),
    "cfg3/i13_iptables_nfqueue_bypass.sh": ("line-not-allowlisted", 2),
    "cfg3/i14_iptables_insert_accept_top.sh": ("line-not-allowlisted", 3),
    "cfg3/i15_iptables_shell_var_reassigned.sh": ("line-not-allowlisted", 1),
    "cfg3/i16_iptables_conditional_drop.sh": ("line-not-allowlisted", 2),
    "cfg3/i17_iptables_save_two_filter_blocks.rules": ("line-not-allowlisted", 1),
    "cfg3/i18_iptables_save_invalid_line_aborts.rules": ("line-not-allowlisted", 1),
    "cfg3/i19_iptables_iprange_partial.sh": ("line-not-allowlisted", 2),
}


@pytest.mark.parametrize("rel", sorted(_OFF))
def test_a_design_iptables_file_is_off_at_its_line(rel, shadow):
    sh = _gate_shadow(os.path.join(_D, rel))
    assert sh["boundary"]["reason"] is None, sh
    reason, line = _OFF[rel]
    assert sh["blocking_reason"] == reason, sh
    assert sh["grammar"]["line"] == line, sh
    assert sh["would_pass"] is False, sh


@pytest.mark.parametrize("rel", ["cfg3/i07_iptables_heredoc_not_executed.sh",
                                 "cfg3/i11_iptables_function_never_called.sh"])
def test_heredoc_and_function_files_never_parse(rel, shadow):
    """The boundary may stop these first; either way nothing parses."""
    sh = _gate_shadow(os.path.join(_D, rel))
    assert sh["blocking_reason"] == "line-not-allowlisted", sh
    assert sh["would_pass"] is False, sh
    if "grammar" in sh:
        assert sh["grammar"]["parses"] is False and sh["grammar"]["line"] == 2, sh


def test_a_vendor_value_that_is_not_iptables_runs_no_grammar(shadow):
    sh = _gate_shadow(_I00, "junos")
    assert sh["blocking_reason"] == "dialect-undetected", sh
    assert "grammar" not in sh, sh


def test_a_pending_iptables_row_fails_a_shadow_run_closed(monkeypatch, shadow):
    """Review of #51, F3, for iptables."""
    import rulehawk
    from rulehawk import citations
    monkeypatch.setitem(citations.PENDING, "iptables-append", "test: pending")
    monkeypatch.delitem(sys.modules, "rulehawk.grammar_iptables", raising=False)
    monkeypatch.delattr(rulehawk, "grammar_iptables", raising=False)
    sh = _gate_shadow(_I00)
    monkeypatch.delitem(sys.modules, "rulehawk.grammar_iptables", raising=False)
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert "grammar" not in sh and "iptables-append" in sh["grammar_unavailable"], sh
    assert sh["would_pass"] is False, sh
