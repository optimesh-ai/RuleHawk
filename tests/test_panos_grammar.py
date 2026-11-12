"""#42 phase 2, slice 4c: the PAN-OS token language and its productions, in
shadow (design v2 sections 6-8, v3 sections 6.1, 7, 8, v4 sections 3, 12-14).

Only cited rows get productions. The grammar reads set-form lines only, one
whole security rule per line in the order the Palo Alto Networks knowledge
base shows (`set rulebase security rules <name> from <zone> to <zone> source
<addr> destination <addr> application <app> service <svc> action <action>`),
with zones, application and service `any`, an address `any` or an IPv4
prefix, and `allow` or `deny`. LF line ends, printable ASCII, no
indentation, single spaces, exact lowercase keywords; no quotes, no `[ ]`
lists (the set-CLI list semantics are not a row, v4 section 14), no object
names, no per-attribute lines, no comments, no blank lines.

k00 is the Junos control; here p00 parses, and `would_pass` stays false.
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
_P00 = os.path.join(_D, "controls", "p00_base.set")


def _gm():
    from rulehawk import grammar_panos
    return grammar_panos


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
            assert cid.startswith("panos-"), cid
            citations.resolve(cid)


def test_no_production_rests_on_a_pending_row():
    gm = _gm()
    from rulehawk import citations
    used = {cid for p in gm.PRODUCTIONS for cid in p.cites}
    assert not used & set(citations.PENDING)


def test_the_grammar_module_imports_only_the_standard_library_and_the_grammar_core():
    for base in ("rulehawk", os.path.join("docs", "rulehawk")):
        src = _read(os.path.join(_ROOT, base, "grammar_panos.py"))
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
    src = _read(os.path.join(_ROOT, "rulehawk", "grammar_panos.py"))
    assert not re.search(r"\bPASS\b|\bVERIFIED\b|NO_NEW_RISK|\"certified\"|\"complete\"", src)


def test_the_productions_are_pairwise_disjoint_and_fixed_shape():
    gm = _gm()
    from rulehawk import grammar_junos as core
    assert core.overlaps(gm.PRODUCTIONS, gm.CLASSES) == []
    assert gm.shape_problems(gm.PRODUCTIONS, gm.CLASSES) == []


def test_the_shape_check_finds_a_bad_production():
    gm = _gm()
    from rulehawk.grammar_junos import Production
    bad = (Production("line", ("set", "NOSUCH"), None, ("panos-action",)),
           Production("line", ("set", "a b"), None, ("panos-action",)),
           Production("line", (), None, ("panos-action",)))
    assert len(gm.shape_problems(bad, gm.CLASSES)) == 3


def test_name_classes_exclude_every_keyword():
    gm = _gm()
    for name, k in gm.CLASSES.items():
        for kw in gm.KEYWORDS:
            assert not k.matches(kw), (name, kw)


def test_two_productions_matching_one_line_is_parse_ambiguous(monkeypatch):
    gm = _gm()
    monkeypatch.setattr(gm, "PRODUCTIONS", tuple(gm.PRODUCTIONS) * 2)
    r = _parse(_read(_P00))
    assert r["reason"] == "parse-ambiguous" and r["line"] == 1, r


# ----------------------------------------------------------------- p00 parses

def test_the_grammar_accepts_p00():
    r = _parse(_read(_P00))
    assert r == {"parses": True, "reason": None, "line": None,
                 "rows": r["rows"], "tags": [], "pending": r["pending"]}, r
    assert {"panos-cli-create-rule", "panos-set-source-any", "panos-source-address",
            "panos-destination-address", "panos-action", "panos-rule-name"} <= set(r["rows"])
    assert r["rows"] == sorted(set(r["rows"]))


def test_p00_parses_but_would_pass_stays_false(shadow):
    sh = _gate_shadow(_P00)
    assert sh["grammar"]["parses"] is True, sh
    assert sh["would_pass"] is False, sh
    assert sh["blocking_reason"] == "file-uncertified", sh


@pytest.mark.parametrize("src,dst,action", [
    ("any", "any", "allow"), ("10.0.0.0/8", "any", "deny"),
    ("any", "203.0.113.7/32", "allow"), ("0.0.0.0/0", "198.51.100.0/24", "deny")])
def test_every_address_and_action_form_parses(src, dst, action):
    line = (f"set rulebase security rules r-1 from any to any source {src} "
            f"destination {dst} application any service any action {action}\n")
    assert _parse(line)["parses"] is True


# ------------------------------------------------- per-production meaning examples

_LINE = _read(_P00).rstrip("\n")


@pytest.mark.parametrize("old,new", [
    # keywords match only their exact spelling
    ("set rulebase", "SET rulebase"),
    ("action deny", "action Deny"),
    ("action deny", "action drop"),
    ("action deny", "action reset-client"),
    ("rulebase security", "rulebase nat"),
    ("set rulebase", "set vsys vsys1 rulebase"),
    # zones, application and service are `any` only
    ("from any", "from inside"),
    ("to any", "to pci"),
    ("application any", "application ssl"),
    ("service any", "service application-default"),
    ("service any", "service service-http"),
    # addresses: `any` or an IPv4 prefix; no object name, no list, no range
    ("source 192.0.2.0/24", "source CORPNET"),
    ("source 192.0.2.0/24", "source 203.0.113.5"),
    ("source 192.0.2.0/24", "source 192.0.2.0/33"),
    ("source 192.0.2.0/24", "source 192.0.2.00/24"),
    ("source 192.0.2.0/24", "source 192.0.2.0-192.0.2.127"),
    ("source 192.0.2.0/24", "source [ 192.0.2.0/24 ]"),
    ("source 192.0.2.0/24", "source 192.0.2.0/24 negate-source yes"),
    ("source 192.0.2.0/24", 'source "192.0.2.0/24"'),
    # the attribute order is fixed; nothing extra
    ("source 192.0.2.0/24 destination 198.51.100.0/24",
     "destination 198.51.100.0/24 source 192.0.2.0/24"),
    ("action deny", "action deny log-end yes"),
    ("action deny", ""),
    # rule names: up to 63 characters, letters, digits and hyphens
    ("rules d ", "rules " + "d" * 64 + " "),
    ("rules d ", "rules d_1 "),
    ("rules d ", "rules any "),
    ("rules d ", 'rules "d" '),
    # whitespace and bytes
    ("set rulebase", "set  rulebase"),
    ("set rulebase", "set\trulebase"),
    ("set rulebase", " set rulebase"),
    ("action deny", "action deny "),
    ("action deny", "action deny\r"),
    ("action deny", "action deny "),
])
def test_a_mutation_is_off_at_its_line(old, new):
    assert old in _LINE, old
    # review of #52/#53, F2: a file holds one rule, so the mutated rule is
    # the only line.
    r = _parse(_LINE.replace(old, new, 1) + "\n")
    assert r["parses"] is False and r["reason"] == "line-not-allowlisted", (new, r)
    assert r["line"] == 1, (new, r)


@pytest.mark.parametrize("extra", [
    "", "# a comment", "move rulebase security rules d top",
    "delete rulebase security rules d", "set rulebase security rules d disabled yes",
    "set rulebase security rules d source 203.0.113.0/24",
    "set rulebase security rules d from any",
    "set address CORPNET ip-netmask 192.0.2.0/24",
])
def test_a_line_with_no_production_is_off(extra):
    r = _parse(_LINE + "\n" + extra + "\n")
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 2, (extra, r)


def test_a_rule_name_set_twice_is_off_at_the_second_line():
    """Setting a rule that is already set merges into it (list attributes
    add members); the set-CLI list semantics are not a row (v3 section 6.1,
    v4 section 14), so the second line is off."""
    other = _LINE.replace("action deny", "action allow").replace("192.0.2.0/24", "any")
    r = _parse(_LINE + "\n" + other + "\n")
    assert r["reason"] == "write-merge-uncited" and r["line"] == 2, r


@pytest.mark.parametrize("old,new", [
    ("source 192.0.2.0/24", "source 192.0.2.1/24"),
    ("destination 198.51.100.0/24", "destination 198.51.100.7/24"),
])
def test_a_prefix_with_host_bits_is_off(old, new):
    """As for Junos (review of #51, F1 item 8): no row says how a prefix
    with host bits set is read."""
    r = _parse(_LINE.replace(old, new) + "\n")
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 1, r


def test_a_rule_name_twice_is_off_even_when_identical():
    r = _parse(_LINE + "\n" + _LINE + "\n")
    assert r["reason"] == "write-merge-uncited" and r["line"] == 2, r


_FILE_ROWS = {"panos-release-scope", "panos-lexing", "panos-list-semantics",
              "panos-default-rules", "panos-any-meaning", "panos-rule-type-default",
              "panos-session-semantics",
              # review of #52-#57, G1 and G2
              "panos-rule-order", "panos-one-line-order"}


def test_every_production_records_its_pending_rows():
    """Review of #51, F4, and of #52/#53, F1 and F2: the rule-name character
    set, the IPv4 prefix form and every file-level row are pending; each
    production records them as needs."""
    gm = _gm()
    from rulehawk import citations
    for p in gm.PRODUCTIONS:
        want = {"panos-rule-name-chars"} | _FILE_ROWS
        if "V4PREFIX" in p.slots:
            want.add("panos-v4-prefix")
        assert set(p.needs) == want, p
        assert set(p.needs) <= set(citations.PENDING), p


def test_every_production_cites_the_one_line_form_and_needs_rule_order():
    """Review of #52/#53, F3, and of #52-#57, G1 and G2: the one-line form
    rests on the KB article's one-line `set ... action allow source ...`;
    rule order and the token order stay pending, in every production's
    needs."""
    for p in _gm().PRODUCTIONS:
        assert "panos-one-line-form" in p.cites, p
        assert "panos-rule-order" not in p.cites, p
        assert {"panos-rule-order", "panos-one-line-order"} <= set(p.needs), p


def test_p00_lists_its_pending_rows():
    assert _parse(_read(_P00))["pending"] == sorted(
        {"panos-rule-name-chars", "panos-v4-prefix"} | _FILE_ROWS)


def test_a_second_rule_is_off():
    """Review of #52/#53, F2: two rules need rule order and the default
    rules' fall-through; a file holds one rule."""
    other = _LINE.replace("rules d ", "rules e ")
    r = _parse(_LINE + "\n" + other + "\n")
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 2, r


@pytest.mark.parametrize("name", ["D", "Rule1"])
def test_names_that_differ_only_in_case_are_off(name):
    first = _LINE.replace("rules d ", f"rules {name.lower()} ")
    second = _LINE.replace("rules d ", f"rules {name} ")
    r = _parse(first + "\n" + second + "\n")
    assert r["parses"] is False and r["line"] == 2, r


@pytest.mark.parametrize("name", ["intrazone-default", "interzone-default",
                                  "Intrazone-Default", "INTERZONE-DEFAULT"])
def test_a_default_rule_name_is_off(name):
    r = _parse(_LINE.replace("rules d ", f"rules {name} ") + "\n")
    assert r["reason"] == "line-not-allowlisted" and r["line"] == 1, r


def test_any_import_error_fails_a_shadow_run_closed(monkeypatch, shadow):
    """Review of #52/#53, F9: not only a pending row."""
    import rulehawk
    monkeypatch.setitem(sys.modules, "rulehawk.grammar_panos", None)
    monkeypatch.delattr(rulehawk, "grammar_panos", raising=False)
    sh = _gate_shadow(_P00)
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert "grammar" not in sh and sh["grammar_unavailable"], sh
    assert sh["would_pass"] is False, sh


def test_a_pending_panos_row_fails_a_shadow_run_closed(monkeypatch, shadow):
    """Review of #51, F3, for PAN-OS."""
    import rulehawk
    from rulehawk import citations
    monkeypatch.setitem(citations.PENDING, "panos-action", "test: pending")
    monkeypatch.delitem(sys.modules, "rulehawk.grammar_panos", raising=False)
    monkeypatch.delattr(rulehawk, "grammar_panos", raising=False)
    sh = _gate_shadow(_P00)
    monkeypatch.delitem(sys.modules, "rulehawk.grammar_panos", raising=False)
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert "grammar" not in sh and "panos-action" in sh["grammar_unavailable"], sh
    assert sh["would_pass"] is False, sh


def test_a_missing_final_newline_still_parses():
    assert _parse(_LINE)["parses"] is True


def test_an_empty_file_is_not_accepted():
    assert _parse("")["parses"] is False


# ------------------------------------------------ the design's PAN-OS rows

_OFF = {
    "cfg/p01_panos_object_named_like_literal.set": 1,
    "cfg3/p02_panos_rule_type_interzone_deny.set": 1,
    "cfg3/p03_panos_same_zone_two_segments.set": 1,
    "cfg3/p04_panos_move_rule_top.set": 2,     # a second rule (review F2)
    "cfg3/p05_panos_vsys_split_rulebase.set": 1,
    "cfg3/p06_panos_shared_object_shadowed.set": 1,
    "cfg3/p07_panos_ip_range_partial.set": 1,
    "cfg3/p08_panos_dnat_prenat_destination.set": 1,
    "cfg3/p09_panos_zone_defined_twice.set": 1,
    "cfg3/p10_panos_description_holds_cisco_and_quote.set": 1,
    "cfg3/p11_panos_list_attr_set_twice.set": 2,
    "cfg3/p12_panos_post_rulebase_before_local.set": 1,
    "cfg3/p13_panos_edl_source.set": 1,
    "cfg3/p14_panos_pci_nexthop_on_corp_segment.set": 1,
    "cfg3/p15_panos_disabled_deny.set": 2,
    "cfg3/p16_panos_negate_source_deny.set": 1,
}


@pytest.mark.parametrize("rel", sorted(_OFF))
def test_a_design_panos_file_is_off_at_its_line(rel, shadow):
    sh = _gate_shadow(os.path.join(_D, rel))
    assert sh["boundary"]["reason"] is None, sh
    assert sh["blocking_reason"] == "line-not-allowlisted", sh
    assert sh["grammar"]["line"] == _OFF[rel], sh
    assert sh["would_pass"] is False, sh


def _files():
    out = []
    for sub in ("design/controls", "design/cfg", "design/cfg2", "design/cfg3",
                "design/cfg4", "boundary"):
        for f in os.listdir(os.path.join(_V, sub)):
            out.append(f"{sub}/{f}")
    return sorted(out)


def test_only_the_positive_controls_parse(shadow):
    """Across every design and boundary file, the grammars accept i00, k00
    and p00 and nothing else, and none would pass."""
    accepted = []
    for rel in _files():
        sh = _gate_shadow(os.path.join(_V, rel))
        assert sh["would_pass"] is False, (rel, sh)
        if sh.get("grammar", {}).get("parses"):
            accepted.append(rel)
            assert sh["blocking_reason"] == "file-uncertified", (rel, sh)
    assert accepted == ["design/controls/i00_base.sh", "design/controls/k00_base.conf",
                        "design/controls/p00_base.set"]


def test_a_vendor_value_that_is_not_panos_runs_no_grammar(shadow):
    sh = _gate_shadow(_P00, "junos")
    assert sh["blocking_reason"] == "dialect-undetected", sh
    assert "grammar" not in sh, sh
