"""#42 phase 2: mutation families 2 (sequence and order) and 4 (opaque
and lexing boundaries), and the metamorphic deletion checks (design v2
section 12), in shadow.

Every mutant carries its ground truth, decided from the cited rows and
the mutant's text, never from the engine:
- `LEAK`: CORP reaches PCI;
- `SAFE`: CORP does not reach PCI;
- `OPEN`: the cited rows do not settle it.
A truth that rests on a pending row is `OPEN` (review of #60-#62, F60-1
and F60-2). Every iptables truth rests on `iptables-script-scope`: `-A`
appends after the rules already loaded, which no cited row states, so a
rule before the script may decide any flow first. A PAN-OS second rule
rests on `panos-rule-order` and `panos-any-meaning`. A lexing variant
(tab, CRLF, doubled or trailing space) rests on `junos-lexing` or
`panos-lexing`. The Junos rows left `SAFE` use only the canonical spelling
the narrowed classes accept and rest on cited rows for their meaning; the
file-level pending rows still block every record on their own.

Each also pins the checker's exact answer, or `REFUSED` when the grammar
does not read the file (no `checker_verdict`). The pinned answer must fit
the truth: a LEAK or OPEN mutant never gets `no-witness`, and a SAFE one
never gets `witness`. Agreeing with the engine counts for nothing.

The metamorphic checks: deleting any one line of a control either makes
the grammar refuse the file or changes its final model (a line the model
ignores would be a bug), and deleting a binding never leaves
`no-witness`. Nothing here changes output: `would_pass` stays false, and
the switch is set only inside these tests.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import dialects  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_K00 = os.path.join(_D, "controls", "k00_base.conf")
_P00 = os.path.join(_D, "controls", "p00_base.set")
_I00 = os.path.join(_D, "controls", "i00_base.sh")
_POL = os.path.join(_D, "pol", "v4_ip.json")

LEAK, SAFE, OPEN = "leak", "safe", "open"
REFUSED = "refused"
_FITS = {LEAK: {"witness", "indeterminate", REFUSED},
         SAFE: {"no-witness", "indeterminate", REFUSED},
         OPEN: {"witness", "indeterminate", REFUSED}}


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _policy():
    with open(_POL, encoding="utf-8") as fh:
        return json.load(fh)


_K = _read(_K00)
_P = _read(_P00)
_I = _read(_I00)
_TD = ("            term d {\n"
       "                from { source-address { 192.0.2.0/24; } "
       "destination-address { 198.51.100.0/24; } }\n"
       "                then discard;\n"
       "            }\n")
_TA = "            term a { from { source-address { 203.0.113.0/24; } } then accept; }\n"
_ALL = "            term z { then accept; }\n"
_ANY_RULE = ("set rulebase security rules z from any to any source any destination any "
             "application any service any action allow\n")
_DROP = _I.split("\n", 1)[1]           # the -A line of i00


def _answer(text: str) -> str:
    sh = dialects.shadow_block(text.encode("utf-8"), "auto", _policy())
    assert sh["would_pass"] is False, sh
    cv = sh.get("checker_verdict")
    if cv is None:
        return REFUSED
    (a,) = cv["assertions"]
    return a["checker"]


def test_the_controls_are_what_the_mutants_start_from():
    assert _TD in _K and _TA in _K and _TD + _TA in _K
    for text in (_K, _P):
        assert _answer(text) == "no-witness"
    # F60-1: i00's truth rests on the pending iptables-script-scope.
    assert _answer(_I) == "indeterminate"


# ------------------------------------------------- family 2: sequence and order

_FAMILY_2 = [
    # Junos terms are evaluated in configuration order (junos-term-order).
    ("junos-accept-all-first", _K.replace(_TD, _ALL + _TD), LEAK, "witness"),
    ("junos-accept-all-last", _K.replace(_TA, _TA + _ALL), SAFE, "no-witness"),
    ("junos-terms-swapped", _K.replace(_TD + _TA, _TA + _TD), SAFE, "no-witness"),
    ("junos-discard-term-without-match-first",
     _K.replace(_TD, "            term x { then discard; }\n" + _TD), SAFE, "no-witness"),
    # PAN-OS: a second rule is not read (rule order is pending).
    ("panos-allow-any-first", _ANY_RULE + _P, LEAK, REFUSED),
    # F60-2: rule order and `any` are pending, so the truth is open.
    ("panos-allow-any-last", _P + _ANY_RULE, OPEN, REFUSED),
    # A source half outside rule d falls to the pending default rules.
    ("panos-half-prefix", _P.replace("source 192.0.2.0/24", "source 192.0.2.0/25"), OPEN,
     "indeterminate"),
    # iptables: -A appends; the first match decides (iptables-first-match).
    # F60-1: every truth rests on the pending script scope, so OPEN.
    ("iptables-accept-first", "iptables -P FORWARD DROP\niptables -A FORWARD -j ACCEPT\n"
     + _DROP, OPEN, "indeterminate"),
    ("iptables-accept-last", _I + "iptables -A FORWARD -j ACCEPT\n", OPEN, "indeterminate"),
    ("iptables-policy-after-the-rule", _DROP + "iptables -P FORWARD ACCEPT\n", OPEN,
     "indeterminate"),
    ("iptables-insert-at-the-top", _I + "iptables -I FORWARD 1 -j ACCEPT\n", LEAK, REFUSED),
    ("iptables-accept-policy-and-no-rule", "iptables -P FORWARD ACCEPT\n", OPEN,
     "indeterminate"),
]

# ------------------------------------------- family 4: opaque and lexing boundaries

_FAMILY_4 = [
    # A comment is inert: the file means what k00 means. The checker does
    # not read comments, so it cannot decide.
    ("junos-hash-comment-line", _K.replace(_TA, _TA + "            # term z { then accept; }\n"),
     SAFE, "indeterminate"),
    ("junos-slash-comment-line",
     _K.replace(_TA, _TA + "            /* term z { then accept; } */\n"), SAFE, "indeterminate"),
    ("junos-multi-line-comment",
     _K.replace(_TA, _TA + "            /*\n            term z { then accept; }\n            */\n"),
     SAFE, REFUSED),
    ("junos-comment-hides-the-action", _K.replace("then discard;", "# then discard;"), OPEN,
     REFUSED),
    # Lexing: LF only, single spaces, exact lowercase keywords (pending rows).
    ("junos-tab", _K.replace("    family inet {\n        filter F",
                             "    family inet {\n\tfilter F"), OPEN, REFUSED),
    ("junos-crlf", _K.replace("\n", "\r\n"), OPEN, REFUSED),
    ("junos-double-space", _K.replace("then discard;", "then  discard;"), OPEN, REFUSED),
    ("junos-upper-case-keyword", _K.replace("then discard;", "then DISCARD;"), OPEN, REFUSED),
    ("junos-quoted-filter-name", _K.replace("filter F {", 'filter "F" {'), OPEN, REFUSED),
    ("junos-trailing-space", _K.replace("then discard;\n", "then discard; \n"), OPEN, REFUSED),
    ("junos-nbsp", _K.replace("then discard;", "then discard;"), OPEN, REFUSED),
    ("panos-quoted-rule-name", _P.replace("rules d ", 'rules "d" '), OPEN, REFUSED),
    ("panos-tab", _P.replace(" action deny", "\taction deny"), OPEN, REFUSED),
    ("panos-crlf", _P.replace("\n", "\r\n"), OPEN, REFUSED),
    ("iptables-rule-commented-out", "iptables -P FORWARD ACCEPT\n# " + _DROP, LEAK, REFUSED),
    ("iptables-trailing-comment", _I.replace("-j DROP\n", "-j DROP # x\n"), OPEN, REFUSED),
    ("iptables-line-continuation",
     _I.replace("-d 198.51.100.0/24 -j DROP", "-d 198.51.100.0/24 \\\n  -j DROP"), OPEN,
     REFUSED),
    ("iptables-semicolon", _I.replace("-j DROP\n", "-j DROP; iptables -P FORWARD ACCEPT\n"),
     OPEN, REFUSED),
    ("iptables-nbsp", _I.replace("-j DROP", "-j DROP"), OPEN, REFUSED),
]


@pytest.mark.parametrize("name,text,truth,expected", _FAMILY_2 + _FAMILY_4,
                         ids=[m[0] for m in _FAMILY_2 + _FAMILY_4])
def test_each_mutant_gets_an_answer_that_fits_its_ground_truth(name, text, truth, expected):
    assert expected in _FITS[truth], (name, truth, expected)
    assert _answer(text) == expected, name


def test_the_mutants_are_real_changes():
    for name, text, _, _ in _FAMILY_2 + _FAMILY_4:
        assert text not in (_K, _P, _I), name


def test_every_family_has_a_leak_the_checker_reads():
    """Not vacuous: family 2 has leaks the checker reads and finds (Junos;
    every iptables truth is open while iptables-script-scope is pending,
    F60-1), and the iptables mutants it reads are indeterminate."""
    reads = [m for m in _FAMILY_2 if m[2] == LEAK and m[3] == "witness"]
    assert {m[0].split("-")[0] for m in reads} >= {"junos"}, reads
    ipt = [m for m in _FAMILY_2 if m[0].startswith("iptables") and m[3] != REFUSED]
    assert ipt and all(m[2] == OPEN and m[3] == "indeterminate" for m in ipt), ipt


# ------------------------------------------------- metamorphic deletion checks

def _lines(text):
    return text.split("\n")[:-1]


@pytest.mark.parametrize("path", [_K00, _P00, _I00], ids=["k00", "p00", "i00"])
def test_deleting_any_line_refuses_the_file_or_changes_its_model(path):
    text = _read(path)
    base = dialects.shadow_block(text.encode(), "auto", _policy())["model"]
    lines = _lines(text)
    for i in range(len(lines)):
        mutant = "\n".join(lines[:i] + lines[i + 1:]) + "\n"
        sh = dialects.shadow_block(mutant.encode(), "auto", _policy())
        assert sh["would_pass"] is False
        if "model" in sh:
            assert sh["model"] != base, (os.path.basename(path), i, lines[i])


# Ground truth for each one-line deletion the grammar still reads.
_DELETIONS = {
    ("k00", 1): (OPEN, "indeterminate"),    # CORP's unit gone: CORP enters nowhere cited
    ("k00", 2): (SAFE, "no-witness"),       # PCI's unit gone: CORP's F still discards
    ("k00", 8): (SAFE, "no-witness"),       # term d matches everything and discards
    ("k00", 11): (SAFE, "no-witness"),      # term a gone: the implicit discard
    # F60-1: an iptables truth rests on the pending script scope.
    ("i00", 0): (OPEN, "indeterminate"),    # no policy line: prior rules and policy unknown
    ("i00", 1): (OPEN, "indeterminate"),    # no rule: prior rules unknown
}


def test_every_deletion_the_grammar_reads_is_pinned_to_its_truth():
    seen = set()
    for tag, path in (("k00", _K00), ("p00", _P00), ("i00", _I00)):
        lines = _lines(_read(path))
        for i in range(len(lines)):
            mutant = "\n".join(lines[:i] + lines[i + 1:]) + "\n"
            got = _answer(mutant)
            if got == REFUSED:
                assert (tag, i) not in _DELETIONS, (tag, i)
                continue
            seen.add((tag, i))
            truth, expected = _DELETIONS[(tag, i)]
            assert expected in _FITS[truth] and got == expected, (tag, i, got)
    assert seen == set(_DELETIONS), seen


@pytest.mark.parametrize("side,truth,expected", [
    ("ge-0/0/0", LEAK, "witness"),          # CORP's ingress unfiltered
    ("ge-0/0/1", OPEN, "indeterminate"),    # another unit unfiltered (review of #58, H1)
])
def test_deleting_a_binding_never_leaves_no_witness(side, truth, expected):
    old = side + " { unit 0 { family inet { filter { input F; } address"
    assert old in _K
    got = _answer(_K.replace(old, side + " { unit 0 { family inet { address"))
    assert expected in _FITS[truth] and got == expected, (side, got)


# --------------------------------------------- review of #60-#62, F60-3 and F60-4

def test_a_source_held_by_two_units_is_indeterminate():
    """F60-3: a ge-0/0/2 unit at 192.0.0.1/16 holds CORP's /24 too, so CORP
    has no single ingress and may stay on one segment with X; the checker
    must not pick one unit (kills the pick-the-first mutant)."""
    text = _K.replace(
        "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n",
        "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n"
        "    ge-0/0/2 { unit 0 { family inet { filter { input F; } address 192.0.0.1/16; } } }\n")
    assert "192.0.0.1/16" in text
    pol = _policy()
    pol["zones"]["PCI"] = ["192.0.5.0/24"]
    sh = dialects.shadow_block(text.encode("utf-8"), "auto", pol)
    assert sh["would_pass"] is False, sh
    (a,) = sh["checker_verdict"]["assertions"]
    assert a["checker"] == "indeterminate", a


def test_a_junos_term_with_no_then_is_indeterminate():
    """F60-4: the checker's own reading takes a term with no `then`; its
    action is uncited, so the flow is undecided (kills the mutants that read
    it as discard, or that end the walk as known). The grammar refuses the
    line first, so this calls the checker directly."""
    from rulehawk_check.evaluate import evaluate
    assert "                then discard;\n" in _K
    raw = _K.replace("                then discard;\n", "").encode("utf-8")
    assert evaluate("junos", raw, _policy()) == ["indeterminate"]
    assert evaluate("junos", _K.encode("utf-8"), _policy()) == ["no-witness"]


def test_the_iptables_plan_still_reads_the_source_and_the_policy():
    """While iptables-script-scope is pending every iptables answer is
    indeterminate, so a wrong `-s` or policy reading cannot change an answer.
    The plan behind the unknown head entry is pinned directly, so those
    mutants (any source; an unset policy read as DROP) still die."""
    import ipaddress
    from rulehawk_check.derive import derive
    from rulehawk_check.evaluate import _iptables
    from rulehawk_check.split import split_bytes
    n = ipaddress.IPv4Network
    src, dst = [n("192.0.2.0/24")], [n("198.51.100.0/24")]
    ((entries, default, space),) = _iptables(
        derive("iptables", split_bytes(_I.encode())), src, dst, "must_not_reach")
    assert entries == [([n("0.0.0.0/0")], [n("0.0.0.0/0")], "unknown"),
                       ([n("192.0.2.0/24")], [n("198.51.100.0/24")], "deny")], entries
    assert default == "deny" and space == [(src[0], dst[0])]
    ((_, default, _),) = _iptables(
        derive("iptables", split_bytes(_DROP.encode())), src, dst, "must_not_reach")
    assert default is None
