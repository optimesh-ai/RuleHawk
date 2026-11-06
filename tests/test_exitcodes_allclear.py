"""One exit-code table, and one gate for every all-clear (#42 phase 2, slice
1: design v4 sections 7 and 13, with the v4 errata R4-M2, R4-M3 and R4-L1).

- rulehawk/exitcodes.py holds the codes. README, docs/github-action.md and
  the three `--help` texts are rendered from it (test_exit_table_matches_docs).
- rulehawk/allclear.py is the only place an all-clear can come from. While
  its compiled-in RULEHAWK_CERT is 0 it gives the stopgap's answers.
- An AST scan over rulehawk/*.py, and a literal scan over the Actions, the
  hosted page and the hosted glue, fail on any all-clear literal outside
  allclear.py that is not on the pinned exemption lists below. Adding an
  entry is a reviewed change; so is removing one.
"""

from __future__ import annotations

import ast
import collections
import contextlib
import io
import os
import re
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from rulehawk import allclear, exitcodes  # noqa: E402

_PKG = os.path.join(_ROOT, "rulehawk")


def _read(rel: str) -> str:
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# The exit-code table (v4 section 7; errata: 4 is reserved)
# --------------------------------------------------------------------------- #
def test_exit_codes_are_the_published_values():
    assert (exitcodes.PASS, exitcodes.FAIL, exitcodes.INVALID, exitcodes.UNKNOWN,
            exitcodes.ACCEPTED) == (0, 1, 2, 3, 4)
    assert exitcodes.ADVISORY == exitcodes.HELP == 0
    assert exitcodes.COMBINE_UNKNOWN == 2
    # 4 is ACCEPTED's alone, and ACCEPTED is not emitted yet.
    others = {exitcodes.PASS, exitcodes.ADVISORY, exitcodes.HELP, exitcodes.FAIL,
              exitcodes.INVALID, exitcodes.UNKNOWN, exitcodes.COMBINE_UNKNOWN}
    assert exitcodes.ACCEPTED not in others
    assert exitcodes.ACCEPTED_EMITTED is False


def _help(main, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = main(argv)
    return rc, out.getvalue()


@pytest.mark.parametrize("command,argv", [("file", ["--help"]),
                                          ("gate", ["gate", "--help"]),
                                          ("combine", ["combine", "--help"])])
def test_exit_table_matches_docs(command, argv):
    from rulehawk import cli
    # The docs carry the generated block exactly once, byte for byte.
    for doc in ("README.md", os.path.join("docs", "github-action.md")):
        text = _read(doc)
        assert text.count(exitcodes.MARK_BEGIN) == 1, doc
        assert exitcodes.doc_block() in text, f"{doc}: regenerate the exit-code table"
    # Each --help prints its generated section and exits with the help code.
    rc, out = _help(cli.main, argv)
    assert rc == exitcodes.HELP
    assert exitcodes.help_section(command) in out, out
    # Every code in the help section is a published constant, and 4 is
    # listed as reserved.
    listed = [int(m) for m in re.findall(r"^  (\d)  ", exitcodes.help_section(command), re.M)]
    assert listed == exitcodes.codes(command)
    assert exitcodes.ACCEPTED in listed
    assert "reserved: not emitted until ACCEPTED ships" in out


def test_exit_table_cells_are_constants():
    values = {v for k, v in vars(exitcodes).items() if k.isupper() and isinstance(v, int)
              and not isinstance(v, bool)}
    for row in exitcodes.markdown_table().splitlines()[2:]:
        if not row.startswith("|"):
            continue
        for cell in row.strip("|").split("|")[1:4]:
            m = re.match(r"\s*(\d+)", cell)
            if m:
                assert int(m.group(1)) in values, row
    assert "reserved: not emitted until ACCEPTED ships" in exitcodes.markdown_table()


# --------------------------------------------------------------------------- #
# allclear.emit (v4 section 13, errata R4-M2, R4-L5)
# --------------------------------------------------------------------------- #
def test_rulehawk_cert_is_a_compiled_in_zero():
    assert allclear.RULEHAWK_CERT == 0
    tree = ast.parse(_read(os.path.join("rulehawk", "allclear.py")))
    sets = [n for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "RULEHAWK_CERT" for t in n.targets)]
    assert len(sets) == 1
    v = sets[0].value
    assert isinstance(v, ast.Constant) and v.value == 0 and type(v.value) is int


@pytest.mark.parametrize("verdict,stopgap", [
    ("PASS", "UNKNOWN"), ("NO_NEW_RISK", "UNKNOWN"), ("VERIFIED", "INDETERMINATE"),
    ("segmentation-ok", "segmentation-unknown"),
    ("connectivity-ok", "connectivity-unknown"), ("complete", "partial")])
def test_emit_gives_the_stopgap_answer(verdict, stopgap):
    assert allclear.emit(verdict) == stopgap
    # A certificate does not help while RULEHAWK_CERT is 0.
    assert allclear.emit(verdict, cert=object()) == stopgap


def test_emit_refuses_a_non_all_clear_verdict():
    with pytest.raises(ValueError):
        allclear.emit("FAIL")


def test_passed_and_exit_code_are_the_stopgaps():
    assert allclear.passed() is False and allclear.passed(object()) is False
    assert allclear.exit_code() == exitcodes.UNKNOWN
    assert allclear.certified(object()) is False


# --------------------------------------------------------------------------- #
# The AST all-clear scan over rulehawk/*.py (errata R4-M2, R4-L1)
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\bPASS\b|\bVERIFIED\b|NO_NEW_RISK|✅")
_EXACT = {"complete", "segmentation-ok", "connectivity-ok", "certified"}
_ALLCLEAR_NAMES = {"PASS", "VERIFIED", "NO_NEW_RISK", "SEG_OK", "REACH_OK", "COMPLETE"}


def _docstrings(tree):
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _parents(tree):
    par = {}
    for node in ast.walk(tree):
        for ch in ast.iter_child_nodes(node):
            par[ch] = node
    return par


def _qualname(node, par):
    names = []
    while node in par:
        node = par[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
    return ".".join(reversed(names)) or "<module>"


def _is_code(v, code):
    return isinstance(v, ast.Constant) and type(v.value) is int and v.value == code


def _scan_module(name: str):
    """(qualname, rule, text) for every all-clear literal in one module."""
    src = open(os.path.join(_PKG, name), encoding="utf-8").read()
    tree = ast.parse(src)
    doc, par = _docstrings(tree), _parents(tree)
    out = []

    def hit(node, rule, text):
        out.append(f"{name}::{_qualname(node, par)}::{rule}::{text}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in doc:
            v = node.value
            if _TOKEN.search(v) or v in _EXACT:
                hit(node, "literal", v[:72])
            if v == "RULEHAWK_CERT":
                hit(node, "cert-env", v)                  # never read from env
            if v == "RULEHAWK_SHADOW" and name == "mcp_server.py":
                hit(node, "shadow-env", v)                # R4-L1
        elif isinstance(node, ast.Return) and node.value is not None:
            vals = ([node.value.body, node.value.orelse]
                    if isinstance(node.value, ast.IfExp) else [node.value])
            if any(_is_code(v, 0) for v in vals):
                hit(node, "return-0", ast.unparse(node.value))
            if any(_is_code(v, 4) for v in vals):
                hit(node, "return-4", ast.unparse(node.value))
        elif isinstance(node, ast.keyword) and node.arg == "passed" \
                and isinstance(node.value, ast.Constant) and node.value.value is True:
            hit(node, "passed-true", "passed=True")
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "passed" \
                        and isinstance(v, ast.Constant) and v.value is True:
                    hit(node, "passed-true", '"passed": True')
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "exitcodes" and node.attr in ("PASS", "ACCEPTED"):
                hit(node, "exit-code", f"exitcodes.{node.attr}")
            if node.value.id == "allclear" and node.attr in _ALLCLEAR_NAMES:
                p = par.get(node)
                first_arg_of_emit = (
                    isinstance(p, ast.Call) and p.args and p.args[0] is node
                    and isinstance(p.func, ast.Attribute) and p.func.attr == "emit"
                    and isinstance(p.func.value, ast.Name) and p.func.value.id == "allclear")
                if not first_arg_of_emit:
                    hit(node, "allclear-name", f"allclear.{node.attr}")
            if node.attr == "RULEHAWK_CERT":
                hit(node, "cert-override", ast.unparse(node))
        elif isinstance(node, ast.ImportFrom) and node.module in ("exitcodes", "allclear"):
            for a in node.names:
                if a.name in ("PASS", "ACCEPTED", "RULEHAWK_CERT") | _ALLCLEAR_NAMES:
                    hit(node, "import-name", f"{node.module}.{a.name}")
        elif isinstance(node, ast.Global) and "RULEHAWK_CERT" in node.names:
            hit(node, "cert-override", "global RULEHAWK_CERT")
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "RULEHAWK_CERT" and name != "allclear.py":
                    hit(node, "cert-override", t.id)
                if isinstance(t, ast.Subscript) and "RULEHAWK_SHADOW" in ast.unparse(t):
                    hit(node, "shadow-set", ast.unparse(t))
        if isinstance(node, ast.Call):
            f = ast.unparse(node.func)
            args = " ".join(ast.unparse(a) for a in node.args)
            if f.endswith(("putenv", "setdefault", "setattr")) and (
                    "RULEHAWK_SHADOW" in args or "RULEHAWK_CERT" in args):
                hit(node, "env-set", f"{f}({args})")
    return out


def _scan():
    found = collections.Counter()
    for n in sorted(os.listdir(_PKG)):
        if n.endswith(".py") and n != "allclear.py":
            found.update(_scan_module(n))
    return found


# Pinned: every all-clear literal outside allclear.py, with the reason it is
# not an all-clear. Keys are module::function::rule::text (strings cut at 72).
_EXEMPT = collections.Counter({
    # Help and the exit-code table: they name PASS only to say it is not
    # emitted.
    "exitcodes.py::<module>::literal::PASS (certified). Not emitted by this release (fail-closed stopgap)": 1,
    "exitcodes.py::<module>::literal::only for --help; an audited run never exits 0 (PASS is not\n     emitted ": 1,
    "exitcodes.py::<module>::literal::only with --fail-on none (advisory; the verdict still says\n     UNKNOWN/": 1,
    "exitcodes.py::help_section::literal:: (0.4.1, fail-closed stopgap: PASS is never reported):": 1,
    "exitcodes.py::markdown_table::literal::. The Actions never report an exit code as a PASS, and `comment/action.y": 1,
    # Negated messages: they name PASS only to deny it (test_stopgap NEGATIONS).
    "gate.py::<module>::literal::The segmentation policy itself is invalid (unknown zone, bad CIDR or por": 1,
    "segcheck.py::check_segmentation::literal::SEGMENTATION POLICY ERROR: 'zones' must be an object of name -> [CIDR, .": 1,
    "segcheck.py::check_segmentation::literal::' — fail-closed: assertions over this zone get no PASS until the policy ": 1,
    "mcp_server.py::_verdict::literal::fail_on=none: nothing blocks, so no PASS is given; read findings_by_seve": 1,
    "mcp_server.py::supported_inputs::literal::fail-closed: unrecognised or unreadable input makes the result INCOMPLET": 1,
    "mcp_server.py::_coverage::literal::at least one input was NOT analysed (see not_analysed); no PASS is given": 1,
    # combine reads records and never builds a PASS check. "PASS" is only
    # enforced_verdict's default when no check is enforced (the advisory exit
    # 0, via _EXIT), the renderer's names for it, and the legacy-record reader
    # that turns an older gate's PASS into UNKNOWN.
    "combine.py::<module>::literal::PASS": 3,
    "combine.py::<module>::literal::✅": 1,
    "combine.py::_report_verdict::literal::## ✅ ": 1,
    "combine.py::_report_verdict::literal::**PASS**": 1,
    "combine.py::_report_verdict::literal::PASS": 1,
    "combine.py::Check.shown::literal::PASS": 1,
    "combine.py::_section::literal::PASS": 1,
    "combine.py::_render_many::literal::PASS": 3,
    "combine.py::_headline::literal::PASS": 1,
    "combine.py::enforced_verdict::literal::PASS": 1,
    # evidence: the claim-status vocabulary, its finding-kind tables and its
    # renderers. A VERIFIED claim exists only if allclear.emit lets one
    # through (_fleet_status asks it).
    "evidence.py::<module>::literal::VERIFIED": 1,
    "evidence.py::<module>::literal::segmentation-ok": 2,
    "evidence.py::<module>::literal::connectivity-ok": 2,
    "evidence.py::<module>::literal::PASS": 1,
    "evidence.py::build_evidence::literal::complete": 1,
    "evidence.py::to_evidence_markdown::literal::complete": 1,
    "evidence.py::to_evidence_markdown::literal::**PASS — ": 1,
    # mcp: the segmentation_passed filter, which no stopgap finding kind
    # matches. (coverage.state goes through allclear.emit since slice 2.)
    "mcp_server.py::audit::literal::segmentation-ok": 1,
    "mcp_server.py::audit::literal::connectivity-ok": 1,
    # The MCP server process's own exit status, not a verdict.
    "mcp_server.py::main::return-0::0": 3,
})


def test_no_all_clear_literal_outside_allclear():
    found = _scan()
    extra, gone = found - _EXEMPT, _EXEMPT - found
    assert not extra, ("all-clear literal outside rulehawk/allclear.py; route it "
                       "through allclear.emit or add a reviewed exemption: "
                       f"{sorted(extra.elements())}")
    assert not gone, f"exemption no longer matches; remove it: {sorted(gone.elements())}"


def test_scan_catches_a_planted_all_clear(tmp_path, monkeypatch):
    """The scan is not vacuous: each rule fires on a planted line."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from . import allclear, exitcodes\n"
        "def v():\n"
        "    x = 'PASS'\n"
        "    y = allclear.PASS\n"
        "    z = {'passed': True, 'shadow': {'certified': 1}}\n"
        "    f(passed=True)\n"
        "    allclear.RULEHAWK_CERT = 1\n"
        "    return exitcodes.PASS\n"
        "def w():\n"
        "    return 0\n"
        "def a():\n"
        "    return 4\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "_PKG", str(tmp_path))
    rules = {k.split("::")[2] for k in _scan_module("planted.py")}
    assert rules >= {"literal", "allclear-name", "passed-true", "cert-override",
                     "exit-code", "return-0", "return-4"}, rules


# --------------------------------------------------------------------------- #
# The literal scan over the non-Python surfaces (errata R4-M3, R4-L1). #44's
# guard lines are pinned exactly, so they stay byte-for-byte until slice 9.
# --------------------------------------------------------------------------- #
_LIT = re.compile(r"\bPASS\b|\bVERIFIED\b|NO_NEW_RISK|✅|passed=true|\"passed\":\s*true"
                  r"|allPass|[Nn]o issues found|all[- ]clear|all_clear")


def _analyze_py():
    js = _read(os.path.join("docs", "worker.js"))
    m = re.search(r"const ANALYZE_PY = `(.*?)`;", js, re.S)
    assert m, "ANALYZE_PY not found in docs/worker.js"
    return m.group(1)


_SURFACES = {
    "action.yml": lambda: _read("action.yml"),
    "comment/action.yml": lambda: _read(os.path.join("comment", "action.yml")),
    "docs/index.html": lambda: _read(os.path.join("docs", "index.html")),
    "docs/worker.js:ANALYZE_PY": _analyze_py,
}


def _literal_scan():
    found = collections.Counter()
    for label, get in _SURFACES.items():
        for line in get().splitlines():
            if _LIT.search(line):
                found[f"{label}::{line.strip()}"] += 1
    return found


_LIT_EXEMPT = collections.Counter({
    # action.yml: docs and guards that say PASS is never reported.
    "action.yml::| none. Fail-closed stopgap (0.4.1): the gate never reports PASS. It": 1,
    "action.yml::Never true in 0.4.1 (fail-closed stopgap: no PASS is reported, under": 1,
    "action.yml::# leaving an earlier check's PASS standing. One record per gate step, kept": 1,
    "action.yml::echo \"::error title=RuleHawk gate UNKNOWN (fail-closed-stopgap)::RuleHawk exited 3: no finding reached '${RH_FAIL_ON}', but this release reports no PASS — fail-closed stopgap pending soundness review (reason fail-closed-stopgap). Exit 3 fails the check until PASS returns where proven; for a non-blocking run, set fail-on: none.\"": 1,
    # comment/action.yml: #44's guards (never PASS; ENFORCED=PASS only means
    # no enforced check exists).
    "comment/action.yml::# stopgap (0.4.1): never PASS; a check that does not fail is UNKNOWN, and a": 1,
    "comment/action.yml::Fewer results make the verdict UNKNOWN, never PASS.": 1,
    "comment/action.yml::re-run whose result never uploaded, leaving the first attempt's PASS),": 1,
    "comment/action.yml::\" (not enforced)\" when only fail-on none checks have it. Never PASS in": 1,
    "comment/action.yml::# ENFORCED is the verdict over the enforced checks: \"PASS\" here only": 1,
    "comment/action.yml::0) ENFORCED=PASS ;;": 1,
    "comment/action.yml::# Fail-closed stopgap: 0.4.1 never reports PASS. A missing or empty": 1,
    "comment/action.yml::# verdict file, or one that says PASS, is not trusted.": 1,
    "comment/action.yml::\"\"|PASS*) VERDICT=UNKNOWN; ENFORCED=UNKNOWN ;;": 1,
    "comment/action.yml::# Belt and braces: a body that reads PASS is replaced, never posted": 1,
    "comment/action.yml::# (the verdict is never PASS in 0.4.1).": 1,
    "comment/action.yml::if [ -s \"${BODY}\" ] && grep -q '^## ✅' \"${BODY}\"; then": 1,
    "comment/action.yml::if [ \"${RH_ENFORCED:-UNKNOWN}\" != \"PASS\" ]; then": 1,
    "comment/action.yml::\"\"|PASS*)": 1,
    "comment/action.yml::# 0.4.1 never reports PASS (fail-closed stopgap): fail closed.": 1,
    "comment/action.yml::echo \"::error title=RuleHawk combined verdict (fail-closed-stopgap)::Unexpected combined verdict '${RH_VERDICT:-}': this release never reports PASS (fail-closed stopgap pending soundness review); failing closed.\"": 1,
    # docs/index.html: CSS and comments, not banners. The banners render from
    # report_json and are swept by tests/test_stopgap.py.
    "docs/index.html::/* all-clear: no issues found */": 1,
    "docs/index.html::.all-clear{display:flex;gap:10px;align-items:center;": 1,
    "docs/index.html::// Fail-closed stopgap: nothing flagged is UNKNOWN, never an all-clear.": 1,
})


def test_no_all_clear_literal_on_the_non_python_surfaces():
    found = _literal_scan()
    extra, gone = found - _LIT_EXEMPT, _LIT_EXEMPT - found
    assert not extra, f"new all-clear literal: {sorted(extra.elements())}"
    assert not gone, f"pinned guard line changed or removed: {sorted(gone.elements())}"


@pytest.mark.parametrize("rel", ["action.yml", os.path.join("comment", "action.yml"),
                                 os.path.join("docs", "worker.js"),
                                 os.path.join("docs", "index.html")])
def test_no_surface_sets_shadow_or_cert(rel):
    """R4-L1: the Action, the comment Action and the hosted page never set
    RULEHAWK_SHADOW, and nothing outside allclear.py names RULEHAWK_CERT."""
    text = _read(rel)
    assert "RULEHAWK_SHADOW" not in text and "RULEHAWK_CERT" not in text


def test_literal_scan_catches_a_planted_all_clear(monkeypatch):
    """The non-Python scan is not vacuous: each pattern fires on a planted line."""
    planted = ["## ✅ RuleHawk", "verdict: PASS", "VERIFIED", "NO_NEW_RISK",
               "passed=true", '{"passed": true}', "allPass", "No issues found",
               "all-clear", "all clear", "all_clear"]
    monkeypatch.setattr(sys.modules[__name__], "_SURFACES",
                        {"planted": lambda: "\n".join(planted)})
    found = _literal_scan()
    assert set(found) == {f"planted::{p}" for p in planted}, found
