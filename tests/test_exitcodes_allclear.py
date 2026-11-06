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
    # Each row's meaning matches its code, in --help and in both docs
    # (review of #47, F5): a row that says UNKNOWN must carry UNKNOWN's code.
    assert _help_row_problems(command, out) == []
    for doc in ("README.md", os.path.join("docs", "github-action.md")):
        text = _read(doc)
        block = text[text.index(exitcodes.MARK_BEGIN):text.index(exitcodes.MARK_END)]
        assert _table_row_problems("\n".join(block.splitlines()[1:])) == [], doc


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


_ZERO_CODES = {"PASS", "ADVISORY", "HELP"}          # exitcodes names whose value is 0
_EXIT_NAMES = _ZERO_CODES | {"ACCEPTED"}
_EXIT_CALLS = {"sys.exit", "exit", "quit", "SystemExit", "os._exit", "_exit"}
_ENV_WRITES = {"update", "setdefault", "__setitem__", "pop", "putenv", "clear"}


def _module_aliases(tree, module: str) -> set:
    """Local names bound to rulehawk.<module> (`from . import x as y`)."""
    names = {module}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None:
            names |= {a.asname or a.name for a in node.names if a.name == module}
        elif isinstance(node, ast.Import):
            names |= {a.asname for a in node.names
                      if a.name == f"rulehawk.{module}" and a.asname}
    return names


def _scan_module(name: str):
    """(qualname, rule, text) for every all-clear literal or emission in one
    module. It reads spellings and emissions, not data flow: an all-clear
    built at run time ("PA" + "SS", "pass".upper(), an f-string) or an exit
    code held in a variable is out of its reach. #44's behavioural tests
    (tests/test_stopgap.py and the attack file) catch those on every fixture
    they run."""
    src = open(os.path.join(_PKG, name), encoding="utf-8").read()
    tree = ast.parse(src)
    doc, par = _docstrings(tree), _parents(tree)
    ec, ac = _module_aliases(tree, "exitcodes"), _module_aliases(tree, "allclear")
    out = []

    def hit(node, rule, text):
        out.append(f"{name}::{_qualname(node, par)}::{rule}::{text}")

    def zero(v):
        return (v is None or _is_code(v, 0)
                or (isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name)
                    and v.value.id in ec and v.attr in _ZERO_CODES))

    def on_allclear(t):
        while isinstance(t, (ast.Attribute, ast.Subscript)):
            t = t.value
            if isinstance(t, ast.Name) and t.id in ac:
                return True
        return False

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
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Name) \
                and node.exc.id == "SystemExit":
            hit(node, "exit-call-0", "raise SystemExit")  # a bare SystemExit exits 0
        elif isinstance(node, ast.keyword) and node.arg == "passed" \
                and isinstance(node.value, ast.Constant) and node.value.value is True:
            hit(node, "passed-true", "passed=True")
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "passed" \
                        and isinstance(v, ast.Constant) and v.value is True:
                    hit(node, "passed-true", '"passed": True')
        elif isinstance(node, ast.Name) and node.id in ("PASS", "VERIFIED", "NO_NEW_RISK"):
            hit(node, "allclear-const", node.id)          # F4: a module constant
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in ec and node.attr in _EXIT_NAMES:
                hit(node, "exit-code", f"exitcodes.{node.attr}")
            if node.value.id in ac and node.attr == "certified":
                hit(node, "allclear-name", "allclear.certified")   # review of #48, L2
            if node.value.id in ac and node.attr in _ALLCLEAR_NAMES:
                p = par.get(node)
                first_arg_of_emit = (
                    isinstance(p, ast.Call) and p.args and p.args[0] is node
                    and isinstance(p.func, ast.Attribute) and p.func.attr == "emit"
                    and isinstance(p.func.value, ast.Name) and p.func.value.id in ac)
                if not first_arg_of_emit:
                    hit(node, "allclear-name", f"allclear.{node.attr}")
            if node.attr == "RULEHAWK_CERT":
                hit(node, "cert-override", ast.unparse(node))
        elif isinstance(node, ast.ImportFrom) and node.module in ("exitcodes", "allclear"):
            for a in node.names:
                if a.name in (_EXIT_NAMES | {"RULEHAWK_CERT", "certified"}) | _ALLCLEAR_NAMES:
                    hit(node, "import-name", f"{node.module}.{a.name}")
        elif isinstance(node, ast.Global) and "RULEHAWK_CERT" in node.names:
            hit(node, "cert-override", "global RULEHAWK_CERT")
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
            targets = (node.targets if isinstance(node, (ast.Assign, ast.Delete))
                       else [node.target])
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "RULEHAWK_CERT" and name != "allclear.py":
                    hit(node, "cert-override", t.id)
                if isinstance(t, ast.Subscript) and "RULEHAWK_SHADOW" in ast.unparse(t):
                    hit(node, "shadow-set", ast.unparse(t))
                if isinstance(t, (ast.Subscript, ast.Attribute)) and "environ" in ast.unparse(t) \
                        and "RULEHAWK_" in ast.unparse(node):
                    hit(node, "env-set", ast.unparse(t))
                if on_allclear(t):
                    hit(node, "allclear-write", ast.unparse(t))
        if isinstance(node, ast.Call):
            f = ast.unparse(node.func)
            args = " ".join(ast.unparse(a) for a in node.args)
            if f.endswith(("putenv", "setdefault", "setattr")) and (
                    "RULEHAWK_SHADOW" in args or "RULEHAWK_CERT" in args):
                hit(node, "env-set", f"{f}({args})")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in _ENV_WRITES \
                    and "environ" in ast.unparse(node.func.value) \
                    and "RULEHAWK_" in ast.unparse(node):
                hit(node, "env-set", f)                   # F4: any environ write
            if f in _EXIT_CALLS and zero(node.args[0] if node.args else None):
                hit(node, "exit-call-0", ast.unparse(node))
            if f in ("setattr", "delattr", "vars") and node.args \
                    and isinstance(node.args[0], ast.Name) and node.args[0].id in ac:
                hit(node, "allclear-write", ast.unparse(node))
        _passed_sets(node, ac, hit)
    return out


def _is_passed_call(v, ac) -> bool:
    return (isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute)
            and v.func.attr == "passed" and isinstance(v.func.value, ast.Name)
            and v.func.value.id in ac)


def _names_passed(t) -> bool:
    return ((isinstance(t, ast.Name) and t.id == "passed")
            or (isinstance(t, ast.Attribute) and t.attr == "passed")
            or (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                and t.slice.value == "passed"))


def _flat(t):
    if isinstance(t, (ast.Tuple, ast.List)):
        for e in t.elts:
            yield from _flat(e)
    elif isinstance(t, ast.Starred):
        yield from _flat(t.value)
    else:
        yield t


def _passed_sets(node, ac, hit):
    """Review of #47 (optional rule): a `passed` name, attribute, keyword or
    dict key set to anything but an allclear.passed() call. Spelling only, like
    the rest of the scan: `passed` read back from something set elsewhere is a
    hit at the site that sets it."""
    def h(n, text):
        hit(n, "passed-set", text[:72])

    if isinstance(node, ast.keyword) and node.arg == "passed" \
            and not _is_passed_call(node.value, ac):
        h(node, f"passed={ast.unparse(node.value)}")
    elif isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "passed" \
                    and not _is_passed_call(v, ac):
                h(node, f'"passed": {ast.unparse(v)}')
    elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
        if node.value is None:                      # `passed: bool`, no value
            return
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        aug = isinstance(node, ast.AugAssign)
        for t in targets:
            if _names_passed(t):
                if aug or not _is_passed_call(node.value, ac):
                    h(node, f"{ast.unparse(t)} = {ast.unparse(node.value)}")
            else:
                for e in _flat(t):
                    if _names_passed(e):            # unpacked: never a passed() call
                        h(node, ast.unparse(e))
    elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension, ast.withitem)):
        t = node.optional_vars if isinstance(node, ast.withitem) else node.target
        for e in _flat(t) if t is not None else ():
            if _names_passed(e):
                h(e if isinstance(node, ast.comprehension) else node, ast.unparse(e))
    elif isinstance(node, ast.Call):
        f = ast.unparse(node.func)
        if f in ("setattr", "dict.__setitem__") or f.endswith((".setdefault", ".__setitem__")):
            key = node.args[1] if f == "setattr" and len(node.args) > 1 else (
                node.args[0] if node.args and f != "setattr" else None)
            val = node.args[2 if f == "setattr" else 1] if len(node.args) > (
                2 if f == "setattr" else 1) else None
            if isinstance(key, ast.Constant) and key.value == "passed" \
                    and not _is_passed_call(val, ac):
                h(node, ast.unparse(node))
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "passed":
        for r in ast.walk(node):
            if isinstance(r, ast.Return) and not _is_passed_call(r.value, ac):
                h(r, f"def passed: return {ast.unparse(r.value) if r.value else 'None'}")


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
    # Emissions (review of #47, F4). The zero exit codes at their sites: the
    # --help returns, the advisory `gate --fail-on none` return, and
    # combine's advisory code for a run with no enforced check (departure 1).
    "cli.py::main::exit-code::exitcodes.HELP": 1,
    "gate.py::main::exit-code::exitcodes.HELP": 1,
    "combine.py::main::exit-code::exitcodes.HELP": 1,
    "gate.py::GateResult.exit_code::exit-code::exitcodes.ADVISORY": 1,
    "combine.py::<module>::exit-code::exitcodes.ADVISORY": 1,
    # exitcodes.py's own PASS exit-code constant: its definition, the PASS
    # row's three cells and the precedence line of the doc table. Text only;
    # nothing returns it.
    "exitcodes.py::<module>::allclear-const::PASS": 4,
    "exitcodes.py::markdown_table::allclear-const::PASS": 1,
    # evidence.py's VERIFIED status constant: its definition and
    # _STATUS_MARK key; comparisons that read a status; and the control
    # roll-up, which copies VERIFIED only from an attestation that already
    # holds it, which only allclear.emit can give.
    "evidence.py::<module>::allclear-const::VERIFIED": 2,
    "evidence.py::build_attestations::allclear-const::VERIFIED": 2,
    "evidence.py::_control_rollup::allclear-const::VERIFIED": 2,
    "evidence.py::build_evidence::allclear-const::VERIFIED": 1,
    # allclear.certified(): the two sites that ask whether a file is
    # certified (review of #48, L2). to_sarif skips a file's
    # rulehawk/uncertified note only if it is; _coverage counts the files that
    # are not. Both pass no certificate, so neither is ever true in 0.4.1.
    "gate.py::to_sarif::allclear-name::allclear.certified": 1,
    "mcp_server.py::_coverage::allclear-name::allclear.certified": 1,
    # `passed` set to something other than an allclear.passed() call (review
    # of #47, optional rule). The gate's JSON and result records copy
    # GateResult.passed, a property that returns allclear.passed(); the
    # failed-run record is a constant False; combine reads `passed` from a
    # record and turns a true one into UNKNOWN (_load, "pre-stopgap record").
    "gate.py::to_json::passed-set::\"passed\": gate.passed": 1,
    "gate.py::to_result::passed-set::\"passed\": gate.passed": 1,
    "gate.py::_failed_result::passed-set::\"passed\": False": 1,
    "combine.py::_load::passed-set::passed": 1,
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
        "    if allclear.certified(x):\n"
        "        pass\n"
        "    ok = allclear.certified\n"
        "    return exitcodes.PASS\n"
        "def w():\n"
        "    return 0\n"
        "def a():\n"
        "    return 4\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "_PKG", str(tmp_path))
    hits = _scan_module("planted.py")
    rules = {k.split("::")[2] for k in hits}
    assert rules >= {"literal", "allclear-name", "passed-true", "cert-override",
                     "exit-code", "return-0", "return-4"}, rules
    # Review of #48, L2: a certified() call, and certified held as a value.
    assert hits.count("planted.py::v::allclear-name::allclear.certified") == 2, hits


def test_scan_catches_a_planted_passed(tmp_path, monkeypatch):
    """Review of #47 (optional rule): `passed` set to anything but an
    allclear.passed() call is a hit, as attribute, name, keyword or dict key."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from . import allclear\n"
        "class G:\n"
        "    passed = not self.violations\n"
        "    def passed(self):\n"
        "        return not self.violations\n"
        "    def a(self):\n"
        "        self.passed = not self.violations\n"
        "        R(passed=not self.violations)\n"
        "        d = {'passed': len(self.violations) == 0}\n"
        "        d['passed'] = ok\n"
        "        setattr(d, 'passed', ok)\n"
        "        passed, code = rec\n"
        "        for passed in xs:\n"
        "            pass\n"
        "    def ok(self):\n"
        "        passed = allclear.passed()\n"
        "        self.passed = allclear.passed()\n"
        "        R(passed=allclear.passed())\n"
        "        return {'passed': allclear.passed()}\n"
        "class H:\n"
        "    @property\n"
        "    def passed(self):\n"
        "        return allclear.passed()\n",
        encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "_PKG", str(tmp_path))
    hits = [k for k in _scan_module("planted.py") if k.split("::")[2] == "passed-set"]
    where = collections.Counter(k.split("::")[1] for k in hits)
    # Nothing in G.ok or H.passed: those are allclear.passed() calls.
    assert where == {"G": 1, "G.passed": 1, "G.a": 7}, hits
    assert "planted.py::G::passed-set::passed = not self.violations" in hits, hits


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


# --------------------------------------------------------------------------- #
# Review of #47: F1, F2, F4 and F5 (red first).
# --------------------------------------------------------------------------- #
_ALLCLEAR_PLANTS = {
    "env-in-certified": (
        "    return RULEHAWK_CERT == 1 and cert is not None and _require_certified(cert)",
        "    import os\n    if os.environ.get('RH_FORCE') == '1':\n        return True\n"
        "    return RULEHAWK_CERT == 1 and cert is not None and _require_certified(cert)"),
    "env-globals": ("RULEHAWK_CERT = 0\n",
                    "RULEHAWK_CERT = 0\nimport os as _os\n"
                    "globals()['RULEHAWK_CERT'] = int(_os.environ.get('RH_C', '0'))\n"),
    "getenv": ("RULEHAWK_CERT = 0\n",
               "RULEHAWK_CERT = 0\nfrom os import getenv\n_X = getenv('RH_C')\n"),
    "argv": ("RULEHAWK_CERT = 0\n", "RULEHAWK_CERT = 0\nimport sys\n_X = sys.argv\n"),
    "file-read": ("RULEHAWK_CERT = 0\n", "RULEHAWK_CERT = 0\n_X = open('cert').read()\n"),
    "importlib": ("RULEHAWK_CERT = 0\n",
                  "RULEHAWK_CERT = 0\n_X = __import__('os').environ\n"),
    "setattr": ("RULEHAWK_CERT = 0\n",
                "RULEHAWK_CERT = 0\nsetattr(__import__(__name__), 'x', 1)\n"),
}


def test_allclear_module_is_closed():
    """F1: allclear.py imports only __future__, typing and .exitcodes, and
    names no environment, argv, file, import or reflection hook."""
    assert _allclear_violations(_read(os.path.join("rulehawk", "allclear.py"))) == []


@pytest.mark.parametrize("plant", sorted(_ALLCLEAR_PLANTS))
def test_allclear_closure_catches_a_planted_override(plant):
    old, new = _ALLCLEAR_PLANTS[plant]
    src = _read(os.path.join("rulehawk", "allclear.py"))
    assert src.count(old) == 1
    assert _allclear_violations(src.replace(old, new)), plant


def test_allclear_gate_functions_are_pinned():
    """F1: the bodies of the gate functions are pinned by AST hash, so any
    change to them is a reviewed edit of this test."""
    assert _allclear_fn_hashes(_read(os.path.join("rulehawk", "allclear.py"))) == _ALLCLEAR_FN_SHA


def test_allclear_pin_catches_an_edit():
    old, new = _ALLCLEAR_PLANTS["env-in-certified"]
    src = _read(os.path.join("rulehawk", "allclear.py")).replace(old, new)
    assert _allclear_fn_hashes(src) != _ALLCLEAR_FN_SHA


def test_scan_catches_a_planted_emission(tmp_path, monkeypatch):
    """F4: the scan sees emissions as well as spellings."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "import os, sys\n"
        "from . import exitcodes as ec, allclear as ac\n"
        "def a():\n    sys.exit(0)\n"
        "def b():\n    raise SystemExit(ec.ADVISORY)\n"
        "def c():\n    os._exit(0)\n"
        "def d():\n    return ec.HELP\n"
        "def e():\n    return VERIFIED\n"
        "def f():\n    os.environ.update(RULEHAWK_SHADOW='1')\n"
        "def g():\n    os.environ.setdefault('RULEHAWK_CERT', '1')\n"
        "def h():\n    ac.emit = lambda v, cert=None: v\n"
        "def i():\n    ac._STOPGAP['PASS'] = 'PASS'\n"
        "def j():\n    raise SystemExit\n",
        encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "_PKG", str(tmp_path))
    hits = _scan_module("planted.py")
    rules = collections.Counter(k.split("::")[2] for k in hits)
    assert rules["exit-call-0"] == 4, hits
    assert rules["exit-code"] >= 2, hits          # ec.ADVISORY, ec.HELP through an alias
    assert rules["allclear-const"] == 1, hits
    assert rules["env-set"] == 2, hits
    assert rules["allclear-write"] == 2, hits


@pytest.mark.parametrize("command,argv", [("file", ["--help"]),
                                          ("gate", ["gate", "--help"]),
                                          ("combine", ["combine", "--help"])])
def test_help_rows_say_what_their_code_means(command, argv):
    """F5: each --help row's meaning matches its code."""
    from rulehawk import cli
    _, out = _help(cli.main, argv)
    assert _help_row_problems(command, out) == []


def test_help_row_check_catches_a_swap():
    text = exitcodes.help_section("file").replace("  1  FAIL:", "  1  UNKNOWN:")
    assert _help_row_problems("file", text)


def test_doc_table_rows_say_what_their_code_means():
    assert _table_row_problems(exitcodes.markdown_table()) == []
    swapped = exitcodes.markdown_table().replace("| FAIL | 1 |", "| UNKNOWN | 1 |")
    assert swapped != exitcodes.markdown_table()
    assert _table_row_problems(swapped)


def test_guard_blocks_are_byte_for_byte_from_e04630e():
    """F2: #44's guard blocks in the Actions, the hosted page and its glue,
    as they were at e04630e."""
    assert _guard_block_problems(_read) == []


def test_guard_pin_catches_a_deleted_guard():
    guard = ('        if [ "${RH_FAIL_ON}" != "none" ]; then\n'
             '          echo "::error title=RuleHawk gate (fail-closed-stopgap)::RuleHawk exited 0 under fail-on \'${RH_FAIL_ON}\', which this release never does; failing closed (fail-closed stopgap pending soundness review)."\n'
             '          exit 1\n        fi\n')
    real = _read("action.yml")
    assert real.count(guard) == 1

    def read(rel):
        return real.replace(guard, "") if rel == "action.yml" else _read(rel)
    assert _guard_block_problems(read)


def _step_run(rel: str, step: str) -> str:
    """The `run: |` script of the named step, dedented."""
    lines = _read(rel).splitlines()
    i = next(n for n, l in enumerate(lines) if l.strip() == f"- name: {step}")
    j = next(n for n in range(i + 1, len(lines)) if lines[n].strip() == "run: |")
    body = []
    for l in lines[j + 1:]:
        if l.strip() and not l.startswith(" " * 8):
            break
        body.append(l[8:])
    return "\n".join(body) + "\n"


def _bash(script: str, env: dict):
    import shutil
    import subprocess
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    e = {"PATH": os.environ.get("PATH", "")}
    e.update(env)
    r = subprocess.run(["bash", "-c", script], env=e, capture_output=True, text=True)
    return r.returncode, r.stdout


@pytest.mark.parametrize("rc,fail_on,want", [
    (None, "high", 1), ("", "high", 1), ("1", "high", 1), ("2", "high", 1),
    ("3", "high", 1), ("5", "high", 1),
    ("0", "critical", 1), ("0", "high", 1), ("0", "medium", 1), ("0", "low", 1),
    ("0", "none", 0),
])
def test_action_enforce_step_fails_closed(rc, fail_on, want):
    """F2: action.yml's Enforce step under bash: every code but an advisory
    exit 0 fails the step, and an enforced exit 0 fails closed."""
    env = {"RH_FAIL_ON": fail_on, "RH_WORST": "none", "RH_VERDICT": "UNKNOWN"}
    if rc is not None:
        env["RH_RC"] = rc
    code, out = _bash(_step_run("action.yml", "Enforce gate verdict"), env)
    assert code == want, (rc, fail_on, out)
    if want == 0:
        assert "::warning" in out and "not enforced" in out


@pytest.mark.parametrize("enforced,verdict,want", [
    (None, "FAIL", 1), ("UNKNOWN", "UNKNOWN", 1), ("FAIL", "FAIL", 1),
    ("PASS", None, 1), ("PASS", "", 1), ("PASS", "PASS", 1),
    ("PASS", "PASS (not enforced)", 1),
    ("PASS", "FAIL (not enforced)", 0), ("PASS", "UNKNOWN (not enforced)", 0),
])
def test_comment_enforce_step_fails_closed(enforced, verdict, want):
    """F2: comment/action.yml's Enforce step under bash."""
    env = {}
    if enforced is not None:
        env["RH_ENFORCED"] = enforced
    if verdict is not None:
        env["RH_VERDICT"] = verdict
    code, out = _bash(_step_run(os.path.join("comment", "action.yml"),
                                "Enforce the combined verdict"), env)
    assert code == want, (enforced, verdict, out)


# --------------------------------------------------------------------------- #
# Helpers for the review-of-#47 tests above.
# --------------------------------------------------------------------------- #
# F1. allclear.py may import only these, and may name none of the hooks below.
_ALLCLEAR_IMPORTS = {("__future__", 0, "annotations"), ("typing", 0, "Optional"),
                     (None, 1, "exitcodes")}
_ALLCLEAR_FORBIDDEN = {
    "os", "sys", "environ", "getenv", "putenv", "argv", "open", "io", "pathlib",
    "importlib", "__import__", "globals", "locals", "vars", "setattr", "getattr",
    "delattr", "eval", "exec", "compile", "__dict__", "__builtins__", "builtins",
    "input", "subprocess", "reload"}


def _allclear_violations(src: str) -> list:
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            out += [f"import {a.name}" for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            out += [f"from {'.' * node.level}{node.module or ''} import {a.name}"
                    for a in node.names
                    if (node.module, node.level, a.name) not in _ALLCLEAR_IMPORTS]
        elif isinstance(node, ast.Name) and node.id in _ALLCLEAR_FORBIDDEN:
            out.append(f"name {node.id}")
        elif isinstance(node, ast.Attribute) and node.attr in _ALLCLEAR_FORBIDDEN:
            out.append(f"attribute {node.attr}")
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            out.append(f"global {','.join(node.names)}")
    return out


# The gate functions and the stopgap table, pinned by the sha256 of their
# exact source lines (docstrings dropped). Exact text, not ast.dump, so the
# pin is the same on every Python version CI runs. Slice 7 (the checker) and
# slice 9 (the flip) edit these on purpose, with this table.
_ALLCLEAR_PINNED = ("_STOPGAP", "_require_certified", "certified", "emit", "passed", "exit_code")
_ALLCLEAR_FN_SHA = {
    "_STOPGAP": "64d59cc524f060de",     # slice 2: COMPLETE -> "partial"
    "_require_certified": "61774ed83da806bc",
    "certified": "ecf1fd02af0c4336",
    "emit": "ba0d1324b1ef76a3",
    "passed": "05424137aeb8e4d9",
    "exit_code": "d45c448c6a711141",
}


def _allclear_fn_hashes(src: str) -> dict:
    import hashlib
    lines = src.splitlines()
    out = {}
    for node in ast.parse(src).body:
        name = (node.name if isinstance(node, ast.FunctionDef) else
                node.targets[0].id if isinstance(node, ast.Assign)
                and isinstance(node.targets[0], ast.Name) else None)
        if name not in _ALLCLEAR_PINNED:
            continue
        drop = set()
        if isinstance(node, ast.FunctionDef) and node.body and isinstance(node.body[0], ast.Expr) \
                and isinstance(node.body[0].value, ast.Constant):
            drop = set(range(node.body[0].lineno, node.body[0].end_lineno + 1))
        text = "\n".join(lines[n - 1] for n in range(node.lineno, node.end_lineno + 1)
                         if n not in drop)
        out[name] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return out


# F5. What each --help row and doc table row means, keyed by how its text
# starts.
def _help_meanings(command):
    unknown = exitcodes.COMBINE_UNKNOWN if command == "combine" else exitcodes.UNKNOWN
    rows = {"file": [("FAIL:", exitcodes.FAIL), ("parse failure", exitcodes.INVALID),
                     ("UNKNOWN:", unknown),
                     ("reserved: not emitted until ACCEPTED ships", exitcodes.ACCEPTED),
                     ("only for --help", exitcodes.HELP)],
            "gate": [("FAIL:", exitcodes.FAIL),
                     ("a file parsed to zero rules", exitcodes.INVALID),
                     ("UNKNOWN:", unknown),
                     ("reserved: not emitted until ACCEPTED ships", exitcodes.ACCEPTED),
                     ("only with --fail-on none", exitcodes.ADVISORY)],
            "combine": [("FAIL:", exitcodes.FAIL), ("UNKNOWN", unknown),
                        ("reserved: not emitted until ACCEPTED ships", exitcodes.ACCEPTED),
                        ("only when no enforced check exists", exitcodes.ADVISORY)]}
    return rows[command]


def _help_row_problems(command: str, text: str) -> list:
    rows = re.findall(r"^  (\d)  (.+)$", text, re.M)
    want = _help_meanings(command)
    problems, seen = [], []
    for code, meaning in rows:
        m = [(k, c) for k, c in want if meaning.startswith(k)]
        if len(m) != 1:
            problems.append(f"unrecognised row: {code}  {meaning}")
        elif int(code) != m[0][1]:
            problems.append(f"row {code} says {m[0][0]!r}, which is code {m[0][1]}")
        else:
            seen.append(m[0][0])
    if sorted(seen) != sorted(k for k, _ in want):
        problems.append(f"rows {seen} are not exactly {[k for k, _ in want]}")
    return problems


# outcome prefix -> codes for (rulehawk FILE, rulehawk gate, rulehawk combine);
# None is "n/a".
_TABLE_MEANINGS = [
    ("PASS (certified)", (exitcodes.PASS,) * 3),
    ("FAIL", (exitcodes.FAIL,) * 3),
    ("config parsed to zero rules", (exitcodes.INVALID,) * 3),
    ("UNKNOWN", (exitcodes.UNKNOWN, exitcodes.UNKNOWN, exitcodes.COMBINE_UNKNOWN)),
    ("ACCEPTED", (exitcodes.ACCEPTED,) * 3),
    ("advisory", (None, exitcodes.ADVISORY, exitcodes.ADVISORY)),
    ("`--help`", (exitcodes.HELP,) * 3),
]


def _table_row_problems(table: str) -> list:
    problems, seen = [], []
    for row in table.splitlines()[2:]:
        if not row.startswith("| "):
            continue
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        m = [(k, want) for k, want in _TABLE_MEANINGS if cells[0].startswith(k)]
        if len(m) != 1:
            problems.append(f"unrecognised row: {row}")
            continue
        got = tuple(None if c.startswith("n/a") else int(re.match(r"(\d+)", c).group(1))
                    for c in cells[1:4])
        if got != m[0][1]:
            problems.append(f"{m[0][0]!r} row has codes {got}, not {m[0][1]}")
        seen.append(m[0][0])
    if sorted(seen) != sorted(k for k, _ in _TABLE_MEANINGS):
        problems.append(f"rows {seen} are not exactly {[k for k, _ in _TABLE_MEANINGS]}")
    return problems


# F2. #44's guard blocks, as they were at e04630e, in tests/fixtures/
# stopgap_guards_e04630e.json: every contiguous run of lines #44 added
# (`git diff -U0 v0.4.0 e04630e`), which must appear in order, and the whole
# Enforce/Combine steps, which must each appear exactly once. Byte for byte,
# indentation included, until slice 9.
def _guard_block_problems(read) -> list:
    import json
    pins = json.loads(_read(os.path.join("tests", "fixtures", "stopgap_guards_e04630e.json")))
    problems = []
    for rel, p in sorted(pins.items()):
        if rel.startswith("_"):
            continue
        text = read(rel)
        at = 0
        for i, run in enumerate(p["runs"]):
            k = text.find(run, at)
            if k < 0:
                problems.append(f"{rel}: guard run {i} changed or out of order: {run[:70]!r}")
            else:
                at = k + len(run)
        for step in p["steps"]:
            if text.count(step) != 1:
                problems.append(f"{rel}: step changed: {step.splitlines()[0].strip()}")
    return problems
