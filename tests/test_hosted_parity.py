"""Hosted in-browser tool <-> CLI parity & honesty gate.

The web demo under ``docs/`` runs the engine client-side via Pyodide: ``worker.js``
loads a VENDORED copy of the ``rulehawk`` package (``docs/rulehawk/``) and executes
an embedded Python entrypoint (``ANALYZE_PY``) that auto-detects the vendor and
parses. So the hosted tool is the SAME engine as the CLI — not a JS reimplementation
that could silently diverge into a false PASS.

This module is the build-time guard for the one invariant the launch page depends
on: *the hosted tool never claims or audits a vendor it can't soundly handle, and
its verdicts match the CLI's fail-closed correctness.* It fails if anyone:
  * lets the vendored engine drift from the CLI engine (hosted would stop matching);
  * references a parser in ``ANALYZE_PY`` whose module isn't loaded (claimed-but-
    unsupported vendor — a config would error or, worse, mis-route);
  * lets ``worker.js`` and the ``index.html`` main-thread fallback disagree;
  * names a vendor in the *supported-vendors* UI copy that has no loaded parser.

It also EXECUTES the literal ``ANALYZE_PY`` extracted from ``worker.js`` against
real Junos / PAN-OS / iptables / Cisco samples and asserts the hosted entrypoint
reproduces the CLI's routing and verdicts — including a CRITICAL segmentation
violation and a fail-closed INDETERMINATE (never a false PASS).
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.parse import parse_acls  # noqa: E402
from rulehawk.parse_iptables import detect as detect_iptables, parse_iptables  # noqa: E402
from rulehawk.parse_junos import detect as detect_junos, parse_junos  # noqa: E402
from rulehawk.parse_panos import detect as detect_panos, parse_panos  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_DOCS = os.path.join(_ROOT, "docs")
_WORKER = os.path.join(_DOCS, "worker.js")
_INDEX = os.path.join(_DOCS, "index.html")
_VENDORED = os.path.join(_DOCS, "rulehawk")
_PKG = os.path.join(_ROOT, "rulehawk")

# Parsers the hosted dispatch may select, and the engine module that defines each.
# Every entry here MUST be loadable in the browser; the tests below enforce it.
_DISPATCH_PARSERS = {
    "parse_junos": "parse_junos",
    "parse_panos": "parse_panos",
    "parse_iptables": "parse_iptables",
    "parse_acls": "parse",          # Cisco IOS/ASA fallback lives in parse.py
}


# --------------------------------------------------------------------------- #
# helpers: pull the real config out of the shipped JS, don't hardcode a copy
# --------------------------------------------------------------------------- #
def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _engine_modules(js: str) -> list:
    m = re.search(r"ENGINE_MODULES\s*=\s*\[([^\]]*)\]", js)
    assert m, "ENGINE_MODULES list not found"
    return re.findall(r'"([^"]+)"', m.group(1))


def _analyze_py(js: str) -> str:
    """Extract the embedded Python entrypoint and undo JS template-literal escaping
    (`\\\\n` -> `\\n`) so it can be exec'd exactly as Pyodide would run it."""
    m = re.search(r"const ANALYZE_PY\s*=\s*`(.*?)`;", js, re.S)
    assert m, "ANALYZE_PY template not found"
    return m.group(1).replace("\\\\", "\\")


def _parsers_referenced(analyze_py: str) -> set:
    return {p for p in _DISPATCH_PARSERS if re.search(rf"\b{p}\b", analyze_py)}


def _run_hosted(analyze_py: str, cfg: str, pol: str = "") -> dict:
    """Execute the literal hosted entrypoint and return the parsed envelope.

    Pyodide's ``runPython`` returns the value of the trailing expression; we
    reproduce that by rewriting the final ``json.dumps(...)`` expression into an
    assignment we can read back. This runs the SAME code the browser runs."""
    tree = ast.parse(analyze_py)
    last = tree.body[-1]
    assert isinstance(last, ast.Expr), "entrypoint must end in an expression"
    tree.body[-1] = ast.copy_location(
        ast.Assign(targets=[ast.Name(id="_ENV", ctx=ast.Store())], value=last.value),
        last,
    )
    ast.fix_missing_locations(tree)
    g = {"json": json, "cfg": cfg, "pol": pol}
    exec(compile(tree, "<hosted ANALYZE_PY>", "exec"), g)  # noqa: S102 (trusted, repo-owned)
    return json.loads(g["_ENV"])


def _cli_route(cfg: str):
    """The CLI's vendor dispatch (rulehawk/cli.py), as the parity oracle."""
    if detect_junos(cfg):
        return "Juniper Junos", parse_junos(cfg)
    if detect_panos(cfg):
        return "Palo Alto PAN-OS", parse_panos(cfg)
    if detect_iptables(cfg):
        return "Linux iptables", parse_iptables(cfg)
    return "Cisco IOS / ASA", parse_acls(cfg)


def _kinds(findings):
    return sorted((f["kind"], f["severity"]) for f in findings)


# --------------------------------------------------------------------------- #
# fixtures (shaped exactly like the per-vendor parser tests)
# --------------------------------------------------------------------------- #
_JUNOS_LEAK = """
firewall { family inet { filter LEAK {
    term BAD {
        from {
            source-address 10.20.0.0/16;
            destination-address 10.10.0.0/16;
            protocol tcp;
            destination-port 445;
        }
        then accept;
    }
} } }
"""

_PANOS_CFG = (
    "set address corp ip-netmask 10.20.0.0/16\n"
    "set address pci ip-netmask 10.10.0.0/16\n"
    "set service svc-smb protocol tcp port 445\n"
    "set rulebase security rules leak from any to any source corp destination pci "
    "application any service svc-smb action allow\n"
)

# Cisco config that references an UNDEFINED object-group on the CORP->PCI path:
# the engine fails closed (opaque/imprecise ACE) -> segmentation-INDETERMINATE,
# never a false PASS. This is the soundness case the hosted tool must reproduce.
_CISCO_INDET = (
    "object-group network PCI_NET\n"
    " network-object 10.10.0.0 255.255.0.0\n"
    "ip access-list extended OUT\n"
    " permit tcp object-group CORP_NET object-group PCI_NET eq 445\n"
)  # CORP_NET is never defined

_POLICY = json.dumps({
    "zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
})

_IPTABLES = _read(os.path.join(_ROOT, "samples", "iptables_save.txt"))


# --------------------------------------------------------------------------- #
# 1. the hosted engine IS the CLI engine (so it is automatically sound)
# --------------------------------------------------------------------------- #
def test_vendored_engine_is_byte_identical_to_cli():
    """Every module the browser loads must be an exact copy of the CLI's — that
    is what makes the hosted verdicts the CLI's verdicts. Run ``make sync-web``
    after any engine change."""
    modules = _engine_modules(_read(_WORKER))
    for mod in modules:
        cli_path = os.path.join(_PKG, mod + ".py")
        web_path = os.path.join(_VENDORED, mod + ".py")
        assert os.path.exists(web_path), f"vendored module missing: {mod}.py"
        assert _read(cli_path) == _read(web_path), (
            f"vendored {mod}.py has drifted from the CLI — run `make sync-web`")


def test_vendored_package_has_no_extra_or_missing_parser():
    cli_py = {f for f in os.listdir(_PKG) if f.endswith(".py")}
    web_py = {f for f in os.listdir(_VENDORED) if f.endswith(".py")}
    assert cli_py == web_py, f"vendored package set differs from CLI: {cli_py ^ web_py}"


# --------------------------------------------------------------------------- #
# 2. no claimed-but-unloaded vendor; worker and fallback agree
# --------------------------------------------------------------------------- #
def test_every_dispatched_parser_is_actually_loaded():
    worker = _read(_WORKER)
    modules = set(_engine_modules(worker))
    for parser in _parsers_referenced(_analyze_py(worker)):
        mod = _DISPATCH_PARSERS[parser]
        assert mod in modules, f"{parser} is dispatched but {mod}.py is not loaded"
        assert os.path.exists(os.path.join(_VENDORED, mod + ".py"))


def test_all_four_vendor_families_are_wired():
    referenced = _parsers_referenced(_analyze_py(_read(_WORKER)))
    assert referenced == set(_DISPATCH_PARSERS), (
        f"hosted tool does not dispatch every vendor family: missing "
        f"{set(_DISPATCH_PARSERS) - referenced}")


def test_worker_and_index_fallback_agree():
    worker, index = _read(_WORKER), _read(_INDEX)
    assert _engine_modules(worker) == _engine_modules(index), \
        "worker.js and index.html load different engine modules"
    assert _parsers_referenced(_analyze_py(worker)) == \
        _parsers_referenced(_analyze_py(index)), \
        "worker.js and the main-thread fallback dispatch different vendors"


def test_ui_supported_copy_names_no_unloaded_vendor():
    """The input label advertises which vendors the tool accepts. Every vendor it
    names there must have a loaded parser; a vendor with no parser (e.g. NX-OS,
    still roadmap) must NOT appear as supported."""
    index = _read(_INDEX)
    label = re.search(r'for="config">.*?</label>', index, re.S).group(0).lower()
    loaded = {"cisco", "junos", "pan-os", "iptables"}
    for token in ("cisco", "junos", "pan-os", "iptables"):
        assert token in label, f"supported-vendor copy omits a wired vendor: {token}"
    # NX-OS has no parser yet — it must not be advertised as supported.
    assert "nx-os" not in label and "nxos" not in label, \
        "input label claims NX-OS, which has no parser (keep it roadmap-only)"
    assert loaded  # loaded set documents the audited families


# --------------------------------------------------------------------------- #
# 3. the literal hosted entrypoint reproduces the CLI's verdicts
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg,vendor", [
    (_JUNOS_LEAK, "Juniper Junos"),
    (_PANOS_CFG, "Palo Alto PAN-OS"),
    (_IPTABLES, "Linux iptables"),
    (_CISCO_INDET, "Cisco IOS / ASA"),
])
def test_hosted_autodetects_same_vendor_as_cli(cfg, vendor):
    env = _run_hosted(_analyze_py(_read(_WORKER)), cfg)
    assert env["vendor"] == vendor
    assert env["vendor"] == _cli_route(cfg)[0]


@pytest.mark.parametrize("cfg", [_JUNOS_LEAK, _PANOS_CFG, _IPTABLES, _CISCO_INDET])
def test_hosted_findings_match_cli_exactly(cfg):
    """Strongest assertion: the hosted entrypoint's findings == running the CLI's
    detect+parse+analyze+segcheck directly. Same engine, same verdicts."""
    env = _run_hosted(_analyze_py(_read(_WORKER)), cfg, _POLICY)
    _, (aces, notes) = _cli_route(cfg)
    findings = analyze(aces) + check_segmentation(aces, json.loads(_POLICY))
    expected = sorted((f.kind, f.severity) for f in findings)
    assert _kinds(env["report_json"]["findings"]) == expected


def test_hosted_audits_junos_segmentation_violation_critical():
    env = _run_hosted(_analyze_py(_read(_WORKER)), _JUNOS_LEAK, _POLICY)
    viol = [f for f in env["report_json"]["findings"]
            if f["kind"] == "segmentation-violation"]
    assert viol and viol[0]["severity"] == "critical"
    assert ":445" in viol[0]["witness"]          # auditor-grade witness packet


def test_hosted_is_fail_closed_indeterminate_never_false_pass():
    env = _run_hosted(_analyze_py(_read(_WORKER)), _CISCO_INDET, _POLICY)
    kinds = {f["kind"] for f in env["report_json"]["findings"]}
    assert "segmentation-indeterminate" in kinds   # unmodeled ref -> fail closed
    assert "segmentation-ok" not in kinds          # never a false PASS


def test_hosted_fallback_entrypoint_also_matches():
    """The index.html main-thread fallback runs its own ANALYZE_PY copy; it must
    produce the identical envelope so the fallback can't audit a different set."""
    env = _run_hosted(_analyze_py(_read(_INDEX)), _JUNOS_LEAK, _POLICY)
    assert env["vendor"] == "Juniper Junos"
    viol = [f for f in env["report_json"]["findings"]
            if f["kind"] == "segmentation-violation"]
    assert viol and viol[0]["severity"] == "critical"
