"""RuleHawk MCP server: the rule-layer audit as tools an agent can call.

    pip install "rulehawk[mcp] @ git+https://github.com/optimesh-ai/RuleHawk"
    rulehawk-mcp            # stdio transport; an MCP client launches it

Five read-only tools over the same engine the CLI and the CI gate run:

  * rulehawk_audit           audit a config file or a directory of configs
  * rulehawk_list_findings   every finding, filterable by severity and kind
  * rulehawk_explain_finding one finding (by id) or one finding kind, explained
  * rulehawk_compare         before vs after: the findings a change introduces
  * rulehawk_supported_inputs what RuleHawk can and cannot read or model

DESIGN RULES (the same ones the CLI and gate keep):

  * Read-only and local-only. The tools read the files they are pointed at and
    nothing else: no network, no subprocess, no writes. Path-grounding against
    a Hammerhead install (`--hh-snapshot`) is deliberately not exposed.
  * Never a silent pass. Every result carries a `coverage` block naming each
    file that was analysed, each file that was NOT (and why), and each config
    line the parser could not model. A file that parses to zero rules is never
    "clean": the verdict is INCOMPLETE, never PASS.
  * Stateless. Each call re-reads its inputs; a finding id is a digest of the
    finding itself, so it is stable across calls on unchanged files and simply
    stops resolving when the file changes.
  * Scope is stated, not implied. Every result says it covers the rule layer
    only: routing, NAT, topology and change impact are not evaluated.

Set RULEHAWK_MCP_ROOT to a directory to refuse any path outside it.

The MCP SDK (`mcp`, Python 3.10+) is imported only inside `build_server()`, so
this module stays importable, and its tool functions testable, without it.
Nothing in `rulehawk/__init__.py` imports this module, so the hosted
in-browser tool never loads it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter
from typing import Dict, List, Optional, Tuple

from . import __version__
from .analyze import Finding
from .boundary import to_dict as boundary_dict
from .gate import (_KIND_HELP, _SEV_ORDER, _SEV_RANK, _VENDORS, FileResult,
                   _pick_parser, no_rules_reason, run_gate)

# Limits keep one call bounded; anything beyond them is reported as not
# analysed, never dropped.
MAX_FILES = 1000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_NOTES_PER_FILE = 20
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
# The shadowing analysis compares rules pairwise within one ACL, so its cost
# grows with the square of the largest ACL (about 25 s at 10,000 rules on a
# laptop). A bigger ACL is reported as not analysed (INCOMPLETE, never PASS)
# rather than leaving the agent's tool call hanging. Override with the
# RULEHAWK_MCP_MAX_ACL_RULES environment variable.
DEFAULT_MAX_ACL_RULES = 10000

_FAIL_ON = ("critical", "high", "medium", "low", "none")

SUPPORTED_VENDORS = [
    {"vendor": "ios-asa", "name": "Cisco IOS extended ACLs and Cisco ASA access-lists (object-groups resolved)"},
    {"vendor": "nxos", "name": "Cisco NX-OS access-lists"},
    {"vendor": "eos", "name": "Arista EOS access-lists"},
    {"vendor": "junos", "name": "Juniper Junos firewall filters (brace form)"},
    {"vendor": "panos", "name": "Palo Alto PAN-OS security policy (set format)"},
    {"vendor": "iptables", "name": "Linux iptables/ip6tables filter rules (iptables-save)"},
    {"vendor": "aws-sg", "name": "AWS Security Groups (aws ec2 describe-security-groups JSON)"},
]

NOT_MODELLED = [
    "routing and topology: each config is an independent first-match ruleset",
    "NAT (ASA nat/static, the iptables nat table)",
    "change impact on forwarding: what a change breaks elsewhere on the network",
    "L7 and identity (PAN-OS app-ID, source-user), time-range, inactive rules, "
    "interface bindings and fragments: over-approximated and noted",
    "vendors not listed in supported_vendors (FortiGate, AWS Network ACLs and "
    "nftables are not supported)",
]

SCOPE_STATEMENT = ("Rule layer only (ACL/filter semantics). Routing, NAT, "
                   "topology and change impact were not evaluated.")

_VENDOR_CHOICES = ("auto", "ios-asa", "nxos", "eos", "junos", "panos",
                   "iptables", "aws-sg")


class InputError(ValueError):
    """A request the tools refuse (bad path, bad argument). Reported to the
    agent as an ERROR result, never raised through the protocol."""

    def __init__(self, msg: str, code: str = "bad_argument", hint: str = ""):
        super().__init__(msg)
        self.code = code
        self.hint = hint


def _max_acl_rules() -> int:
    try:
        n = int(os.environ.get("RULEHAWK_MCP_MAX_ACL_RULES", ""))
    except ValueError:
        return DEFAULT_MAX_ACL_RULES
    return n if n > 0 else DEFAULT_MAX_ACL_RULES


# --------------------------------------------------------------------------- #
# input resolution
# --------------------------------------------------------------------------- #
def _root() -> Optional[str]:
    r = os.environ.get("RULEHAWK_MCP_ROOT", "").strip()
    return os.path.realpath(os.path.expanduser(r)) if r else None


def _resolve(path: str, what: str = "path") -> str:
    """Absolute, symlink-resolved path. A relative path resolves against
    RULEHAWK_MCP_ROOT when it is set, else against the server's working
    directory (which an MCP client chooses, so absolute paths are safer)."""
    if not isinstance(path, str) or not path.strip():
        raise InputError(f"{what} is required", "path_required",
                         f"pass the absolute path of a config file or directory as {what}")
    raw = os.path.expanduser(path.strip())
    root = _root()
    base = root or os.getcwd()
    p = os.path.realpath(os.path.join(base, raw))
    if root and p != root and not p.startswith(root + os.sep):
        raise InputError(
            f"{what} {path!r} resolves to {p}, outside RULEHAWK_MCP_ROOT ({root})",
            "path_outside_root",
            f"pass a path under {root}, or restart the server with "
            "RULEHAWK_MCP_ROOT set to a directory that contains the file")
    if not os.path.exists(p):
        if os.path.isabs(raw):
            hint = "check the path; it must exist on the machine running rulehawk-mcp"
        elif root:
            hint = (f"relative paths resolve against RULEHAWK_MCP_ROOT ({root}); "
                    "pass an absolute path")
        else:
            hint = (f"relative paths resolve against the server's working "
                    f"directory ({base}); pass an absolute path")
        raise InputError(f"{what} {path!r} does not exist (looked for {p})",
                         "path_not_found", hint)
    return p


def _collect(path: str, what: str = "path") -> Tuple[str, List[str], List[dict]]:
    """Expand a file or directory into (base, files, not_analysed).

    A directory is walked recursively. Names starting with '.' (e.g. .git) are
    not read, and are counted in `not_analysed` so the omission is visible."""
    p = _resolve(path, what)
    if os.path.isfile(p):
        candidates = [p]
        base = os.path.dirname(p)
        skipped: List[dict] = []
    elif os.path.isdir(p):
        base = p
        candidates = []
        hidden = 0
        for dirpath, dirs, files in os.walk(p):
            hidden += sum(1 for d in dirs if d.startswith("."))
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for f in sorted(files):
                if f.startswith("."):
                    hidden += 1
                    continue
                candidates.append(os.path.join(dirpath, f))
        skipped = []
        if hidden:
            skipped.append({"path": p, "reason": (
                f"{hidden} hidden file(s)/directory(ies) (names starting with "
                "'.') were not read")})
    else:
        raise InputError(f"{what} {path!r} is neither a file nor a directory",
                         "path_not_found", "pass a regular file or a directory")
    files: List[str] = []
    for c in candidates:
        if len(files) >= MAX_FILES:
            skipped.append({"path": c, "reason": (
                f"file limit reached ({MAX_FILES} files per call)")})
            continue
        try:
            size = os.path.getsize(c)
        except OSError as e:
            skipped.append({"path": c, "reason": f"cannot read: {e}"})
            continue
        if size > MAX_FILE_BYTES:
            skipped.append({"path": c, "reason": (
                f"file is {size} bytes; the limit is {MAX_FILE_BYTES}")})
            continue
        files.append(c)
    if not files and not skipped:
        skipped.append({"path": p, "reason": "directory contains no files"})
    return base, files, skipped


def _load_policy(policy_path: str) -> Tuple[Optional[dict], Optional[str]]:
    if not policy_path:
        return None, None
    p = _resolve(policy_path, "policy_path")
    try:
        with open(p, "rb") as fh:
            policy = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read policy {policy_path!r}: {e}",
                         "policy_unreadable",
                         "policy_path must be a JSON segmentation policy; see "
                         "docs/policy.md, or omit policy_path")
    if not isinstance(policy, dict):
        raise InputError(f"policy {policy_path!r} must be a JSON object",
                         "policy_unreadable", "see docs/policy.md for the schema")
    return policy, p


def _check_choice(value: str, choices, what: str) -> str:
    v = (value or "").strip().lower()
    if v not in choices:
        raise InputError(f"{what} must be one of {', '.join(choices)}; got {value!r}",
                         "bad_argument", f"use one of: {', '.join(choices)}")
    return v


def _check_vendor(value: str) -> str:
    """auto, a vendor id, or a common alias (cisco, juniper, paloalto...)."""
    v = (value or "auto").strip().lower()
    if v == "auto":
        return v
    if v in _VENDORS:
        return _VENDORS[v]
    raise InputError(f"vendor must be one of {', '.join(_VENDOR_CHOICES)}; got {value!r}",
                     "bad_argument",
                     "leave vendor as auto unless detection picked the wrong parser")


def _limit(n) -> int:
    try:
        n = int(n)
    except (TypeError, ValueError):
        raise InputError("limit must be an integer", "bad_argument")
    if n < 1:
        raise InputError("limit must be at least 1", "bad_argument")
    return min(n, MAX_LIMIT)


# --------------------------------------------------------------------------- #
# shaping results
# --------------------------------------------------------------------------- #
def _rel(path: str, base: str) -> str:
    try:
        r = os.path.relpath(path, base)
    except ValueError:
        return path
    return path if r.startswith("..") else r


def make_finding_id(path: str, f: Finding) -> str:
    """Stable id: a digest of where the finding is and what it says."""
    key = "\x1f".join([os.path.realpath(path), f.kind, f.rule_id, f.rule,
                       f.cited, f.witness, f.message])
    return "RH-" + hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:12]


def _finding_dict(fr: FileResult, f: Finding, base: str) -> dict:
    return {
        "id": make_finding_id(fr.path, f),
        "file": _rel(fr.path, base),
        "line": fr.line_of(f),
        "rule_id": f.rule_id,
        "kind": f.kind,
        "severity": f.severity,
        "message": f.message,
        "rule": f.rule,
        "cited": f.cited,
        "witness": f.witness,
        "fix": f.fix,
        "accepted": f.accepted,
    }


def _sorted_pairs(pairs):
    return sorted(pairs, key=lambda p: (-_SEV_RANK.get(p[1].severity, 0),
                                        p[0].path, p[1].line, p[1].rule_id))


def _counts(findings) -> Dict[str, int]:
    c = {k: 0 for k in _SEV_ORDER}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def _coverage(gate, base: str, skipped: List[dict]) -> dict:
    analysed, not_analysed = [], list(skipped)
    partial = 0
    for fr in gate.files:
        if fr.status == "ok":
            notes = list(fr.notes)
            if notes:
                partial += 1
            analysed.append({
                "file": _rel(fr.path, base),
                "vendor": fr.vendor,
                "rules_analysed": fr.n_rules,
                "score": fr.score,
                "findings_by_severity": _counts(
                    [f for f in fr.findings if f.severity != "info"]),
                "unmodelled_lines": notes[:MAX_NOTES_PER_FILE],
                "unmodelled_lines_total": len(notes),
            })
        elif fr.status == "no_rules_parsed":
            not_analysed.append({
                "path": _rel(fr.path, base),
                "reason": "no rules parsed: " + no_rules_reason(fr, gate.vendor),
                "parser_tried": fr.vendor,
                "parser_notes": list(fr.notes)[:5],
                "hint": ("check it is a supported format "
                         "(rulehawk_supported_inputs); a config with no ACLs "
                         "or firewall policy has nothing to audit")})
        else:
            not_analysed.append({"path": _rel(fr.path, base),
                                 "reason": f"cannot read: {fr.error}"})
    for na in not_analysed:
        na["path"] = _rel(na["path"], base) if os.path.isabs(na["path"]) else na["path"]
    if not_analysed:
        state = "incomplete"
    elif partial:
        state = "partial"
    else:
        state = "complete"
    return {
        "state": state,
        "explanation": {
            "complete": "every file was parsed and every line was modelled",
            "partial": ("every file was parsed, but some lines were not "
                        "modelled (see unmodelled_lines); review them"),
            "incomplete": ("at least one input was NOT analysed (see "
                           "not_analysed); no PASS is given"),
        }[state],
        "files_analysed": len(analysed),
        "files_not_analysed": len(not_analysed),
        "files_with_unmodelled_lines": partial,
        "rules_analysed": sum(a["rules_analysed"] for a in analysed),
        "analysed": analysed,
        "not_analysed": not_analysed,
    }


def _scope(findings) -> dict:
    b = boundary_dict(findings)
    return {"statement": SCOPE_STATEMENT, "scope": b["scope"],
            "not_evaluated": b["not_evaluated"],
            "needs_path_verification": b["needs_path_verification"],
            "needs_path_verification_because": b["triggered_by"]}


def _error(tool: str, msg: str, code: str = "bad_argument", hint: str = "") -> dict:
    out = {"tool": tool, "rulehawk_version": __version__, "verdict": "ERROR",
           "error": msg, "error_code": code}
    if hint:
        out["hint"] = hint
    out["coverage"] = {"state": "incomplete", "explanation": "nothing was analysed"}
    out["scope"] = {"statement": SCOPE_STATEMENT}
    return out


def _input_error(tool: str, e: InputError) -> dict:
    return _error(tool, str(e), e.code, e.hint)


def _over_budget(files: List[str], vendor: str) -> Tuple[List[str], List[dict]]:
    """Split off files whose largest ACL is too big to analyse in one call."""
    cap = _max_acl_rules()
    keep: List[str] = []
    skipped: List[dict] = []
    for p in files:
        try:
            with open(p, "rb") as fh:
                text = fh.read().decode("utf-8", errors="replace")
        except OSError:
            keep.append(p)          # audit_file reports the read error itself
            continue
        _, parse_fn = _pick_parser(text, vendor)
        per_acl = Counter(a.acl for a in parse_fn(text)[0])
        biggest = max(per_acl.values()) if per_acl else 0
        if biggest > cap:
            acl = max(per_acl, key=per_acl.get)
            skipped.append({"path": p, "reason": (
                f"ACL {acl!r} has {biggest} rules, over the per-call limit of "
                f"{cap} (analysis time grows with the square of the ACL size)"),
                "hint": ("run the CLI instead (`rulehawk FILE`), which has no "
                         "limit, or raise RULEHAWK_MCP_MAX_ACL_RULES in the "
                         "server's environment")})
        else:
            keep.append(p)
    return keep, skipped


def _run(path: str, policy_path: str, vendor: str, fail_on: str,
         what: str = "path"):
    vendor = _check_vendor(vendor)
    fail_on = _check_choice(fail_on or "high", _FAIL_ON, "fail_on")
    policy, _ = _load_policy(policy_path)
    base, files, skipped = _collect(path, what)
    files, too_big = _over_budget(files, vendor)
    gate = run_gate(files, policy, fail_on=fail_on, vendor=vendor)
    return gate, base, skipped + too_big, fail_on, policy is not None


def _verdict(gate, coverage: dict, fail_on: str) -> Tuple[str, str]:
    blockers = gate.violations
    if blockers:
        return "FAIL", (f"{len(blockers)} finding(s) at or above fail_on="
                        f"{fail_on}")
    if coverage["state"] == "incomplete":
        return "INCOMPLETE", (f"{coverage['files_not_analysed']} input(s) not "
                              "analysed; nothing unanalysed can pass")
    if fail_on == "none":
        return "ADVISORY", ("fail_on=none: nothing blocks, so no PASS is given; "
                            "read findings_by_severity")
    return "PASS", f"no finding at or above fail_on={fail_on}"


# --------------------------------------------------------------------------- #
# tools (plain functions: the MCP layer below only registers them)
# --------------------------------------------------------------------------- #
def audit(path: str, policy_path: str = "", vendor: str = "auto",
          fail_on: str = "high") -> dict:
    """Audit one config file or every file in a directory."""
    try:
        gate, base, skipped, fail_on, has_policy = _run(
            path, policy_path, vendor, fail_on)
    except InputError as e:
        return _input_error("rulehawk_audit", e)
    cov = _coverage(gate, base, skipped)
    verdict, why = _verdict(gate, cov, fail_on)
    all_findings = [f for fr in gate.files for f in fr.findings]
    blockers = _sorted_pairs(gate.violations)
    return {
        "tool": "rulehawk_audit",
        "rulehawk_version": __version__,
        "verdict": verdict,
        "verdict_reason": why,
        "fail_on": fail_on,
        "policy_applied": has_policy,
        "worst_severity": gate.worst,
        "score": gate.score,
        "findings_by_severity": gate.counts(),
        "blocking_findings": [_finding_dict(fr, f, base) for fr, f in blockers],
        "segmentation_passed": [
            {"file": _rel(fr.path, base), "claim": f.rule_id, "message": f.message}
            for fr in gate.files for f in fr.findings
            if f.kind in ("segmentation-ok", "connectivity-ok")],
        "coverage": cov,
        "scope": _scope(all_findings),
        "next": ("Call rulehawk_list_findings for every finding, or "
                 "rulehawk_explain_finding with an id for detail."),
    }


def list_findings(path: str, policy_path: str = "", vendor: str = "auto",
                  min_severity: str = "low", kinds: Optional[List[str]] = None,
                  limit: int = DEFAULT_LIMIT) -> dict:
    """Every finding (sorted worst first), filtered by severity and kind."""
    try:
        min_sev = _check_choice(min_severity or "low", _SEV_ORDER, "min_severity")
        lim = _limit(limit)
        want = set(kinds or [])
        unknown = sorted(want - set(_KIND_HELP) - {"segmentation-infeasible-path"})
        gate, base, skipped, _, has_policy = _run(path, policy_path, vendor, "high")
    except InputError as e:
        return _input_error("rulehawk_list_findings", e)
    floor = _SEV_RANK[min_sev]
    pairs = [(fr, f) for fr in gate.files for f in fr.findings
             if _SEV_RANK.get(f.severity, 0) >= floor
             and (not want or f.kind in want)]
    pairs = _sorted_pairs(pairs)
    out = {
        "tool": "rulehawk_list_findings",
        "rulehawk_version": __version__,
        "filters": {"min_severity": min_sev, "kinds": sorted(want), "limit": lim},
        "policy_applied": has_policy,
        "findings_total": len(pairs),
        "findings_returned": min(len(pairs), lim),
        "truncated": len(pairs) > lim,
        "findings": [_finding_dict(fr, f, base) for fr, f in pairs[:lim]],
        "coverage": _coverage(gate, base, skipped),
        "scope": _scope([f for _, f in pairs]),
    }
    if unknown:
        out["unknown_kinds"] = unknown
    return out


def _source_line(path: str, line: int) -> str:
    if line < 1:
        return ""
    try:
        with open(path, "rb") as fh:
            for i, raw in enumerate(fh, 1):
                if i == line:
                    return raw.decode("utf-8", "replace").rstrip("\r\n")[:500]
    except OSError:
        return ""
    return ""


def explain_finding(finding_id: str = "", path: str = "", kind: str = "",
                    policy_path: str = "", vendor: str = "auto") -> dict:
    """Explain one finding by id (re-audits `path`), or one finding kind."""
    tool = "rulehawk_explain_finding"
    fid = (finding_id or "").strip()
    k = (kind or "").strip()
    if not fid:
        if not k:
            return _error(tool, "give finding_id (with path) or kind",
                          "bad_argument",
                          "pass finding_id plus the path it came from, or a kind "
                          "such as dangerous-exposure")
        if k not in _KIND_HELP:
            out = _error(tool, f"unknown kind {k!r}", "bad_argument",
                         "use one of known_kinds")
            out["known_kinds"] = sorted(_KIND_HELP)
            return out
        return {"tool": tool, "rulehawk_version": __version__, "kind": k,
                "explanation": _KIND_HELP[k],
                "scope": {"statement": SCOPE_STATEMENT}}
    if not re.fullmatch(r"RH-[0-9a-f]{12}", fid):
        return _error(tool, f"finding_id {fid!r} is not a RuleHawk id (RH-xxxxxxxxxxxx)",
                      "bad_argument",
                      "use an id field from rulehawk_audit or rulehawk_list_findings")
    if not (path or "").strip():
        return _error(tool, "finding_id needs path: the same config file or "
                      "directory the finding came from", "path_required",
                      "re-send with path (and policy_path, if the finding came "
                      "from a policy run)")
    try:
        gate, base, skipped, _, _ = _run(path, policy_path, vendor, "high")
    except InputError as e:
        return _input_error(tool, e)
    for fr in gate.files:
        for f in fr.findings:
            if make_finding_id(fr.path, f) != fid:
                continue
            d = _finding_dict(fr, f, base)
            d["source_line"] = _source_line(fr.path, d["line"])
            return {
                "tool": tool, "rulehawk_version": __version__, "found": True,
                "finding": d,
                "kind_explanation": _KIND_HELP.get(f.kind, ""),
                "file_vendor": fr.vendor,
                "file_unmodelled_lines": list(fr.notes)[:MAX_NOTES_PER_FILE],
                "scope": _scope([f]),
            }
    out = _error(tool, (f"no finding {fid} in {path!r}: the file changed since "
                        "the id was issued, or a different path/policy was used"),
                 "finding_not_found",
                 "call rulehawk_list_findings again with the same path and "
                 "policy_path to get current ids")
    out["found"] = False
    out["coverage"] = _coverage(gate, base, skipped)
    return out


def _ws(s: str) -> str:
    return " ".join((s or "").split())


def _fkey(f: Finding) -> tuple:
    # NOT rule_id: it is ACL:seq and shifts when a rule is inserted above.
    return (f.kind, _ws(f.rule), _ws(f.cited), _ws(f.witness))


def _pair_files(b_base, b_files, a_base, a_files, b_is_file, a_is_file):
    if b_is_file and a_is_file:
        return [(b_files[0] if b_files else None, a_files[0] if a_files else None)]
    bm = {os.path.relpath(p, b_base): p for p in b_files}
    am = {os.path.relpath(p, a_base): p for p in a_files}
    return [(bm.get(r), am.get(r)) for r in sorted(set(bm) | set(am))]


def compare(before: str, after: str, policy_path: str = "",
            vendor: str = "auto", fail_on: str = "high") -> dict:
    """Findings the `after` config introduces relative to `before`."""
    tool = "rulehawk_compare"
    try:
        vendor_c = _check_vendor(vendor)
        fail_on = _check_choice(fail_on or "high", _FAIL_ON, "fail_on")
        policy, _ = _load_policy(policy_path)
        rb, ra = _resolve(before, "before"), _resolve(after, "after")
        if os.path.isfile(rb) != os.path.isfile(ra):
            raise InputError("before and after must both be files or both be directories",
                             "bad_argument",
                             "pass two files, or two directories whose files "
                             "pair by relative path")
        b_base, b_files, b_skip = _collect(before, "before")
        a_base, a_files, a_skip = _collect(after, "after")
        b_run, b_big = _over_budget(b_files, vendor_c)
        a_run, a_big = _over_budget(a_files, vendor_c)
        b_skip, a_skip = b_skip + b_big, a_skip + a_big
        too_big = {d["path"] for d in b_big + a_big}
    except InputError as e:
        return _input_error(tool, e)
    thr = _SEV_RANK.get(fail_on, 99) if fail_on != "none" else 99
    b_gate = run_gate(b_run, policy, fail_on, vendor_c)
    a_gate = run_gate(a_run, policy, fail_on, vendor_c)
    b_by = {fr.path: fr for fr in b_gate.files}
    a_by = {fr.path: fr for fr in a_gate.files}
    pairs = _pair_files(b_base, b_files, a_base, a_files,
                        os.path.isfile(rb), os.path.isfile(ra))
    introduced, resolved, files_out = [], [], []
    still_blocking = 0
    for bp, ap in pairs:
        bfr, afr = b_by.get(bp), a_by.get(ap)
        entry = {"before": _rel(bp, b_base) if bp else None,
                 "after": _rel(ap, a_base) if ap else None}
        b_ok = bfr is not None and bfr.status == "ok"
        a_ok = afr is not None and afr.status == "ok"
        if ap is None:
            entry["change"] = "removed"
        elif bp is None:
            entry["change"] = "added"
        else:
            entry["change"] = "modified"
        if bp in too_big or ap in too_big:
            entry["comparable"] = False
            entry["reason"] = ("over the per-call ACL size limit (see "
                               "coverage.not_analysed); not compared")
        elif afr is not None and not a_ok:
            entry["comparable"] = False
            entry["reason"] = "after file not analysed (no rules recognised or unreadable)"
        elif bfr is not None and not b_ok:
            entry["comparable"] = False
            entry["reason"] = ("before file not analysed, so every finding in "
                               "after would look new; not compared")
        else:
            entry["comparable"] = True
        bf = [f for f in (bfr.findings if b_ok else []) if f.severity != "info"]
        af = [f for f in (afr.findings if a_ok else []) if f.severity != "info"]
        if entry["comparable"] and afr is not None:
            left = Counter(_fkey(f) for f in bf)
            for f in af:
                k = _fkey(f)
                if left[k] > 0:
                    left[k] -= 1
                    if _SEV_RANK.get(f.severity, 0) >= thr and f.accepted is None:
                        still_blocking += 1
                else:
                    introduced.append(_finding_dict(afr, f, a_base))
            right = Counter(_fkey(f) for f in af)
            for f in bf:
                k = _fkey(f)
                if right[k] > 0:
                    right[k] -= 1
                else:
                    resolved.append(_finding_dict(bfr, f, b_base))
            b_rules = Counter((a.acl, _ws(a.raw)) for a in (bfr.aces if bfr else []))
            added = []
            seen = set()
            for a in afr.aces:
                k2 = (a.acl, _ws(a.raw))
                if k2 in seen:
                    continue
                seen.add(k2)
                if b_rules[k2] == 0:
                    added.append({"acl": a.acl, "line": a.line, "rule": a.raw})
            entry["rules_added"] = added[:50]
            entry["rules_added_total"] = len(added)
        elif entry["comparable"] and afr is None and b_ok:
            resolved.extend(_finding_dict(bfr, f, b_base) for f in bf)
        files_out.append(entry)
    new_blocking = [d for d in introduced
                    if _SEV_RANK.get(d["severity"], 0) >= thr and not d["accepted"]]
    not_comparable = [e for e in files_out if not e["comparable"]]
    b_cov = _coverage(b_gate, b_base, b_skip)
    a_cov = _coverage(a_gate, a_base, a_skip)
    if new_blocking:
        verdict, why = "INTRODUCES_RISK", (
            f"{len(new_blocking)} new finding(s) at or above fail_on={fail_on}")
    elif not_comparable or a_cov["state"] == "incomplete" or b_cov["state"] == "incomplete":
        verdict, why = "INCOMPLETE", ("at least one file could not be analysed "
                                      "on both sides; no all-clear is given")
    elif fail_on == "none":
        verdict, why = "ADVISORY", (f"fail_on=none: nothing blocks; "
                                    f"{len(introduced)} finding(s) introduced")
    else:
        verdict, why = "NO_NEW_RISK", (
            f"no new finding at or above fail_on={fail_on}"
            + (f"; {still_blocking} pre-existing blocking finding(s) remain"
               if still_blocking else ""))
    introduced.sort(key=lambda d: (-_SEV_RANK.get(d["severity"], 0), d["file"], d["line"]))
    return {
        "tool": tool,
        "rulehawk_version": __version__,
        "verdict": verdict,
        "verdict_reason": why,
        "fail_on": fail_on,
        "policy_applied": policy is not None,
        "introduced": introduced[:MAX_LIMIT],
        "introduced_total": len(introduced),
        "resolved": resolved[:MAX_LIMIT],
        "resolved_total": len(resolved),
        "pre_existing_blocking": still_blocking,
        "files": files_out,
        "coverage": {"before": b_cov, "after": a_cov},
        "method": ("Both sides are audited independently and their findings "
                   "are matched on kind + rule text + cited rule + witness "
                   "(not on sequence numbers, which shift on insert). An "
                   "edited rule therefore shows as one resolved and one "
                   "introduced finding. This is a rule-layer finding delta, "
                   "not a forwarding or reachability diff."),
        "scope": _scope([f for fr in a_gate.files for f in fr.findings]),
    }


def supported_inputs() -> dict:
    """What RuleHawk reads, what it models, and what it does not."""
    return {
        "tool": "rulehawk_supported_inputs",
        "rulehawk_version": __version__,
        "supported_vendors": SUPPORTED_VENDORS,
        "vendor_detection": ("auto-detected per file; pass vendor= to force "
                             "one. A file no parser recognises is reported as "
                             "not analysed, never as clean."),
        "finding_kinds": {k: v for k, v in sorted(_KIND_HELP.items())},
        "policy": ("optional JSON segmentation policy (zones, must_not_reach, "
                   "must_reach); see docs/policy.md in the RuleHawk repo"),
        "not_modelled": NOT_MODELLED,
        "limits": {"max_files_per_call": MAX_FILES,
                   "max_file_bytes": MAX_FILE_BYTES,
                   "max_rules_per_acl": _max_acl_rules(),
                   "hidden_files": "names starting with '.' are not read"},
        "guarantees": [
            "read-only: no file is written",
            "local-only: no network access and no subprocess",
            "fail-closed: unrecognised or unreadable input makes the result "
            "INCOMPLETE, never PASS",
        ],
        "scope": {"statement": SCOPE_STATEMENT},
    }


# --------------------------------------------------------------------------- #
# MCP wiring
# --------------------------------------------------------------------------- #
INSTRUCTIONS = (
    "RuleHawk audits firewall/ACL rulesets locally (rule layer only). Before "
    "pushing an ACL or firewall change, call rulehawk_audit (or rulehawk_compare "
    "with the running and candidate configs), using absolute paths. Only PASS "
    "and NO_NEW_RISK are an all-clear. Treat FAIL, INTRODUCES_RISK, "
    "INCOMPLETE, ADVISORY or ERROR as a stop, and show the human the "
    "blocking findings and the coverage.not_analysed list. RuleHawk does not "
    "model routing, NAT or topology, so a PASS is not a reachability proof."
)


def build_server():
    """Build the MCP server (needs the `mcp` extra, Python 3.10+)."""
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations

    ro = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                         idempotentHint=True, openWorldHint=False)
    server = MCPServer("rulehawk", instructions=INSTRUCTIONS,
                       version=__version__,
                       website_url="https://github.com/optimesh-ai/RuleHawk")

    @server.tool(name="rulehawk_audit", title="Audit firewall config",
                 annotations=ro)
    def rulehawk_audit(path: str, policy_path: str = "", vendor: str = "auto",
                       fail_on: str = "high") -> dict:
        """Audit a firewall/ACL config file, or every file in a directory, for
        shadowed, redundant, over-permissive and risky-exposure rules (and,
        with policy_path, segmentation violations with a witness packet).
        Start here.

        Returns verdict PASS / FAIL / INCOMPLETE / ERROR (ADVISORY when
        fail_on=none), the blocking findings (severity >= fail_on, each with
        file, line, rule and fix), and a coverage block listing every file
        analysed, every file NOT analysed and why, and lines the parser could
        not model. Only PASS is an all-clear. On ERROR, read `error` and `hint`.
        Rule layer only: routing, NAT and topology are not evaluated.

        path: absolute path of a config file (show running-config, iptables-save,
        PAN-OS set commands, AWS SG JSON...) or a directory of them.
        policy_path: optional segmentation policy JSON. vendor: leave as auto;
        or force ios-asa, nxos, eos, junos, panos, iptables, aws-sg.
        fail_on: critical, high (default), medium, low, none.
        """
        return audit(path, policy_path, vendor, fail_on)

    @server.tool(name="rulehawk_list_findings", title="List findings",
                 annotations=ro)
    def rulehawk_list_findings(path: str, policy_path: str = "",
                               vendor: str = "auto", min_severity: str = "low",
                               kinds: Optional[List[str]] = None,
                               limit: int = DEFAULT_LIMIT) -> dict:
        """List every RuleHawk finding for a config file or directory, worst
        first, each with a stable id, file, line, rule, cited rule, witness
        packet and suggested fix. Filter with min_severity (critical, high,
        medium, low, info; default low) and kinds (e.g. ["dangerous-exposure"];
        see rulehawk_supported_inputs for all kinds). At most `limit` findings
        (default 100); `truncated` says if more exist. Includes the same
        coverage block as rulehawk_audit. path: absolute path, as for
        rulehawk_audit.
        """
        return list_findings(path, policy_path, vendor, min_severity, kinds, limit)

    @server.tool(name="rulehawk_explain_finding", title="Explain a finding",
                 annotations=ro)
    def rulehawk_explain_finding(finding_id: str = "", path: str = "",
                                 kind: str = "", policy_path: str = "",
                                 vendor: str = "auto") -> dict:
        """Explain one finding: pass finding_id (RH-...) AND the same path
        (and policy_path) it came from (path is required with finding_id), and
        get the finding, the source line, what the finding kind means and how
        to fix it. Or pass only kind (e.g. "intent-inversion-deny-dead") for
        the meaning of a finding kind.
        """
        return explain_finding(finding_id, path, kind, policy_path, vendor)

    @server.tool(name="rulehawk_compare", title="Compare before/after configs",
                 annotations=ro)
    def rulehawk_compare(before: str, after: str, policy_path: str = "",
                         vendor: str = "auto", fail_on: str = "high") -> dict:
        """Compare a before (running) and after (candidate) config, both files
        or both directories (paired by relative path), using absolute paths.
        Use this before pushing a change. Returns the findings the change
        introduces, the ones it resolves, the rules it adds, and verdict
        INTRODUCES_RISK / NO_NEW_RISK / INCOMPLETE / ERROR (ADVISORY when
        fail_on=none). Only NO_NEW_RISK is an all-clear. This is a rule-layer
        finding delta, not a forwarding or reachability diff.
        """
        return compare(before, after, policy_path, vendor, fail_on)

    @server.tool(name="rulehawk_supported_inputs", title="Supported inputs",
                 annotations=ro)
    def rulehawk_supported_inputs() -> dict:
        """List the config formats RuleHawk reads, the finding kinds it
        reports, and what it does not model (routing, NAT, topology, some L7).
        """
        return supported_inputs()

    return server


_NO_SDK = (
    "rulehawk-mcp: the MCP SDK is not installed, so the server cannot start.\n"
    "It needs Python 3.10 or newer; this is Python {py}. In a 3.10+ environment:\n"
    '  pip install "rulehawk[mcp] @ git+https://github.com/optimesh-ai/RuleHawk"\n'
    "(On Python 3.9 pip installs the CLI and silently skips the MCP extra.)")


def _sdk_version() -> Optional[str]:
    try:
        import mcp  # noqa: F401
    except ImportError:
        return None
    try:
        from importlib.metadata import version
        return version("mcp")
    except Exception:
        return "unknown"


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "-h" in argv or "--help" in argv:
        print(__doc__.split("DESIGN RULES")[0].rstrip())
        return 0
    if "--version" in argv:
        py = ".".join(str(x) for x in sys.version_info[:3])
        sdk = _sdk_version()
        if sdk is None:
            print(f"rulehawk-mcp {__version__} (Python {py}, MCP SDK not installed)")
            print(_NO_SDK.format(py=py), file=sys.stderr)
            return 2
        print(f"rulehawk-mcp {__version__} (Python {py}, MCP SDK {sdk})")
        return 0
    if argv:
        print(f"rulehawk-mcp: unexpected argument {argv[0]!r} (it takes none; "
              "an MCP client launches it over stdio)", file=sys.stderr)
        return 2
    try:
        server = build_server()
    except ImportError:
        py = ".".join(str(x) for x in sys.version_info[:3])
        print(_NO_SDK.format(py=py), file=sys.stderr)
        return 2
    server.run("stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
