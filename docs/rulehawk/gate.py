"""RuleHawk CI gate — audit many firewall/ACL configs and gate a pull request.

This is the engine behind the RuleHawk GitHub Action. It is a thin, fast,
*deterministic* orchestration layer over the existing analysis IP — it parses
each config with the right vendor frontend, runs the same `analyze` +
`check_segmentation` the CLI runs, then renders the findings in the three forms a
PR gate needs:

  * SARIF 2.1.0          — uploaded to GitHub code scanning so every finding is
                           annotated on the EXACT changed line in the PR diff
                           (this is why the parsers now carry `ACE.line`).
  * a Step Summary       — a markdown report (score, severity table, the witness
                           packets, a per-file breakdown) shown on the run page.
  * a sticky PR comment  — the same report posted once per PR and updated in
                           place, so reviewers see the verdict without leaving
                           the conversation.

and computes a single exit code from a `--fail-on` severity threshold, so the
check goes red exactly when the team decides it should.

DESIGN PRINCIPLES (inherited from the engine):
  * Sound, never noisy. `segmentation-ok` is good news, not a finding — it never
    annotates a line and never fails the build. `segmentation-indeterminate`
    (we could not PROVE isolation) is surfaced honestly at MEDIUM, not hidden.
  * Never a false bill of health. A file that parses to ZERO rules is reported
    as `no_rules_parsed` (status, not a 100/100 score) — the same guarantee the
    CLI gives, generalized across a whole repo.
  * Your config never leaves the runner. Everything runs in-process; the gate
    emits findings and counts, never ships config text anywhere.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .analyze import Finding, analyze, score
from .evidence import Subject, build_evidence, to_evidence_markdown
from .parse import parse_acls
from .parse_iptables import detect as detect_iptables, parse_iptables
from .parse_junos import detect as detect_junos, parse_junos
from .parse_panos import detect as detect_panos, parse_panos
from .parse_nxos import detect as detect_nxos, parse_nxos
from .parse_awssg import detect as detect_awssg, parse_awssg
from .parse_eos import detect as detect_eos, parse_eos
from .segcheck import check_segmentation

# Severity ordering shared by the threshold logic, SARIF level mapping, and the
# report sort. Higher = worse.
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_ORDER = ("critical", "high", "medium", "low", "info")

# Severity -> SARIF result level. Code scanning shows `error` as a failing
# annotation, `warning`/`note` as advisory. `info` findings (segmentation-ok)
# are never emitted to SARIF at all (see _sarif).
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}

# GitHub code-scanning sorts/filters by this numeric CVSS-like band (a documented
# SARIF property GitHub reads). Keeps criticals at the top of the Security tab.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0",
                      "low": "2.0", "info": "0.0"}

_REPO_URL = "https://github.com/optimesh-ai/RuleHawk"

# Per-kind help text for the SARIF rule catalog + summary glossary. The severity
# lives on each Finding; this is the stable, human explanation of the rule class.
_KIND_HELP: Dict[str, str] = {
    "intent-inversion-deny-dead":
        "A deny that never fires because an earlier permit already allows the "
        "same traffic — a silent SECURITY hole: the traffic you meant to block "
        "is allowed.",
    "intent-inversion-permit-dead":
        "A permit that never fires because an earlier deny already drops the "
        "same traffic — a silent CONNECTIVITY loss.",
    "union-shadowed-deny-dead":
        "A deny made unreachable by the cumulative union of earlier permits — "
        "the traffic you meant to block is allowed.",
    "union-shadowed-permit-dead":
        "A permit made unreachable by the cumulative union of earlier denies — "
        "a silent connectivity loss.",
    "redundant":
        "A rule fully covered by an earlier same-action rule — safe to delete.",
    "union-redundant":
        "A rule whose traffic is already fully handled by earlier rules — safe "
        "to delete.",
    "permit-any-any":
        "`permit ip any any` — allows ALL traffic and defeats the ACL.",
    "broad-any-any":
        "A very broad `permit <proto> any any` between any hosts.",
    "dangerous-exposure":
        "A sensitive service (telnet/SMB/RDP/DB/...) permitted from ANY source.",
    "ssh-exposure":
        "SSH permitted from ANY source — fine for a bastion, risky otherwise.",
    "source-port-trust":
        "A permit that matches only the SOURCE port (e.g. `permit tcp any eq "
        "53 any`) — source ports are attacker-controlled, so the rule admits "
        "traffic to every destination port. Match the destination port, or "
        "add `established` if it is return traffic.",
    "segmentation-violation":
        "A declared zone isolation (must_not_reach) is broken: the config "
        "permits a concrete witness packet across the forbidden boundary.",
    "segmentation-indeterminate":
        "Isolation could not be PROVEN — a rule uses an unmodeled form "
        "(neq / complex mask / unresolved group). Review manually.",
    "segmentation-ok":
        "A declared zone isolation holds: no permitted witness flow exists.",
    "segmentation-error":
        "The segmentation policy itself is invalid (unknown zone, bad CIDR or "
        "port) — fail-closed: the affected assertion gets no PASS until fixed.",
    "connectivity-ok":
        "A declared must_reach deployment flow is provably permitted at the "
        "filter layer — reported with a concrete witness packet.",
    "connectivity-broken":
        "A declared must_reach deployment flow (e.g. hosts -> proxy/vendor "
        "egress ranges) is permitted by NO parsed ruleset — the traffic will "
        "be dropped at the filter layer.",
    "connectivity-indeterminate":
        "The must_reach flow could not be proven open OR closed — a rule on "
        "the path uses an unmodeled form. Review manually.",
}


@dataclass
class FileResult:
    """The audit of one config file."""
    path: str                       # path as given (used in SARIF/locations)
    vendor: str                     # ios-asa | junos | panos | iptables | nxos | eos
    status: str                     # ok | no_rules_parsed | error
    n_rules: int
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    line_by_id: Dict[Tuple[str, int], int] = field(default_factory=dict)
    error: str = ""
    # Carried for the evidence artifact: `raw` is the exact bytes read (so the
    # recorded digest is re-hashable), `aces` lets each policy assertion be
    # re-checked per file to attribute a failure to the config that caused it.
    raw: bytes = b""
    aces: List = field(default_factory=list)

    def to_subject(self) -> Subject:
        return Subject(source=self.path, raw=self.raw, vendor=self.vendor,
                       aces=self.aces, findings=self.findings,
                       notes=self.notes, error=self.error)

    @property
    def score(self) -> Optional[int]:
        # No parsed rules => not "clean", just nothing analyzed (mirrors report).
        return score(self.findings) if self.n_rules else None

    def line_of(self, f: Finding) -> int:
        """Best-effort 1-based source line for a finding's rule.

        Lookup order:
          1. line_by_id[(acl, seq)]  — preferred; built from ACE.line at parse time.
          2. Finding.line             — direct fallback when line_by_id misses or
                                       returns 0 (parser did not record a line) or
                                       the rule_id is a zone-pair label rather than
                                       an acl:seq (e.g. segmentation-ok).
          3. 1                        — hard minimum; SARIF requires startLine >= 1.

        Info findings (segmentation-ok) carry zone-pair rule_ids and are excluded
        from SARIF by real_findings, so their fallback is safe."""
        acl_seq = _split_rule_id(f.rule_id)
        if acl_seq is not None and acl_seq in self.line_by_id:
            ln = self.line_by_id[acl_seq]
            if ln > 0:
                return ln
        if f.line > 0:
            return f.line
        return 1


def _split_rule_id(rule_id: str) -> Optional[Tuple[str, int]]:
    """`acl:seq` -> (acl, seq); None for non-rule ids (zone labels like
    `CORP!->PCI`). ACL names never contain a colon, so rsplit is safe."""
    if ":" not in rule_id:
        return None
    acl, _, seq = rule_id.rpartition(":")
    if not seq.isdigit():
        return None
    return acl, int(seq)


# --------------------------------------------------------------------------- #
# vendor selection + per-file audit
# --------------------------------------------------------------------------- #
_VENDORS = {
    "ios": "ios-asa", "asa": "ios-asa", "ios-asa": "ios-asa", "cisco": "ios-asa",
    "junos": "junos", "juniper": "junos",
    "panos": "panos", "paloalto": "panos", "palo-alto": "panos",
    "iptables": "iptables", "netfilter": "iptables",
    "nxos": "nxos", "nx-os": "nxos", "nexus": "nxos",
    "eos": "eos", "arista": "eos",
    "aws": "aws-sg", "aws-sg": "aws-sg", "awssg": "aws-sg",
    "securitygroups": "aws-sg", "security-groups": "aws-sg",
}


def _pick_parser(text: str, vendor: str):
    """Return (vendor_label, parse_fn) for `text`, honoring a forced vendor or
    auto-detecting (same precedence as the CLI)."""
    if vendor and vendor != "auto":
        v = _VENDORS.get(vendor.lower())
        if v == "junos":
            return "junos", parse_junos
        if v == "panos":
            return "panos", parse_panos
        if v == "iptables":
            return "iptables", parse_iptables
        if v == "nxos":
            return "nxos", parse_nxos
        if v == "eos":
            return "eos", parse_eos
        if v == "aws-sg":
            return "aws-sg", parse_awssg
        return "ios-asa", parse_acls
    if detect_junos(text):
        return "junos", parse_junos
    if detect_panos(text):
        return "panos", parse_panos
    if detect_iptables(text):
        return "iptables", parse_iptables
    if detect_awssg(text):
        return "aws-sg", parse_awssg
    if detect_nxos(text):
        return "nxos", parse_nxos
    if detect_eos(text):
        return "eos", parse_eos
    return "ios-asa", parse_acls


def audit_file(path: str, policy: Optional[dict], vendor: str = "auto") -> FileResult:
    """Parse + analyze (+ segment-check) one config file."""
    # Read BYTES so the evidence digest is of the file an auditor can re-hash.
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        return FileResult(path, "?", "error", 0, error=str(e))
    text = raw.decode("utf-8", errors="replace")
    vlabel, parse_fn = _pick_parser(text, vendor)
    aces, notes = parse_fn(text)
    findings = analyze(aces)
    if policy:
        findings += check_segmentation(aces, policy)
    line_by_id = {(a.acl, a.seq): a.line for a in aces}
    status = "ok" if aces else "no_rules_parsed"
    return FileResult(path, vlabel, status, len(aces), findings, notes,
                      line_by_id, raw=raw, aces=aces)


# --------------------------------------------------------------------------- #
# aggregation
# --------------------------------------------------------------------------- #
@dataclass
class GateResult:
    files: List[FileResult]
    fail_on: str

    @property
    def real_findings(self) -> List[Tuple[FileResult, Finding]]:
        """(file, finding) pairs, excluding pure-info good-news (segmentation-ok)."""
        out: List[Tuple[FileResult, Finding]] = []
        for fr in self.files:
            for f in fr.findings:
                if f.severity != "info":
                    out.append((fr, f))
        return out

    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in _SEV_ORDER}
        for _, f in self.real_findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def total_rules(self) -> int:
        return sum(fr.n_rules for fr in self.files)

    @property
    def worst(self) -> str:
        """Highest severity present among real findings, or 'none'."""
        sev = "none"
        rank = -1
        for _, f in self.real_findings:
            r = _SEV_RANK.get(f.severity, 0)   # defensive: unknown severity -> 0
            if r > rank:
                rank, sev = r, f.severity
        return sev

    @property
    def violations(self) -> List[Tuple[FileResult, Finding]]:
        """Findings at or above the fail threshold — what makes the gate red."""
        thr = _SEV_RANK.get(self.fail_on, 99) if self.fail_on != "none" else 99
        if self.fail_on == "none":
            return []
        return [(fr, f) for fr, f in self.real_findings
                if _SEV_RANK.get(f.severity, 0) >= thr]

    @property
    def parse_failures(self) -> List[FileResult]:
        """Files that produced ZERO rules or could not be read. These FAIL CLOSED:
        `check_segmentation([], policy)` would otherwise return an all-PASS (info)
        verdict and a garbled config could masquerade as a clean bill of health —
        the one thing the engine refuses to do. Exit 2, independent of --fail-on
        (except advisory `--fail-on none`)."""
        return [fr for fr in self.files
                if fr.status in ("error", "no_rules_parsed")]

    def exit_code(self) -> int:
        """0 clean · 1 finding at/above threshold · 2 a file failed to parse
        (fail-closed). `--fail-on none` is advisory: it never blocks."""
        if self.fail_on == "none":
            return 0
        if self.parse_failures:
            return 2
        return 1 if self.violations else 0

    @property
    def passed(self) -> bool:
        return self.exit_code() == 0

    @property
    def score(self) -> Optional[int]:
        """Lowest per-file score across files that had rules (the gate is only as
        clean as its worst file); None if nothing parsed anywhere."""
        scored = [fr.score for fr in self.files if fr.score is not None]
        return min(scored) if scored else None


def run_gate(paths: List[str], policy: Optional[dict], fail_on: str = "high",
             vendor: str = "auto") -> GateResult:
    return GateResult([audit_file(p, policy, vendor) for p in paths], fail_on)


# --------------------------------------------------------------------------- #
# file discovery
# --------------------------------------------------------------------------- #
def discover(patterns: List[str]) -> Tuple[List[str], List[str]]:
    """Expand each pattern to a sorted, de-duplicated list of existing files.

    A pattern may be a literal file (kept as-is), a glob (recursive `**`
    supported), or a DIRECTORY (walked recursively for all files — so a natural
    `configs: firewall` works, not only `firewall/**/*`).

    Returns (files, unmatched_patterns). A pattern that matches NOTHING is a
    gate-level error, never silently dropped: a typo'd `configs:` entry would
    otherwise mean that firewall is simply never audited — green check, zero
    coverage."""
    seen: Dict[str, None] = {}
    unmatched: List[str] = []
    for pat in patterns:
        if os.path.isfile(pat):
            seen.setdefault(pat, None)
            continue
        if os.path.isdir(pat):
            hits = [m for m in sorted(glob.glob(os.path.join(pat, "**", "*"),
                                                recursive=True))
                    if os.path.isfile(m)]
        else:
            hits = [m for m in sorted(glob.glob(pat, recursive=True))
                    if os.path.isfile(m)]
        if not hits:
            unmatched.append(pat)
        for m in hits:
            seen.setdefault(m, None)
    return list(seen), unmatched


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #
def _sarif_uri(path: str) -> str:
    """A repo-relative, forward-slash URI for SARIF artifactLocation.

    Relative to $GITHUB_WORKSPACE (the checkout root) when set — the Action may
    run with a `working-directory:` below the root, and a CWD-relative URI would
    then point at a nonexistent repo path, silently detaching every annotation.
    A file OUTSIDE the workspace keeps its absolute path (an escaping `../` URI
    is unmappable either way; absolute is at least unambiguous)."""
    ap = os.path.abspath(path)
    root = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
    try:
        rel = os.path.relpath(ap, root)
    except ValueError:                      # different drive (Windows)
        rel = None
    if rel is None or rel == ".." or rel.startswith(".." + os.sep):
        return ap.replace(os.sep, "/")
    return rel.replace(os.sep, "/")


def _fingerprint(uri: str, f: Finding) -> str:
    """A CONTENT-based stable id for GitHub alert matching. Keyed on what the
    finding IS (file, ACL, kind, normalized rule text, witness) — never on the
    match-order `seq`, which shifts whenever an unrelated rule is inserted above
    and would close-and-reopen every downstream alert on each PR. The witness
    keeps two different boundary breaches on the SAME rule distinct."""
    acl_seq = _split_rule_id(f.rule_id)
    acl = acl_seq[0] if acl_seq else f.rule_id
    rule_text = " ".join(f.rule.split())
    body = "|".join((uri, acl, f.kind, rule_text, f.witness))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]


def to_sarif(gate: GateResult, version: Optional[str] = None) -> str:
    """Render findings as SARIF 2.1.0 for `github/codeql-action/upload-sarif`.

    Info findings (segmentation-ok) are omitted — they are good news, not
    annotations. Every other finding becomes one result located on its exact
    source line, so GitHub renders it inline on the PR diff."""
    if version is None:
        from . import __version__ as version
    rules: List[dict] = []
    rule_index: Dict[str, int] = {}
    results: List[dict] = []
    fp_seen: Dict[str, int] = {}    # occurrence salt: two IDENTICAL rules that are
    for fr, f in gate.real_findings:    # both e.g. `redundant` stay distinct alerts
        if f.kind not in rule_index:
            rule_index[f.kind] = len(rules)
            rules.append({
                "id": f.kind,
                "name": "".join(w.capitalize() for w in f.kind.split("-")),
                "shortDescription": {"text": _KIND_HELP.get(f.kind, f.kind)},
                "fullDescription": {"text": _KIND_HELP.get(f.kind, f.kind)},
                "helpUri": f"{_REPO_URL}#what-it-finds",
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY.get(f.severity, "0.0"),
                    "tags": ["firewall", "segmentation", "network-security"],
                },
            })
        msg = f.message
        if f.witness:
            msg += f"\nWitness packet: {f.witness}"
        if f.cited:
            msg += f"\nCause: {f.cited}"
        if f.fix:
            msg += f"\nFix: {f.fix}"
        line = fr.line_of(f)
        fp = _fingerprint(_sarif_uri(fr.path), f)
        n = fp_seen.get(fp, 0)
        fp_seen[fp] = n + 1
        if n:
            fp = f"{fp}:{n}"
        results.append({
            "ruleId": f.kind,
            "ruleIndex": rule_index[f.kind],
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(fr.path)},
                    "region": {"startLine": line},
                },
            }],
            "partialFingerprints": {
                # Content-based (see _fingerprint): keyed on file/ACL/kind/rule
                # text/witness — never the match-order seq, which shifts on any
                # insertion above and would churn every downstream alert. The
                # witness keeps distinct boundary breaches via the SAME rule as
                # separate alerts (rule_id+kind alone would collapse them).
                "ruleHawk/v2": fp,
            },
        })
    # Fail-closed: a file that parsed to zero rules (or could not be read) must
    # surface in code scanning, never masquerade as clean. One file-level error.
    for fr in gate.parse_failures:
        if "RH-PARSE-000" not in rule_index:
            rule_index["RH-PARSE-000"] = len(rules)
            rules.append({
                "id": "RH-PARSE-000",
                "name": "NoRulesParsed",
                "shortDescription": {"text": "No firewall rules parsed from this file."},
                "fullDescription": {"text": "RuleHawk could not extract any rules "
                                    "from this file — it is NOT a clean bill of "
                                    "health. Check the vendor/format, or force "
                                    "--vendor."},
                "helpUri": f"{_REPO_URL}#vendors",
                "defaultConfiguration": {"level": "error"},
                "properties": {"security-severity": "7.0",
                               "tags": ["firewall", "parse"]},
            })
        detail = (f"could not read file: {fr.error}" if fr.status == "error"
                  else "no rules parsed (failing closed — not a clean bill of health)")
        results.append({
            "ruleId": "RH-PARSE-000",
            "ruleIndex": rule_index["RH-PARSE-000"],
            "level": "error",
            "message": {"text": f"RuleHawk parsed zero rules from "
                                f"{_sarif_uri(fr.path)} — {detail}."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(fr.path)},
                    "region": {"startLine": 1},
                },
            }],
            "partialFingerprints": {
                "ruleHawk/v2": f"{_sarif_uri(fr.path)}:parse-failure",
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RuleHawk",
                "informationUri": _REPO_URL,
                "version": version,
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


# --------------------------------------------------------------------------- #
# JSON (machine aggregate)
# --------------------------------------------------------------------------- #
def to_json(gate: GateResult) -> str:
    return json.dumps({
        "passed": gate.passed,
        "exit_code": gate.exit_code(),
        "fail_on": gate.fail_on,
        "worst_severity": gate.worst,
        "score": gate.score,
        "files_audited": len(gate.files),
        "rules_analyzed": gate.total_rules,
        "findings_by_severity": gate.counts(),
        "violations": len(gate.violations),
        "parse_failures": [fr.path for fr in gate.parse_failures],
        "files": [{
            "path": fr.path,
            "vendor": fr.vendor,
            "status": fr.status,
            "rules_analyzed": fr.n_rules,
            "score": fr.score,
            "error": fr.error,
            "findings": [{
                "rule_id": f.rule_id, "kind": f.kind, "severity": f.severity,
                "line": fr.line_of(f), "message": f.message, "rule": f.rule,
                "cited": f.cited, "fix": f.fix, "witness": f.witness,
            } for f in _sorted(fr.findings)],
            "parse_notes": fr.notes,
        } for fr in gate.files],
    }, indent=2)


# --------------------------------------------------------------------------- #
# Markdown report (Step Summary + PR comment share this body)
# --------------------------------------------------------------------------- #
_COMMENT_MARKER = "<!-- rulehawk-gate -->"   # sticky-comment find/replace anchor

# Brand voice: flat, no decorative emoji (matches the de-vibed Carbon web UI).
# A single ✅/❌ for the binary verdict is kept — it mirrors report.to_text and is
# the universal CI convention. Severities are plain text labels.
_SEV_BADGE = {"critical": "**CRITICAL**", "high": "**HIGH**", "medium": "**MEDIUM**",
              "low": "**LOW**", "info": "**INFO**"}


def _sorted(findings: List[Finding]) -> List[Finding]:
    # Numeric-aware: `EDGE:10` must sort after `EDGE:2`, not before it.
    def key(f: Finding):
        acl_seq = _split_rule_id(f.rule_id)
        acl, seq = acl_seq if acl_seq else (f.rule_id, 0)
        return (-_SEV_RANK.get(f.severity, 0), acl, seq)
    return sorted(findings, key=key)


def to_markdown(gate: GateResult, *, title: str = "RuleHawk firewall gate") -> str:
    """A self-contained markdown report used verbatim as the Step Summary and the
    PR comment body (the comment prepends a hidden marker for sticky updates)."""
    counts = gate.counts()
    pf = gate.parse_failures
    if gate.passed:
        verdict = f"**PASS** — no findings at or above `{gate.fail_on}`."
    elif pf and not gate.violations:
        verdict = (f"**FAIL (fail-closed)** — {len(pf)} file(s) parsed to zero "
                   f"rules. That is not a clean bill of health; the gate blocks "
                   f"rather than assume isolation it could not verify.")
    else:
        extra = (f" plus {len(pf)} unparseable file(s)" if pf else "")
        verdict = (f"**FAIL** — {len(gate.violations)} finding(s) at or above "
                   f"`{gate.fail_on}`{extra} block this change.")
    icon = "✅" if gate.passed else "❌"
    sc = gate.score
    lines: List[str] = []
    lines.append(f"## {icon} {title}")
    lines.append("")
    lines.append(verdict)
    lines.append("")
    # Headline metrics row.
    score_txt = f"{sc}/100" if sc is not None else "—"
    lines.append(f"| Score | Files | Rules | Critical | High | Medium | Low |")
    lines.append(f"|---|---|---|---|---|---|---|")
    lines.append(f"| {score_txt} | {len(gate.files)} | {gate.total_rules} | "
                 f"{counts['critical']} | {counts['high']} | {counts['medium']} | "
                 f"{counts['low']} |")
    lines.append("")

    # Segmentation witnesses get their own callout — the headline value.
    seg = [(fr, f) for fr, f in gate.real_findings
           if f.kind == "segmentation-violation"]
    if seg:
        lines.append("### Segmentation violations")
        lines.append("")
        lines.append("A declared zone boundary is breached. Each row is a concrete "
                     "packet the config **permits** that it must not:")
        lines.append("")
        lines.append("| Witness packet | Where | Fix |")
        lines.append("|---|---|---|")
        for fr, f in seg:
            loc = f"`{_sarif_uri(fr.path)}:{fr.line_of(f)}`"
            lines.append(f"| `{f.witness}` | {loc} | {f.fix} |")
        lines.append("")

    # Per-file breakdown.
    for fr in gate.files:
        real = [f for f in fr.findings if f.severity != "info"]
        ok = [f for f in fr.findings if f.kind == "segmentation-ok"]
        conn_ok = [f for f in fr.findings if f.kind == "connectivity-ok"]
        if fr.status == "error":
            lines.append(f"<details><summary>❌ <code>{_sarif_uri(fr.path)}</code> "
                         f"— ERROR, could not read: {fr.error}</summary></details>")
            lines.append("")
            continue
        if fr.status == "no_rules_parsed":
            lines.append(f"<details><summary>❌ <code>{_sarif_uri(fr.path)}</code> "
                         f"— <b>no rules parsed</b> (not a clean bill of health; check "
                         f"the vendor/format)</summary>")
            lines += _notes_block(fr.notes)
            lines.append("</details>")
            lines.append("")
            continue
        head_icon = "❌" if any(f.severity in ("critical", "high") for f in real) else (
            "·" if real else "✅")
        fscore = f"{fr.score}/100" if fr.score is not None else "—"
        summ = (f"{head_icon} <code>{_sarif_uri(fr.path)}</code> "
                f"<sub>({fr.vendor}, {fr.n_rules} rules, score {fscore}, "
                f"{len(real)} finding(s))</sub>")
        lines.append(f"<details><summary>{summ}</summary>")
        lines.append("")
        if not real:
            lines.append("No hygiene/segmentation findings. ✅")
        for f in _sorted(real):
            lines.append(f"- {_SEV_BADGE.get(f.severity, f.severity)} "
                         f"**{f.kind}** "
                         f"(`{_sarif_uri(fr.path)}:{fr.line_of(f)}`)  ")
            lines.append(f"  `{f.rule}`  ")
            lines.append(f"  {f.message}  ")
            if f.witness:
                lines.append(f"  witness: `{f.witness}`  ")
            if f.cited:
                lines.append(f"  cause: {f.cited}  ")
            if f.fix:
                lines.append(f"  fix: _{f.fix}_  ")
        if ok:
            lines.append("")
            lines.append("Segmentation proven: "
                         + ", ".join(f"`{f.rule_id.replace('!->', ' → ')}`" for f in ok))
        if conn_ok:
            lines.append("")
            lines.append("Connectivity proven (must_reach): "
                         + ", ".join(f"`{f.witness}`" for f in conn_ok))
        if fr.notes:
            lines += _notes_block(fr.notes)
        lines.append("</details>")
        lines.append("")

    lines.append("")
    lines.append(f"<sub>RuleHawk runs entirely inside your runner — your config "
                 f"never leaves your infrastructure. · [docs]({_REPO_URL})</sub>")
    return "\n".join(lines)


def _notes_block(notes: List[str], cap: int = 25) -> List[str]:
    if not notes:
        return []
    out = ["", f"<i>Parse notes ({len(notes)}):</i>", ""]
    for n in notes[:cap]:
        out.append(f"- {n}")
    if len(notes) > cap:
        out.append(f"- …and {len(notes) - cap} more (see `--json`).")
    return out


def comment_body(gate: GateResult) -> str:
    return f"{_COMMENT_MARKER}\n{to_markdown(gate)}"


# --------------------------------------------------------------------------- #
# console (CI log) renderer — concise, greppable
# --------------------------------------------------------------------------- #
def to_console(gate: GateResult) -> str:
    counts = gate.counts()
    sc = gate.score
    out: List[str] = []
    out.append("=" * 68)
    out.append(" RuleHawk CI gate")
    out.append("=" * 68)
    for fr in gate.files:
        if fr.status == "error":
            out.append(f"  [ERROR] {fr.path}: {fr.error}")
            continue
        if fr.status == "no_rules_parsed":
            out.append(f"  [WARN ] {fr.path}: no rules parsed ({fr.vendor})")
            continue
        real = [f for f in fr.findings if f.severity != "info"]
        tag = "FAIL" if any(f.severity in ("critical", "high") for f in real) else (
            "WARN" if real else "ok")
        out.append(f"  [{tag:5}] {fr.path}  ({fr.vendor}, {fr.n_rules} rules, "
                   f"score {fr.score}, {len(real)} findings)")
        for f in _sorted(real):
            out.append(f"            {f.severity.upper():8} {f.kind} "
                       f"@ {os.path.basename(fr.path)}:{fr.line_of(f)}")
            if f.witness:
                out.append(f"                     witness: {f.witness}")
    out.append("-" * 68)
    score_txt = f"{sc}/100" if sc is not None else "n/a"
    out.append(f"  score {score_txt}   "
               + "  ".join(f"{k}:{counts[k]}" for k in ("critical", "high",
                                                        "medium", "low")))
    if gate.passed:
        out.append(f"  VERDICT: PASS (threshold --fail-on {gate.fail_on})")
    elif gate.exit_code() == 2:
        n = len(gate.parse_failures)
        out.append(f"  VERDICT: FAIL (exit 2, fail-closed) — {n} file(s) parsed "
                   f"to zero rules; cannot certify isolation")
    else:
        out.append(f"  VERDICT: FAIL — {len(gate.violations)} finding(s) "
                   f">= {gate.fail_on} (threshold --fail-on {gate.fail_on})")
    out.append("=" * 68)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI:  rulehawk gate [files/globs...] [options]
# --------------------------------------------------------------------------- #
_USAGE = """rulehawk gate — audit firewall/ACL configs and gate a pull request

usage:
  rulehawk gate <file-or-glob>... [options]

options:
  --policy PATH        segmentation policy JSON (zones + must_not_reach)
  --fail-on LEVEL      fail the gate at this severity or worse:
                       critical | high | medium | low | none   (default: high)
  --vendor V           force a vendor for every file (incl. aws-sg):
                       auto | ios | junos | panos | iptables | nxos | eos
                       (default: auto)
  --sarif PATH         write a SARIF 2.1.0 report (for code scanning)
  --summary PATH       write the markdown report ('-' for stdout); defaults to
                       $GITHUB_STEP_SUMMARY when that env var is set
  --comment PATH       write the sticky PR-comment markdown body
  --json PATH          write the machine aggregate ('-' for stdout)
  --evidence PATH      write the compliance-evidence artifact ('-' for stdout):
                       provenance + VERIFIED/FAILED policy attestations +
                       control references, across every config audited
  --evidence-md PATH   the same artifact as a readable markdown document
  -q, --quiet          suppress the console report
  -h, --help           show this help
"""


def _take(argv: List[str], flag: str) -> Optional[str]:
    """Pop `--flag VALUE` from argv; return VALUE or None."""
    if flag in argv:
        k = argv.index(flag)
        if k + 1 >= len(argv):
            print(f"rulehawk gate: {flag} requires a value", file=sys.stderr)
            raise SystemExit(2)
        val = argv[k + 1]
        del argv[k:k + 2]
        return val
    return None


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or "-h" in argv or "--help" in argv:
        print(_USAGE)
        return 0 if argv else 2
    quiet = False
    for q in ("-q", "--quiet"):
        if q in argv:
            quiet = True
            argv.remove(q)
    policy_path = _take(argv, "--policy")
    fail_on = (_take(argv, "--fail-on") or "high").lower()
    vendor = (_take(argv, "--vendor") or "auto").lower()
    sarif_path = _take(argv, "--sarif")
    summary_path = _take(argv, "--summary")
    comment_path = _take(argv, "--comment")
    json_path = _take(argv, "--json")
    evidence_path = _take(argv, "--evidence")
    evidence_md_path = _take(argv, "--evidence-md")

    if fail_on not in ("critical", "high", "medium", "low", "none"):
        print(f"rulehawk gate: bad --fail-on {fail_on!r}", file=sys.stderr)
        return 2
    if vendor != "auto" and vendor not in _VENDORS:
        print(f"rulehawk gate: unknown --vendor {vendor!r} "
              "(choose: auto | ios | junos | panos | iptables | nxos | eos)",
              file=sys.stderr)
        return 2

    # Anything still flag-shaped is an unknown option. Silently dropping it made
    # `--fail-onn low` run at the default threshold with `low` as a (dead) file
    # pattern — the user's intent ignored twice over.
    unknown = [a for a in argv if a.startswith("-") and a != "-"]
    if unknown:
        print(f"rulehawk gate: unknown option(s): {' '.join(unknown)}",
              file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return 2

    patterns = [a for a in argv if not a.startswith("-")]
    if not patterns:
        print("rulehawk gate: no config files/globs given", file=sys.stderr)
        return 2
    paths, unmatched = discover(patterns)
    if unmatched:
        # Fail closed: a pattern matching nothing means a config that is never
        # audited. Do not run a partial gate and call it green.
        print(f"rulehawk gate: no files matched pattern(s): "
              f"{', '.join(unmatched)}", file=sys.stderr)
        return 2
    if not paths:
        print(f"rulehawk gate: no files matched {patterns}", file=sys.stderr)
        return 2

    policy: Optional[dict] = None
    policy_raw: Optional[bytes] = None
    if policy_path:
        try:
            with open(policy_path, "rb") as _pf:
                policy_raw = _pf.read()
            policy = json.loads(policy_raw.decode("utf-8"))
        except (OSError, ValueError) as e:
            print(f"rulehawk gate: cannot read policy {policy_path!r}: {e}",
                  file=sys.stderr)
            return 2

    gate = run_gate(paths, policy, fail_on, vendor)

    # When a machine artifact is written to stdout ('-'), the human console
    # report must NOT interleave with it (that corrupts the JSON/markdown a
    # pipe consumes). Route the console to stderr in that case.
    stdout_machine = "-" in (json_path, summary_path, sarif_path, comment_path)
    if not quiet:
        print(to_console(gate), file=(sys.stderr if stdout_machine else sys.stdout))

    try:
        if sarif_path:
            _write(sarif_path, to_sarif(gate))
        if json_path:
            _emit(json_path, to_json(gate))
        if evidence_path or evidence_md_path:
            art = build_evidence([fr.to_subject() for fr in gate.files],
                                 policy=policy, policy_source=policy_path or "",
                                 policy_raw=policy_raw, generator="ci")
            if evidence_path:
                _emit(evidence_path, json.dumps(art, indent=2))
            if evidence_md_path:
                _emit(evidence_md_path, to_evidence_markdown(art))
        # Step summary: explicit path, else GitHub's env file when present.
        summary_target = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_target:
            _emit(summary_target, to_markdown(gate), append=(summary_path is None))
        if comment_path:
            _write(comment_path, comment_body(gate))
    except OSError as e:
        # An unwritable output path must read as an infra/usage error (2), not
        # as "findings blocked this change" (1) or a traceback.
        print(f"rulehawk gate: cannot write output: {e}", file=sys.stderr)
        return 2

    return gate.exit_code()


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content if content.endswith("\n") else content + "\n")


def _emit(path: str, content: str, append: bool = False) -> None:
    if path == "-":
        print(content)
        return
    with open(path, "a" if append else "w", encoding="utf-8") as fh:
        fh.write(content if content.endswith("\n") else content + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
