"""Compliance-evidence artifact — RuleHawk output an audit/GRC platform can file.

A finding is not evidence. Evidence is a finding plus *provenance* (what was
audited, when, with which tool version) plus a *control reference* (which
framework requirement it speaks to) plus an explicit *positive attestation* for
what passed. GRC platforms and auditors collect screenshots and self-attestations
for network-segmentation controls today; RuleHawk can hand them a concrete
witness packet instead — but only if the output says what it is evidence *of*.

`build_evidence()` returns that artifact (schema `rulehawk.evidence/v1`):

  * subjects    — every config audited: source, SHA-256 of the exact bytes,
                  vendor, rules parsed, status
  * policy      — source + SHA-256 of the policy, if used
  * attestations— one per `must_not_reach` / `must_reach` assertion, aggregated
                  across the whole audited set: VERIFIED / FAILED /
                  INDETERMINATE, naming the subjects that verified it and the
                  ones that failed (with the witness packet)
  * findings    — every finding, annotated with its subject and its controls
  * controls    — the per-control rollup an evidence vault indexes on
  * scope       — the limits, restated inside the artifact so it cannot be read
                  out of context

ONE schema covers every entry point: `rulehawk <cfg> --evidence` is a fleet of
one, `rulehawk gate ... --evidence` is a fleet of many, and the hosted tool is a
fleet of one marked `generator: "hosted"`. A GRC integration writes one parser.

Four honesty rules are load-bearing and must not be relaxed:

1. **A control appears only when we have evidence for it.** We never emit a
   control entry to fill out a framework's checklist.
2. **VERIFIED means we proved something.** Only a passing assertion yields it.
   Absence of findings is not proof — with no policy the artifact makes no
   isolation claim at all and says so.
3. **An unaudited config poisons the fleet claim.** If ANY subject failed to
   parse, no attestation may be VERIFIED: the leak could be in the file we could
   not read. See `_fleet_status`.
4. **The claim is scoped to the rulesets audited**, never to the network. With
   no routing or NAT model, "no audited ruleset permits this flow" is what we
   can prove, so that is exactly what the artifact says.

The control references are informational cross-references to help a reviewer
file the result. RuleHawk is not a certification and no mapping here asserts
that a requirement is *satisfied in full* — most of these requirements cover
ground (NAT, routing, physical topology, process) RuleHawk does not model. See
`SCOPE_LIMITS`.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime
import hashlib
import json
from typing import Dict, List, Optional, Sequence

from .analyze import Finding, score
from .riskaccept import Ledger, accepted_for, evaluate, finalize
from .segcheck import check_segmentation

SCHEMA = "rulehawk.evidence/v1"

# --------------------------------------------------------------------------- #
# frameworks
# --------------------------------------------------------------------------- #
FRAMEWORKS = {
    "PCI-DSS-4.0": "PCI DSS v4.0",
    "NIST-800-53r5": "NIST SP 800-53 Rev. 5",
    "ISO-27001-2022": "ISO/IEC 27001:2022 Annex A",
    "CIS-v8": "CIS Critical Security Controls v8",
    "SOC2-TSC-2017": "AICPA Trust Services Criteria (2017)",
    "HIPAA-SECURITY": "HIPAA Security Rule (45 CFR Part 164 Subpart C)",
}

CONTROL_TITLES = {
    "PCI-DSS-4.0": {
        "1.2.1": "NSC rulesets: configuration standards defined and maintained",
        "1.2.7": "Configurations of NSCs are reviewed at least every six months",
        "1.3.1": "Inbound traffic to the CDE is restricted; all other traffic denied",
        "1.4.1": "NSCs are implemented between trusted and untrusted networks",
        "11.4.5": "Segmentation controls are tested to confirm CDE isolation",
    },
    "NIST-800-53r5": {
        "AC-4": "Information Flow Enforcement",
        "CM-6": "Configuration Settings",
        "CM-7": "Least Functionality",
        "SC-7": "Boundary Protection",
        "SC-7(5)": "Boundary Protection | Deny by Default — Allow by Exception",
        "SC-7(21)": "Boundary Protection | Isolation of System Components",
    },
    "ISO-27001-2022": {
        "A.8.9": "Configuration management",
        "A.8.20": "Networks security",
        "A.8.21": "Security of network services",
        "A.8.22": "Segregation of networks",
    },
    "CIS-v8": {
        "4.4": "Implement and Manage a Firewall on Servers",
        "12.2": "Establish and Maintain a Secure Network Architecture",
        "13.4": "Perform Traffic Filtering Between Network Segments",
    },
    "SOC2-TSC-2017": {
        "CC6.1": "Logical access security over protected information assets",
        "CC6.6": "Logical access controls against threats from outside the boundary",
        "A1.2": "Environmental protections, backup and recovery of availability",
    },
    "HIPAA-SECURITY": {
        "164.312(a)(1)": "Access Control",
        "164.312(e)(1)": "Transmission Security",
    },
}

# Finding kind -> the controls it bears on. Deliberately conservative: a finding
# is mapped only where the requirement is actually about ruleset content or
# network segregation. A finding that costs AVAILABILITY rather than
# confidentiality (a dead permit, a broken required flow) maps to configuration
# management and SOC 2 availability — never to the PCI CDE traffic requirements
# or SOC 2 CC6, which are about restricting access, not preserving it.
_SEGMENTATION = {
    "PCI-DSS-4.0": ["1.3.1", "1.4.1", "11.4.5"],
    "NIST-800-53r5": ["AC-4", "SC-7", "SC-7(21)"],
    "ISO-27001-2022": ["A.8.22"],
    "CIS-v8": ["13.4"],
    "SOC2-TSC-2017": ["CC6.1", "CC6.6"],
    "HIPAA-SECURITY": ["164.312(a)(1)", "164.312(e)(1)"],
}
_OVERLY_PERMISSIVE = {
    "PCI-DSS-4.0": ["1.2.1", "1.3.1"],
    "NIST-800-53r5": ["CM-7", "SC-7(5)"],
    "ISO-27001-2022": ["A.8.20"],
    "CIS-v8": ["4.4", "12.2"],
    "SOC2-TSC-2017": ["CC6.6"],
    "HIPAA-SECURITY": ["164.312(a)(1)"],
}
_EXPOSURE = {
    "PCI-DSS-4.0": ["1.3.1", "1.4.1"],
    "NIST-800-53r5": ["CM-7", "SC-7"],
    "ISO-27001-2022": ["A.8.20", "A.8.21"],
    "CIS-v8": ["4.4"],
    "SOC2-TSC-2017": ["CC6.6"],
    "HIPAA-SECURITY": ["164.312(e)(1)"],
}
_SECURITY_HOLE = {      # a deny that never fires — traffic you meant to block
    "PCI-DSS-4.0": ["1.2.1", "1.3.1"],
    "NIST-800-53r5": ["CM-6", "SC-7"],
    "ISO-27001-2022": ["A.8.20"],
    "CIS-v8": ["12.2"],
    "SOC2-TSC-2017": ["CC6.1"],
}
_AVAILABILITY = {       # silent connectivity loss — a config/availability issue
    "PCI-DSS-4.0": ["1.2.1"],
    "NIST-800-53r5": ["CM-6"],
    "ISO-27001-2022": ["A.8.9"],
    "CIS-v8": ["12.2"],
    "SOC2-TSC-2017": ["A1.2"],
}
_HYGIENE = {            # safe-to-delete cruft — ruleset maintenance only
    "PCI-DSS-4.0": ["1.2.1", "1.2.7"],
    "NIST-800-53r5": ["CM-6"],
    "ISO-27001-2022": ["A.8.9"],
    "CIS-v8": ["12.2"],
}

CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
    # isolation (must_not_reach)
    "segmentation-violation": _SEGMENTATION,
    "segmentation-ok": _SEGMENTATION,
    "segmentation-indeterminate": _SEGMENTATION,
    "segmentation-error": _SEGMENTATION,
    # required connectivity (must_reach) — availability, not confidentiality
    "connectivity-broken": _AVAILABILITY,
    "connectivity-ok": _AVAILABILITY,
    "connectivity-indeterminate": _AVAILABILITY,
    # ruleset content
    "permit-any-any": _OVERLY_PERMISSIVE,
    "broad-any-any": _OVERLY_PERMISSIVE,
    "dangerous-exposure": _EXPOSURE,
    "ssh-exposure": _EXPOSURE,
    "source-port-trust": _EXPOSURE,
    "intent-inversion-deny-dead": _SECURITY_HOLE,
    "union-shadowed-deny-dead": _SECURITY_HOLE,
    "intent-inversion-permit-dead": _AVAILABILITY,
    "union-shadowed-permit-dead": _AVAILABILITY,
    "redundant": _HYGIENE,
    "union-redundant": _HYGIENE,
}

SCOPE_LIMITS = [
    "Layer-3/4 filter layer only: (action, proto, src-net, dst-net, src-port, "
    "dst-port, icmp-type).",
    "NAT is not modeled — address translation must be verified separately.",
    "No routing or topology: each config is an independent first-match context. "
    "A segmentation result therefore covers the rulesets audited, NOT end-to-end "
    "network reachability.",
    "Coverage is exactly the configs listed under `subjects` — a device whose "
    "config was not supplied was not audited and is not covered by any claim "
    "here.",
    "L7/identity (app-ID, source-user), time-range, inactive rules, interface "
    "bindings and fragments are over-approximated and surfaced as notes.",
    "RuleHawk fails closed: a config that parses to zero rules is reported as "
    "no_rules_parsed, never as a clean result, and blocks any VERIFIED "
    "attestation for the run.",
]

# Appended to the scope limits for browser-generated artifacts. In the hosted
# tool the audited input is the text submitted to the page, which the browser
# normalizes (line endings) — so the digest is of exactly what was audited, but
# it need not equal `sha256sum` of an original file on disk. Say so rather than
# let a reader assume file-level provenance the page cannot give.
HOSTED_DIGEST_NOTE = (
    "Generated in-browser: the digest covers the configuration text as "
    "submitted to the page. Because the browser normalizes line endings, it may "
    "differ from `sha256sum` of an original file on disk. For file-level "
    "provenance, run the CLI or the CI gate."
)

DISCLAIMER = (
    "Control references are informational cross-references to assist review. "
    "This artifact is not a certification and does not assert that any "
    "requirement is satisfied in full — the requirements cited cover ground "
    "(NAT, routing, physical topology, process) outside RuleHawk's model. See "
    "`scope.limits`."
)

# Attestation / control status vocabulary.
VERIFIED = "VERIFIED"            # proved across every audited ruleset
FAILED = "FAILED"                # disproved: a concrete witness packet
ACCEPTED_RISK = "ACCEPTED_RISK"  # disproved, but formally accepted and owned
INDETERMINATE = "INDETERMINATE"  # could not decide — never read as a pass
ATTENTION = "ATTENTION"          # mapped findings, but below critical/high
NO_EVIDENCE = "NO_EVIDENCE"      # nothing audited bears on this control

# Per-direction verdict wiring. Isolation proves a NEGATIVE (no permitted flow);
# required connectivity proves a POSITIVE (no denied flow). Both fail closed:
# an indeterminate never upgrades to a pass.
_DIRECTIONS = {
    "must_not_reach": {
        "verb": "cannot reach",
        "ok": "segmentation-ok",
        "bad": "segmentation-violation",
        "unknown": ("segmentation-indeterminate", "segmentation-error"),
        "basis_ok": "no audited ruleset permits this flow",
        "basis_bad": "at least one audited ruleset permits this flow",
    },
    "must_reach": {
        "verb": "must reach",
        "ok": "connectivity-ok",
        "bad": "connectivity-broken",
        "unknown": ("connectivity-indeterminate", "segmentation-error"),
        "basis_ok": "every audited ruleset permits this flow",
        "basis_bad": "at least one audited ruleset denies this flow",
    },
}


@dataclasses.dataclass
class Subject:
    """One config that was audited. `raw` is the exact bytes, so the recorded
    digest is the digest of the file an auditor can re-hash."""
    source: str
    raw: bytes
    vendor: str
    aces: list = dataclasses.field(default_factory=list)
    findings: List[Finding] = dataclasses.field(default_factory=list)
    notes: List[str] = dataclasses.field(default_factory=list)
    error: str = ""

    @property
    def status(self) -> str:
        if self.error:
            return "error"
        return "ok" if self.aces else "no_rules_parsed"

    @property
    def audited(self) -> bool:
        """Did we actually read rules out of this file? A `False` here blocks
        every VERIFIED attestation in the run — see honesty rule 3."""
        return bool(self.aces)

    def to_dict(self) -> dict:
        d = {"source": self.source, "sha256": sha256(self.raw),
             "bytes": len(self.raw), "vendor": self.vendor,
             "rules_parsed": len(self.aces), "status": self.status}
        if self.error:
            d["error"] = self.error
        return d


def tool_version() -> str:
    """The *installed* version when available, so provenance reflects the code
    that actually ran rather than a constant someone forgot to bump."""
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version("rulehawk")
        except PackageNotFoundError:
            pass
    except ImportError:  # pragma: no cover - Python < 3.8
        pass
    from . import __version__
    return __version__


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return (datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
            .isoformat().replace("+00:00", "Z"))


def controls_for(kind: str) -> List[dict]:
    """Controls a finding kind bears on; [] for an unmapped kind (never guessed)."""
    out = []
    for fw, ids in sorted(CONTROL_MAP.get(kind, {}).items()):
        for cid in ids:
            out.append({"framework": fw, "control": cid,
                        "title": CONTROL_TITLES.get(fw, {}).get(cid, "")})
    return out


def control_refs(kind: str) -> List[str]:
    """The same controls as compact `framework:control` references.

    Findings carry refs rather than inlined {framework, control, title} objects:
    every finding of a given kind maps to the identical control set, so inlining
    the titles duplicated them once per finding. On a 1,200-device fleet that
    was 3.8 MB of an artifact whose actual content is 0.3 MB — 82% of every
    finding was a copy of the same requirement text. `control_catalog` resolves
    each ref once.
    """
    return [f"{c['framework']}:{c['control']}" for c in controls_for(kind)]


def _control_catalog(refs) -> Dict[str, dict]:
    """Resolve every ref used anywhere in this artifact, once."""
    out: Dict[str, dict] = {}
    for ref in sorted(set(refs)):
        fw, _, cid = ref.partition(":")
        out[ref] = {"framework": fw, "framework_name": FRAMEWORKS.get(fw, fw),
                    "control": cid,
                    "title": CONTROL_TITLES.get(fw, {}).get(cid, "")}
    return out


def _assertion_claim(a: dict, direction: str) -> str:
    spec = _DIRECTIONS[direction]
    proto = str(a.get("proto") or "ip").lower()
    ports = a.get("ports")
    claim = f"{a.get('src')} {spec['verb']} {a.get('dst')}"
    if proto not in ("ip", "any"):
        claim += f" on {proto}"
        if ports:
            claim += "/" + ",".join(str(p) for p in ports)
    return claim


def _subject_verdict(subject: Subject, zones: dict, assertion: dict,
                     direction: str):
    """(status, witness, detail) for one assertion against one subject.

    Each assertion is re-checked alone so the result attributes to it exactly.
    `check_segmentation` evaluates assertions independently, so splitting is
    equivalent to one combined run — tests/test_evidence.py pins that.
    """
    spec = _DIRECTIONS[direction]
    findings = check_segmentation(
        subject.aces, {"zones": zones, direction: [assertion]})
    kinds = {f.kind: f for f in findings}
    if spec["bad"] in kinds:
        f = kinds[spec["bad"]]
        return FAILED, f.witness, f.message
    for kind in spec["unknown"]:
        if kind in kinds:
            return INDETERMINATE, "", kinds[kind].message
    if spec["ok"] in kinds:
        return VERIFIED, "", kinds[spec["ok"]].message
    # Unreachable today; a fail-closed default so a new segmentation finding
    # kind can never default to VERIFIED.
    return INDETERMINATE, "", "No result produced for this assertion."


def _fleet_status(per_subject: Sequence[dict], all_audited: bool) -> str:
    """Combine per-subject verdicts into the claim for the whole audited set.

    Any single ruleset that breaks the assertion breaks it -> FAILED. Otherwise
    VERIFIED requires that we actually audited everything: a config we could not
    parse might contain the very rule that breaks it, so an unparsed subject
    downgrades the run to INDETERMINATE rather than letting it read as proven.
    That is honesty rule 3, and it is the difference between an artifact an
    auditor can rely on and a checkbox.
    """
    statuses = [p["status"] for p in per_subject]
    if FAILED in statuses:
        return FAILED
    if not all_audited or INDETERMINATE in statuses or not statuses:
        return INDETERMINATE
    # Everything that broke the claim is formally accepted. That is NOT proof of
    # isolation and must never roll up as one — it is an owned, expiring breach.
    if ACCEPTED_RISK in statuses:
        return ACCEPTED_RISK
    return VERIFIED


def build_attestations(subjects: Sequence[Subject],
                       policy: Optional[dict],
                       ledger: Optional[Ledger] = None) -> List[dict]:
    """One attestation per assertion, across all subjects, both directions.

    A per-subject FAILED covered by an in-force exception becomes ACCEPTED_RISK.
    That is NOT a pass: the claim is still disproved, we have merely recorded
    who owns the breach and when the acceptance lapses. `_fleet_status` keeps
    them distinct so a control rollup can never read an accepted risk as
    verified isolation.
    """
    if not policy:
        return []
    zones = policy.get("zones") or {}
    audited = [s for s in subjects if s.audited]
    all_audited = bool(subjects) and len(audited) == len(subjects)
    out = []
    for direction, spec in _DIRECTIONS.items():
        for assertion in (policy.get(direction) or []):
            if not isinstance(assertion, dict):
                continue        # segcheck already reports this as a policy error
            per_subject = []
            for s in audited:
                status, witness, detail = _subject_verdict(
                    s, zones, assertion, direction)
                entry = {"subject": s.source, "status": status,
                         "witness": witness, "detail": detail}
                if status == FAILED and ledger is not None:
                    exc = accepted_for(
                        ledger, spec["bad"], assertion.get("src"),
                        assertion.get("dst"), assertion.get("proto"),
                        assertion.get("ports"), s.source)
                    if exc is not None:
                        entry["status"] = ACCEPTED_RISK
                        entry["accepted"] = {
                            "id": exc.id, "reason": exc.raw.get("reason", ""),
                            "approved_by": exc.raw.get("approved_by", ""),
                            "expires": exc.raw.get("expires", "")}
                per_subject.append(entry)
            status = _fleet_status(per_subject, all_audited)
            failed_on = [p for p in per_subject if p["status"] == FAILED]
            accepted_on = [p for p in per_subject
                           if p["status"] == ACCEPTED_RISK]
            entry = {
                "assertion": assertion,
                "direction": direction,
                "claim": _assertion_claim(assertion, direction),
                "status": status,
                # Say precisely what a pass does and does not mean. Without a
                # routing or NAT model this is the strongest sound phrasing.
                "basis": (spec["basis_ok"] if status == VERIFIED else
                          spec["basis_bad"] if status == FAILED else
                          "broken, but formally accepted as a time-boxed risk — "
                          "isolation is NOT proven"
                          if status == ACCEPTED_RISK else
                          "the audited set was incomplete or could not be decided"),
                "verified_on": [p["subject"] for p in per_subject
                                if p["status"] == VERIFIED],
                "accepted_on": [{"subject": p["subject"],
                                 "witness": p["witness"],
                                 "accepted": p["accepted"]}
                                for p in accepted_on],
                "failed_on": [{"subject": p["subject"], "witness": p["witness"],
                               "detail": p["detail"]} for p in failed_on],
                "indeterminate_on": [{"subject": p["subject"], "detail": p["detail"]}
                                     for p in per_subject
                                     if p["status"] == INDETERMINATE],
                "controls": control_refs(spec["bad"]),
            }
            # The single most useful line for a reader: the concrete packet.
            entry["witness"] = failed_on[0]["witness"] if failed_on else ""
            if not all_audited and status == INDETERMINATE:
                entry["detail"] = (
                    "Not all supplied configs could be parsed, so this claim "
                    "cannot be certified for this run — an unaudited config may "
                    "break it. See subjects with status no_rules_parsed / error.")
            out.append(entry)
    return out


def _control_rollup(findings: Sequence[Finding],
                    attestations: Sequence[dict]) -> List[dict]:
    """Per-control status. A control is emitted ONLY when something we audited
    bears on it — we never pad the artifact with untested requirements."""
    acc: Dict[tuple, dict] = {}

    def slot(fw: str, cid: str) -> dict:
        return acc.setdefault((fw, cid), {
            "framework": fw, "framework_name": FRAMEWORKS.get(fw, fw),
            "control": cid, "title": CONTROL_TITLES.get(fw, {}).get(cid, ""),
            "status": NO_EVIDENCE, "verified": 0, "failed": 0,
            "accepted": 0, "indeterminate": 0, "findings": 0,
        })

    for f in findings:
        # Policy-assertion findings are represented by their attestation below;
        # counting them here too would double-report the same evidence.
        if f.kind.startswith(("segmentation-", "connectivity-")):
            continue
        for c in controls_for(f.kind):
            s = slot(c["framework"], c["control"])
            s["findings"] += 1
            if f.severity in ("critical", "high"):
                s["status"] = FAILED
            elif s["status"] != FAILED:
                s["status"] = ATTENTION
    for a in attestations:
        for ref in a["controls"]:
            fw, _, cid = ref.partition(":")
            s = slot(fw, cid)
            if a["status"] == VERIFIED:
                s["verified"] += 1
                if s["status"] == NO_EVIDENCE:
                    s["status"] = VERIFIED
            elif a["status"] == FAILED:
                s["failed"] += 1
                s["status"] = FAILED
            elif a["status"] == ACCEPTED_RISK:
                # An owned, expiring breach. It must not read as proven
                # isolation, and it must not read as an open failure either.
                s["accepted"] += 1
                if s["status"] != FAILED:
                    s["status"] = ACCEPTED_RISK
            else:
                s["indeterminate"] += 1
                if s["status"] != FAILED:
                    s["status"] = INDETERMINATE
    return [acc[k] for k in sorted(acc, key=lambda k: (k[0], k[1]))]


def build_evidence(subjects: Sequence[Subject], *,
                   policy: Optional[dict] = None,
                   policy_source: str = "", policy_raw: Optional[bytes] = None,
                   generator: str = "cli",
                   generated_at: Optional[str] = None,
                   as_of=None) -> dict:
    """Assemble the evidence artifact for one or many audited configs.

    `generator` records WHERE the artifact came from ("cli", "ci", "hosted").
    This is real audit provenance, not decoration: evidence a CI pipeline
    produced on every merge carries different weight than evidence someone
    generated by hand in a browser, and a reviewer is entitled to tell them
    apart. The hosted path also gets an extra scope line, because there the
    digest covers the text as submitted to the page.
    """
    subjects = list(subjects)
    ledger = finalize_ledger_after(build_attestations, subjects, policy, as_of)
    attestations = ledger[1]
    ledger = ledger[0]
    all_findings = [f for s in subjects for f in s.findings]
    audited = [s for s in subjects if s.audited]
    total_rules = sum(len(s.aces) for s in subjects)
    art = {
        "schema": SCHEMA,
        "tool": {"name": "rulehawk", "version": tool_version(),
                 "generator": generator,
                 "url": "https://github.com/optimesh-ai/RuleHawk"},
        "generated_at": generated_at or utc_now(),
        "coverage": {
            "subjects": len(subjects),
            "subjects_audited": len(audited),
            "subjects_not_audited": len(subjects) - len(audited),
            "complete": len(audited) == len(subjects) and bool(subjects),
            "rules_parsed": total_rules,
        },
        "subjects": [s.to_dict() for s in subjects],
        "result": {
            # Same convention as the JSON report: nothing parsed is not "clean".
            "hygiene_score": (score(all_findings) if total_rules else None),
            "attestations_verified": sum(a["status"] == VERIFIED for a in attestations),
            "attestations_failed": sum(a["status"] == FAILED for a in attestations),
            "attestations_accepted": sum(
                a["status"] == ACCEPTED_RISK for a in attestations),
            "attestations_indeterminate": sum(
                a["status"] == INDETERMINATE for a in attestations),
            "findings_total": len(all_findings),
        },
        "attestations": attestations,
        # Risk acceptance is reported as prominently as failure — never as an
        # absence. An assessor must be able to read exactly what was accepted,
        # by whom, and when the acceptance lapses.
        "accepted_risks": ledger.to_dict(),
        "findings": [
            {"subject": s.source, "rule_id": f.rule_id, "kind": f.kind,
             "severity": f.severity, "message": f.message, "rule": f.rule,
             "cited": f.cited, "fix": f.fix, "witness": f.witness,
             "accepted": f.accepted, "controls": control_refs(f.kind)}
            for s in subjects for f in s.findings
        ],
        "controls": _control_rollup(all_findings, attestations),
        "frameworks": copy.deepcopy(FRAMEWORKS),
        # Every `controls` ref used above, resolved once.
        "control_catalog": _control_catalog(
            [r for a in attestations for r in a["controls"]]
            + [r for s in subjects for f in s.findings
               for r in control_refs(f.kind)]),
        "scope": {"limits": list(SCOPE_LIMITS) + (
            [HOSTED_DIGEST_NOTE] if generator == "hosted" else []),
            "disclaimer": DISCLAIMER},
        "parse_notes": [{"subject": s.source, "note": n}
                        for s in subjects for n in s.notes],
    }
    if policy is not None:
        art["policy"] = {
            "source": policy_source,
            "sha256": sha256(policy_raw) if policy_raw is not None else "",
            "zones": sorted((policy.get("zones") or {}).keys()),
            "assertions": sum(len(policy.get(d) or []) for d in _DIRECTIONS),
        }
    else:
        # State the absence explicitly: with no policy there are no isolation
        # attestations, and a reader must not infer isolation from silence.
        art["policy"] = None
        art["scope"]["note"] = (
            "No segmentation policy was supplied, so this artifact makes NO "
            "isolation claim. Supply a policy with `must_not_reach` assertions "
            "to produce VERIFIED segmentation attestations.")
    return art


def finalize_ledger_after(build_fn, subjects, policy, as_of):
    """Evaluate the exception ledger, build attestations against it, then mark
    in-force exceptions that matched nothing as unused. Returns (ledger,
    attestations) — the order matters: `unused` is only knowable after every
    finding has been offered to the ledger."""
    ledger = evaluate(policy, as_of)
    attestations = build_fn(subjects, policy, ledger)
    return finalize(ledger), attestations


def to_evidence_json(*args, **kwargs) -> str:
    return json.dumps(build_evidence(*args, **kwargs), indent=2, sort_keys=False)


# --------------------------------------------------------------------------- #
# human-readable rendering — the auditor does not read JSON
# --------------------------------------------------------------------------- #
_STATUS_MARK = {VERIFIED: "PASS", FAILED: "FAIL", INDETERMINATE: "UNKNOWN",
                ACCEPTED_RISK: "ACCEPTED", ATTENTION: "REVIEW",
                NO_EVIDENCE: "—"}


# Rendering caps for a fleet-scale document. NEVER a silent truncation: every
# capped list says how many were elided and where the complete data lives (the
# JSON artifact is always complete). A 1,200-row table is not a document a
# reviewer reads — it is one they close.
_ROW_CAP = 25


def _capped(rows: List[str], total: int, what: str) -> List[str]:
    if total <= _ROW_CAP:
        return rows
    return rows + [f"| … and {total - _ROW_CAP} more {what} "
                   f"| | | | (see the JSON artifact) |"]


def _cell(text: str) -> str:
    """Escape a value for a markdown table cell. Real control titles contain
    pipes — NIST's "Boundary Protection | Isolation of System Components" —
    which silently split the row into an extra column and corrupt the table."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_evidence_markdown(art: dict, *, title: str = "Segmentation evidence") -> str:
    """Render an artifact as a document a compliance reviewer can actually read
    and attach to an audit package. Same content as the JSON, no new claims."""
    cov, res = art["coverage"], art["result"]
    out: List[str] = [f"# {title}", ""]
    out.append(f"**Generated** {art['generated_at']} · "
               f"**Tool** {art['tool']['name']} {art['tool']['version']} "
               f"({art['tool'].get('generator', 'cli')})")
    out.append("")

    # Verdict up front — the reader should not have to hunt for it.
    if res["attestations_failed"]:
        verdict = f"**FAIL — {res['attestations_failed']} claim(s) disproved.**"
    elif res.get("attestations_accepted"):
        verdict = (f"**ACCEPTED RISK — {res['attestations_accepted']} claim(s) "
                   f"are broken but formally accepted. Isolation is NOT "
                   f"proven for those.**")
    elif res["attestations_indeterminate"]:
        verdict = (f"**INCOMPLETE — {res['attestations_indeterminate']} claim(s) "
                   f"could not be decided. Nothing is proven for those.**")
    elif res["attestations_verified"]:
        verdict = f"**PASS — {res['attestations_verified']} claim(s) verified.**"
    else:
        verdict = "**No policy claims** — no segmentation policy was supplied."
    out += [verdict, ""]

    out.append(f"Audited **{cov['subjects_audited']} of {cov['subjects']}** "
               f"config(s), {cov['rules_parsed']} rules.")
    if not cov["complete"]:
        out.append("")
        out.append("> **Coverage is incomplete.** One or more supplied configs "
                   "could not be parsed, so no claim in this report is marked "
                   "verified — an unaudited config may break it.")
    out.append("")

    if art["attestations"]:
        out += ["## Policy claims", "",
                "| Claim | Result | Evidence |", "|---|---|---|"]
        for a in art["attestations"]:
            ev = f"`{_cell(a['witness'])}`" if a["witness"] else _cell(a["basis"])
            out.append(f"| {_cell(a['claim'])} | "
                       f"**{_STATUS_MARK[a['status']]}** | {ev} |")
        out.append("")
        for a in art["attestations"]:
            if a["status"] == FAILED:
                out.append(f"**{_cell(a['claim'])} — FAILED on "
                           f"{len(a['failed_on'])} config(s):**")
                out.append("")
                for f in a["failed_on"]:
                    detail = (f"permits `{_cell(f['witness'])}`" if f["witness"]
                              else _cell(f["detail"]))
                    out.append(f"- `{_cell(f['subject'])}` {detail}")
                out.append("")

    acc = art.get("accepted_risks") or {}
    accepted_claims = [a for a in art["attestations"]
                       if a["status"] == ACCEPTED_RISK]
    if accepted_claims or acc.get("expired") or acc.get("invalid") or acc.get("unused"):
        out += ["## Accepted risk", "",
                f"Exceptions evaluated on **{acc.get('evaluated_on', '?')}**: "
                f"{acc.get('applied', 0)} in force, {acc.get('expired', 0)} "
                f"expired, {acc.get('invalid', 0)} invalid, "
                f"{acc.get('unused', 0)} unused.", ""]
    if accepted_claims:
        out += ["These claims are **broken**. They are not failures of this run "
                "only because a named owner accepted the risk, and each "
                "acceptance expires.", "",
                "| Ticket | Claim | Configs | Accepted by | Expires |",
                "|---|---|---|---|---|"]
        # Grouped by TICKET, not by device: one risk acceptance covering 33
        # devices is one decision a risk committee made, not 33 rows to scroll.
        grouped: Dict[tuple, List[str]] = {}
        for a in accepted_claims:
            for e in a["accepted_on"]:
                d = e["accepted"]
                key = (d["id"], a["claim"], d["approved_by"], d["expires"])
                grouped.setdefault(key, []).append(e["subject"])
        for (tid, claim, who, exp), subs in sorted(grouped.items()):
            shown = ", ".join(f"`{_cell(x)}`" for x in sorted(subs)[:3])
            if len(subs) > 3:
                shown += f" +{len(subs) - 3} more"
            out.append(f"| {_cell(tid)} | {_cell(claim)} | {len(subs)}: {shown} "
                       f"| {_cell(who)} | {_cell(exp)} |")
        out.append("")
    lapsed = [e for e in acc.get("exceptions", [])
              if e["status"] in ("expired", "invalid")]
    if lapsed:
        out += ["**Exceptions that did NOT suppress anything** (the underlying "
                "finding is enforced):", ""]
        for e in lapsed:
            out.append(f"- `{_cell(e['id'])}` — {_cell(e['status'])}: "
                       f"{_cell(e.get('detail', ''))}")
        out.append("")

    if art["controls"]:
        out += ["## Control references", "",
                "| Framework | Control | Requirement | Result |", "|---|---|---|---|"]
        for c in art["controls"]:
            out.append(f"| {_cell(c['framework'])} | `{_cell(c['control'])}` "
                       f"| {_cell(c['title'])} "
                       f"| {_STATUS_MARK.get(c['status'], c['status'])} |")
        out.append("")

    out += ["## Configs audited", "",
            "| Config | Vendor | Rules | SHA-256 | Status |", "|---|---|---|---|---|"]
    # Anything not "ok" is shown first and never elided — a config that failed to
    # parse is the single most important row here, because it is why a claim
    # could not be verified.
    subjects = sorted(art["subjects"], key=lambda x: (x["status"] == "ok",
                                                      x["source"]))
    rows = [f"| `{_cell(x['source'])}` | {_cell(x['vendor'])} "
            f"| {x['rules_parsed']} | `{x['sha256'][7:19]}…` "
            f"| {_cell(x['status'])} |" for x in subjects[:_ROW_CAP]]
    out += _capped(rows, len(subjects), "config(s)")
    out += ["", "Digests are of the exact bytes audited — re-hash a file with "
                "`sha256sum` to confirm this report describes it.", ""]

    if art["policy"]:
        out += [f"**Policy** `{_cell(art['policy']['source'])}` "
                f"(`{art['policy']['sha256'][7:19]}…`), "
                f"{art['policy']['assertions']} assertion(s) over zones "
                f"{', '.join(art['policy']['zones'])}.", ""]

    out += ["## Scope and limits", ""]
    out += [f"- {lim}" for lim in art["scope"]["limits"]]
    if art["scope"].get("note"):
        out += ["", f"> {art['scope']['note']}"]
    out += ["", f"_{art['scope']['disclaimer']}_", ""]
    return "\n".join(out)
