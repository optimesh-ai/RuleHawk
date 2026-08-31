"""Time-boxed, accountable risk acceptance.

This is the mechanism that decides whether a large organization keeps the gate
switched on — and it is also the mechanism most likely to be abused into a mute
button. Every test here defends one of the five rules that make it a control:
nothing disappears, expiry is enforced, accountability is mandatory, anything
unparseable fails closed, and dead exceptions are surfaced.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.evidence import (ACCEPTED_RISK, FAILED, VERIFIED, Subject,  # noqa: E402
                               build_evidence, to_evidence_markdown)
from rulehawk.riskaccept import (APPLIED, EXPIRED, INVALID, UNUSED,  # noqa: E402
                                 apply_to_findings, evaluate, finalize)
from rulehawk.segcheck import check_segmentation  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TODAY = datetime.date(2026, 6, 15)

_LEAK = ("ip access-list extended EDGE\n"
         " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 1433\n"
         " deny ip any any\n")

_ZONES = {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]}
_CLAIM = {"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [1433]}


def _exc(**over):
    e = {"id": "RISK-1", "claim": dict(_CLAIM), "reason": "documented reason",
         "approved_by": "owner@acme.com", "expires": "2027-01-01"}
    e.update(over)
    return e


def _policy(*exceptions, assertion=None):
    return {"zones": _ZONES,
            "must_not_reach": [assertion or dict(_CLAIM)],
            "exceptions": list(exceptions)}


def _run(policy, cfg=_LEAK, subject="edge.txt", as_of=_TODAY):
    aces, _ = parse_acls(cfg)
    findings = check_segmentation(aces, policy)
    ledger = evaluate(policy, as_of)
    findings = apply_to_findings(findings, ledger, subject)
    finalize(ledger)
    return findings, ledger


# --------------------------------------------------------------------------- #
# rule 1 — nothing disappears
# --------------------------------------------------------------------------- #
def test_an_accepted_finding_is_not_deleted_or_downgraded():
    findings, _ = _run(_policy(_exc()))
    viol = next(f for f in findings if f.kind == "segmentation-violation")
    assert viol.severity == "critical", "severity must not be quietly lowered"
    assert viol.witness, "the witness packet must survive acceptance"
    assert viol.accepted["id"] == "RISK-1"
    assert viol.accepted["approved_by"] == "owner@acme.com"


def test_acceptance_records_who_why_and_until_when():
    findings, _ = _run(_policy(_exc()))
    acc = next(f for f in findings if f.accepted).accepted
    assert set(acc) == {"id", "reason", "approved_by", "expires"}
    assert all(acc[k] for k in acc), "an empty accountability field is useless"


def test_an_accepted_claim_is_never_verified():
    """We did not prove isolation; we recorded that someone owns the breach."""
    art = _evidence(_policy(_exc()))
    a = art["attestations"][0]
    assert a["status"] == ACCEPTED_RISK
    assert a["status"] != VERIFIED
    assert "NOT proven" in a["basis"]


def test_control_rollup_does_not_read_acceptance_as_a_pass():
    art = _evidence(_policy(_exc()))
    pci = next(c for c in art["controls"] if c["control"] == "11.4.5")
    assert pci["status"] == ACCEPTED_RISK
    assert pci["accepted"] == 1 and pci["verified"] == 0


# --------------------------------------------------------------------------- #
# rule 2 — expiry is enforced
# --------------------------------------------------------------------------- #
def test_an_expired_acceptance_does_not_suppress():
    findings, ledger = _run(_policy(_exc(expires="2025-01-01")))
    viol = next(f for f in findings if f.kind == "segmentation-violation")
    assert viol.accepted is None, "a lapsed acceptance must enforce again"
    assert ledger.entries[0].status == EXPIRED


def test_the_gate_re_arms_on_the_day_the_acceptance_lapses():
    """The same config and the same policy, one day either side of expiry."""
    policy = _policy(_exc(expires="2026-06-15"))
    day_of, _ = _run(policy, as_of=datetime.date(2026, 6, 15))
    day_after, _ = _run(policy, as_of=datetime.date(2026, 6, 16))
    assert next(f for f in day_of if f.kind == "segmentation-violation").accepted
    assert not next(f for f in day_after
                    if f.kind == "segmentation-violation").accepted


def test_an_expired_exception_is_reported_but_does_not_double_count():
    """The underlying finding is already enforced at its own severity; a second
    high here would report one risk twice."""
    _, ledger = _run(_policy(_exc(expires="2025-01-01")))
    problem = next(p for p in ledger.problems if p.kind == "exception-expired")
    assert problem.severity == "info"
    assert "lapsed" in problem.message.lower()


# --------------------------------------------------------------------------- #
# rule 3 — accountability is mandatory
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field", ["id", "reason", "approved_by", "expires"])
def test_an_exception_missing_accountability_does_not_apply(field):
    findings, ledger = _run(_policy(_exc(**{field: ""})))
    assert next(f for f in findings
                if f.kind == "segmentation-violation").accepted is None
    assert ledger.entries[0].status == INVALID
    assert field in ledger.entries[0].detail


def test_an_invalid_exception_is_high_severity():
    """It looks like protection and gives none — the gate must go red."""
    _, ledger = _run(_policy(_exc(approved_by="")))
    problem = next(p for p in ledger.problems if p.kind == "exception-invalid")
    assert problem.severity == "high"
    assert "mute button" in problem.message


# --------------------------------------------------------------------------- #
# rule 4 — anything unparseable fails closed
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", [
    {"expires": "31/12/2027"}, {"expires": "2027-13-45"}, {"expires": "soon"},
    {"expires": "2027-01-01T00:00:00Z"},
    {"claim": {}}, {"claim": "CORP->PCI"}, {"claim": {"src": "CORP"}},
])
def test_malformed_exceptions_never_suppress(bad):
    findings, ledger = _run(_policy(_exc(**bad)))
    assert next(f for f in findings
                if f.kind == "segmentation-violation").accepted is None
    assert ledger.entries[0].status == INVALID


def test_a_non_object_exception_entry_is_invalid_not_a_crash():
    findings, ledger = _run(_policy("just make it green"))
    assert next(f for f in findings
                if f.kind == "segmentation-violation").accepted is None
    assert ledger.entries[0].status == INVALID


def test_an_exception_for_a_different_claim_does_not_apply():
    """The accepted risk must be the one the approver actually read."""
    for other in ({"src": "DMZ", "dst": "PCI", "proto": "tcp", "ports": [1433]},
                  {"src": "CORP", "dst": "OT", "proto": "tcp", "ports": [1433]},
                  {"src": "CORP", "dst": "PCI", "proto": "udp", "ports": [1433]},
                  {"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [3389]}):
        findings, _ = _run(_policy(_exc(claim=other)))
        assert next(f for f in findings
                    if f.kind == "segmentation-violation").accepted is None, other


def test_a_portless_exception_covers_every_port_of_that_protocol():
    """"We accept CORP->PCI on tcp" is a real, broader decision — allowed, but
    only because it is MORE explicit, not less."""
    findings, _ = _run(_policy(_exc(
        claim={"src": "CORP", "dst": "PCI", "proto": "tcp"})))
    assert next(f for f in findings if f.kind == "segmentation-violation").accepted


def test_a_narrow_exception_does_not_cover_a_broader_assertion():
    """An exception for :1433 must not waive an assertion covering every port."""
    policy = _policy(_exc(claim={"src": "CORP", "dst": "PCI", "proto": "tcp",
                                 "ports": [1433]}),
                     assertion={"src": "CORP", "dst": "PCI", "proto": "tcp"})
    findings, _ = _run(policy)
    assert next(f for f in findings
                if f.kind == "segmentation-violation").accepted is None


def test_subject_scoping_limits_an_exception_to_named_configs():
    policy = _policy(_exc(subjects=["other.txt"]))
    assert next(f for f in _run(policy, subject="edge.txt")[0]
                if f.kind == "segmentation-violation").accepted is None
    policy = _policy(_exc(subjects=["edge.txt"]))
    assert next(f for f in _run(policy, subject="firewall/edge.txt")[0]
                if f.kind == "segmentation-violation").accepted


# --------------------------------------------------------------------------- #
# rule 5 — dead exceptions are surfaced
# --------------------------------------------------------------------------- #
def test_an_exception_that_matches_nothing_is_reported_unused():
    clean = "ip access-list extended EDGE\n deny ip any any\n"
    _, ledger = _run(_policy(_exc()), cfg=clean)
    assert ledger.entries[0].status == UNUSED
    assert any(p.kind == "exception-unused" for p in ledger.problems)


def test_an_applied_exception_is_not_reported_unused():
    _, ledger = _run(_policy(_exc()))
    assert ledger.entries[0].status == APPLIED
    assert not any(p.kind == "exception-unused" for p in ledger.problems)


# --------------------------------------------------------------------------- #
# the artifact reports acceptance as prominently as failure
# --------------------------------------------------------------------------- #
def _evidence(policy, cfg=_LEAK, as_of=_TODAY):
    aces, notes = parse_acls(cfg)
    findings = analyze(aces) + check_segmentation(aces, policy)
    subj = Subject(source="edge.txt", raw=cfg.encode(), vendor="ios-asa",
                   aces=aces, findings=findings, notes=notes)
    return build_evidence([subj], policy=policy, as_of=as_of)


def test_the_artifact_publishes_the_exception_ledger():
    art = _evidence(_policy(_exc(), _exc(id="RISK-2", expires="2025-01-01")))
    led = art["accepted_risks"]
    assert led["applied"] == 1 and led["expired"] == 1
    assert led["evaluated_on"] == _TODAY.isoformat()
    assert {e["id"] for e in led["exceptions"]} == {"RISK-1", "RISK-2"}


def test_the_document_states_the_claim_is_broken_not_passing():
    md = to_evidence_markdown(_evidence(_policy(_exc())))
    assert "ACCEPTED RISK" in md
    assert "broken" in md
    assert "**PASS" not in md
    assert "RISK-1" in md and "owner@acme.com" in md and "2027-01-01" in md


def test_the_document_shows_lapsed_exceptions_did_not_suppress():
    md = to_evidence_markdown(_evidence(_policy(_exc(expires="2025-01-01"))))
    assert "did NOT suppress" in md
    assert "**FAIL" in md, "the underlying claim must be reported as failed"


def test_evidence_is_deterministic_for_a_given_as_of():
    a = _evidence(_policy(_exc()))
    b = _evidence(_policy(_exc()))
    a.pop("generated_at"), b.pop("generated_at")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --------------------------------------------------------------------------- #
# end-to-end: the gate verdict
# --------------------------------------------------------------------------- #
def _gate(tmp_path, policy, cfg=_LEAK):
    (tmp_path / "edge.txt").write_text(cfg)
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(policy))
    return subprocess.run(
        [sys.executable, "-m", "rulehawk", "gate", str(tmp_path / "*.txt"),
         "--policy", str(pol), "--fail-on", "high", "-q"],
        cwd=_ROOT, capture_output=True, text=True)


def test_gate_is_red_without_an_exception(tmp_path):
    assert _gate(tmp_path, _policy()).returncode == 1


def test_gate_is_green_with_an_in_force_acceptance(tmp_path):
    """The whole point: a documented, owned, expiring risk stops blocking."""
    assert _gate(tmp_path, _policy(_exc())).returncode == 0


def test_gate_is_red_again_once_the_acceptance_expires(tmp_path):
    assert _gate(tmp_path, _policy(_exc(expires="2025-01-01"))).returncode == 1


def test_gate_is_red_when_an_exception_is_unaccountable(tmp_path):
    """Fail closed: an anonymous exception must not buy a green build."""
    assert _gate(tmp_path, _policy(_exc(approved_by=""))).returncode == 1


def test_gate_still_reports_the_accepted_finding(tmp_path):
    """Green must not mean invisible."""
    (tmp_path / "edge.txt").write_text(_LEAK)
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(_policy(_exc())))
    proc = subprocess.run(
        [sys.executable, "-m", "rulehawk", "gate", str(tmp_path / "*.txt"),
         "--policy", str(pol), "--fail-on", "high"],
        cwd=_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "segmentation-violation" in proc.stdout
