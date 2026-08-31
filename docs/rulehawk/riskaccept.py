"""Time-boxed, accountable risk acceptance — the reason an enterprise keeps the
gate switched on.

THE PROBLEM THIS SOLVES. Point a segmentation gate at a real estate of firewalls
for the first time and it goes red immediately: a 300-device fleet in our own
scale test produced 62 CRITICAL segmentation violations on day one, every one of
them pre-existing and none of them introduced by the pull request being gated. A
gate that is red on day one and stays red is not a gate — teams route around it,
set `--fail-on none`, or delete the workflow. That is how security gating dies in
large organizations, and it is a product problem, not a user problem.

Every tool eventually grows a mute button for this. Almost all of them grow the
WRONG one: an ignore-list that makes the finding vanish, with no owner, no
reason, and no end date. The suppressed risk is then invisible to exactly the
audience — an assessor, a risk committee — that the tool exists to inform.

THE HONEST VERSION. An exception here never deletes anything. It converts a
finding into a recorded, attributed, EXPIRING risk acceptance that the evidence
artifact reports as prominently as a failure:

  {"exceptions": [
    {"id":          "RISK-4471",
     "claim":       {"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [1433]},
     "subjects":    ["firewall/dc-core-asa.txt"],     // optional; omit = fleet-wide
     "reason":      "Reporting server requires SQL to the CDE. Compensating "
                    "control: jump-host allowlist + query audit (SEC-88).",
     "approved_by": "jane.doe@acme.com",
     "expires":     "2026-12-31"}]}

Five rules make it a control rather than a mute button. Each is enforced here and
pinned by tests:

1. **Nothing disappears.** An accepted finding keeps its kind, its witness packet
   and its original severity; it gains an `accepted` record. The artifact carries
   an `accepted_risks` section, and a claim covered only by acceptances is
   reported `ACCEPTED_RISK` — never `VERIFIED`. We did not prove isolation; we
   recorded that someone owns the breach.

2. **Expiry is mandatory and enforced.** No `expires`, or a date in the past, and
   the exception DOES NOT APPLY — the finding fails again and the gate goes red
   by itself. Time-boxing is what makes this an acceptance and not a permanent
   hole, and it is the one thing a suppression list can never do.

3. **Accountability is mandatory.** Missing `id`, `reason` or `approved_by` makes
   the exception INVALID: it does not apply, and it is reported as a policy
   error. An anonymous exception is indistinguishable from a mute button.

4. **Fail closed on anything unparseable.** A malformed date, a non-object entry,
   a claim that does not name zones — none of them suppress anything.

5. **Dead exceptions are surfaced.** An exception matching no finding is reported
   as unused, so the list gets pruned instead of accreting forever.

Evaluation is deterministic given `as_of` (defaulting to today, and always
recorded in the artifact), so the same inputs on the same date produce the same
verdict — including in a resumed CI run.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
from typing import Dict, List, Optional, Sequence, Tuple

from .analyze import Finding

# Status of one exception after evaluation.
APPLIED = "applied"        # matched at least one finding and is in force
EXPIRED = "expired"        # past its expiry -> did NOT suppress anything
INVALID = "invalid"        # missing accountability fields / unparseable
UNUSED = "unused"          # well-formed and in force, but matched nothing

_REQUIRED = ("id", "reason", "approved_by", "expires")

# Kinds an exception may cover. Deliberately limited to POLICY-claim failures:
# these are the ones an organization formally accepts through a risk process. A
# hygiene finding (a redundant rule) is fixed, not accepted, and a blanket
# mechanism for suppressing any finding would be the mute button this module
# exists to avoid.
ACCEPTABLE_KINDS = frozenset({"segmentation-violation", "connectivity-broken"})


def today() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def _parse_date(value) -> Optional[datetime.date]:
    """Strict ISO `YYYY-MM-DD`. Anything else is unparseable — and an exception
    whose expiry we cannot read must not suppress a critical finding."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}",
                                                      value.strip()):
        return None
    try:
        return datetime.date.fromisoformat(value.strip())
    except ValueError:
        return None


def _norm_ports(value) -> Optional[frozenset]:
    """None = 'every port' (a portless claim). Otherwise the exact port set."""
    if value is None:
        return None
    if isinstance(value, (int, str)):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return frozenset()
    out = set()
    for p in value:
        try:
            out.add(int(p))
        except (TypeError, ValueError):
            continue
    return frozenset(out)


@dataclasses.dataclass
class Exception_:
    """One evaluated exception."""
    raw: dict
    status: str
    detail: str = ""
    matched: int = 0

    @property
    def id(self) -> str:
        return str(self.raw.get("id") or "(no id)")

    def to_dict(self) -> dict:
        d = {"id": self.id, "status": self.status, "matched": self.matched,
             "reason": self.raw.get("reason", ""),
             "approved_by": self.raw.get("approved_by", ""),
             "expires": self.raw.get("expires", ""),
             "claim": self.raw.get("claim", {}),
             "subjects": self.raw.get("subjects") or []}
        if self.detail:
            d["detail"] = self.detail
        return d


def _validate(entry, as_of: datetime.date) -> Tuple[str, str]:
    """(status, detail) for a single exception BEFORE matching."""
    if not isinstance(entry, dict):
        return INVALID, f"exception entry is not an object: {entry!r}"
    missing = [k for k in _REQUIRED if not str(entry.get(k) or "").strip()]
    if missing:
        return INVALID, (
            f"missing required field(s) {', '.join(missing)} — an exception "
            f"without an owner, a reason and an expiry date is a mute button, "
            f"not a risk acceptance, so it does NOT apply")
    claim = entry.get("claim")
    if not isinstance(claim, dict) or not claim.get("src") or not claim.get("dst"):
        return INVALID, ("`claim` must be an object naming `src` and `dst` "
                         "zones — this exception does NOT apply")
    expires = _parse_date(entry.get("expires"))
    if expires is None:
        return INVALID, (f"unparseable `expires` {entry.get('expires')!r} "
                         f"(want YYYY-MM-DD) — this exception does NOT apply")
    if expires < as_of:
        return EXPIRED, (f"expired on {expires.isoformat()} (evaluated "
                         f"{as_of.isoformat()}) — the acceptance has lapsed and "
                         f"the finding is enforced again")
    return APPLIED, ""


def _claim_key(src, dst, proto, ports) -> tuple:
    proto = str(proto or "ip").lower()
    if proto == "any":
        proto = "ip"
    return (str(src), str(dst), proto, _norm_ports(ports))


def _covers(exc_claim: dict, src: str, dst: str, proto: str,
            ports) -> bool:
    """Does this exception's claim cover the assertion (src, dst, proto, ports)?

    Matching is EXACT on zones and protocol. Ports are covered when the
    exception's port set is a superset of the assertion's — a portless exception
    (no `ports`) covers every port for that protocol, which is what "we accept
    CORP->PCI on tcp" means. An exception can never widen to a different zone
    pair or protocol: the whole point is that the accepted risk is the one the
    approver actually read.
    """
    e_src, e_dst, e_proto, e_ports = _claim_key(
        exc_claim.get("src"), exc_claim.get("dst"),
        exc_claim.get("proto"), exc_claim.get("ports"))
    a_src, a_dst, a_proto, a_ports = _claim_key(src, dst, proto, ports)
    if (e_src, e_dst) != (a_src, a_dst) or e_proto != a_proto:
        return False
    if e_ports is None:            # exception covers every port
        return True
    if a_ports is None:            # assertion is every port, exception is not
        return False
    return a_ports <= e_ports


def _subject_matches(entry: dict, subject: Optional[str]) -> bool:
    """`subjects` scopes an exception to named configs; omit it for fleet-wide.
    Matching is on the path as reported, or its basename, so a policy written
    once works whether the gate is run from the repo root or a subdirectory."""
    scope = entry.get("subjects")
    if not scope:
        return True
    if subject is None:
        return False
    if not isinstance(scope, (list, tuple)):
        return False
    base = subject.rsplit("/", 1)[-1]
    return any(str(s) == subject or str(s) == base
               or subject.endswith("/" + str(s)) for s in scope)


class Ledger:
    """The evaluated exception list — what applied, what lapsed, what is dead."""

    def __init__(self, entries: Sequence[Exception_], as_of: datetime.date):
        self.entries = list(entries)
        self.as_of = as_of

    def by_status(self, status: str) -> List[Exception_]:
        return [e for e in self.entries if e.status == status]

    @property
    def problems(self) -> List[Finding]:
        """Policy-level findings for exceptions that did not apply. Invalid ones
        are HIGH (they look like protection but give none). Expired ones are
        INFO: the underlying finding is already enforced and reported at its own
        severity — raising a second high here would double-count one risk."""
        out: List[Finding] = []
        for e in self.by_status(INVALID):
            out.append(Finding(
                f"exception:{e.id}", "exception-invalid", "high",
                f"EXCEPTION NOT APPLIED ({e.id}): {e.detail}", "",
                fix="add the missing fields, or delete the exception"))
        for e in self.by_status(EXPIRED):
            out.append(Finding(
                f"exception:{e.id}", "exception-expired", "info",
                f"EXCEPTION LAPSED ({e.id}): {e.detail}", "",
                fix="renew the risk acceptance with a new expiry, or remediate"))
        for e in self.by_status(UNUSED):
            out.append(Finding(
                f"exception:{e.id}", "exception-unused", "info",
                f"EXCEPTION UNUSED ({e.id}): it matched no finding in this run. "
                f"Either the risk was remediated (delete it) or it no longer "
                f"describes the configuration it was written for.", "",
                fix="delete the exception, or correct its claim/subjects"))
        return out

    def to_dict(self) -> dict:
        return {"evaluated_on": self.as_of.isoformat(),
                "total": len(self.entries),
                "applied": len(self.by_status(APPLIED)),
                "expired": len(self.by_status(EXPIRED)),
                "invalid": len(self.by_status(INVALID)),
                "unused": len(self.by_status(UNUSED)),
                "exceptions": [e.to_dict() for e in self.entries]}


def evaluate(policy: Optional[dict],
             as_of: Optional[datetime.date] = None) -> Ledger:
    """Validate every exception in `policy` without matching it to findings yet."""
    as_of = as_of or today()
    entries: List[Exception_] = []
    for entry in ((policy or {}).get("exceptions") or []):
        status, detail = _validate(entry, as_of)
        entries.append(Exception_(
            raw=entry if isinstance(entry, dict) else {"id": repr(entry)},
            status=status, detail=detail))
    return Ledger(entries, as_of)


def accepted_for(ledger: Ledger, kind: str, src: str, dst: str, proto: str,
                 ports, subject: Optional[str]) -> Optional[Exception_]:
    """The in-force exception covering this policy failure, or None.

    Only APPLIED entries can match: an expired or invalid exception must never
    suppress anything, which is the whole guarantee this module makes.
    """
    if kind not in ACCEPTABLE_KINDS:
        return None
    for e in ledger.entries:
        if e.status != APPLIED:
            continue
        if not _subject_matches(e.raw, subject):
            continue
        if _covers(e.raw.get("claim") or {}, src, dst, proto, ports):
            e.matched += 1
            return e
    return None


def finalize(ledger: Ledger) -> Ledger:
    """Mark in-force exceptions that matched nothing as UNUSED. Call once, after
    every finding has been offered to `accepted_for`."""
    for e in ledger.entries:
        if e.status == APPLIED and e.matched == 0:
            e.status = UNUSED
    return ledger


def apply_to_findings(findings: Sequence[Finding], ledger: Ledger,
                      subject: Optional[str] = None) -> List[Finding]:
    """Stamp `accepted` on every policy finding covered by an in-force exception.

    Matching uses the `claim` segcheck stamped on the finding — the assertion it
    actually came from — never a re-parse of its English message. A finding is
    never removed and never downgraded: `gate` simply stops counting an accepted
    finding as a violation, while every report still shows it, its witness
    packet, and who owns it until when.
    """
    for f in findings:
        if f.accepted is not None or f.kind not in ACCEPTABLE_KINDS:
            continue
        claim = f.claim or {}
        if not claim:
            continue
        exc = accepted_for(ledger, f.kind, claim.get("src"), claim.get("dst"),
                           claim.get("proto"), claim.get("ports"), subject)
        if exc is not None:
            f.accepted = {"id": exc.id, "reason": exc.raw.get("reason", ""),
                          "approved_by": exc.raw.get("approved_by", ""),
                          "expires": exc.raw.get("expires", "")}
    return list(findings)
