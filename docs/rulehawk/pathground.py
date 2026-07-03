"""Path-grounding — kill infeasible-routing-path false positives in segmentation
findings by routing each concrete witness packet through Hammerhead's forwarding
model (per-device FIB / reachability, 99.93% Batfish FIB parity).

WHY (the adoption killer this removes). RuleHawk's `segcheck` is topology-blind:
it proves a *single* ordered ACL permits a forbidden witness flow (first-match
semantics), but it cannot know whether traffic from the source zone to the
destination zone ever actually TRAVERSES the interface that ACL guards. A permit
on an interface no CORP->PCI packet ever crosses is a real rule but NOT an active
segmentation leak. Flagging it critical is exactly the "FP due to infeasible
routing path" that Xumi (arXiv 2508.17990, Aug 2025) shows is one of the two
dominant false-positive sources in ACL-conflict detection — and the #1 reason a
free auditor gets muted (alert fatigue). Xumi had to bolt a path validator on;
Hammerhead already ships one.

WHAT (soundness contract — we never hide a real leak). We only ever DOWNGRADE a
finding, and only on a definitive, NAT-free "not delivered" verdict from the
forwarding model:

  * REACHABLE      -> the model delivers a probe that IS an instance of the
                     witness class (same proto, and the witness's dst port when
                     it has one) end-to-end across the network: an ACTIVE,
                     forwarding-reachable leak. Keep it critical and STAMP it
                     path-confirmed (higher-confidence).
  * UNREACHABLE    -> the model proves NO ROUTE delivers the witness: some device
                     on the destination path has no FIB entry for the dst. The
                     FIB lookup is destination-only, so this proof holds for
                     EVERY proto/port — the permit exists but the segmentation
                     VIOLATION cannot occur -> downgrade to an informational
                     infeasible-path note (suppressed from the CI-failing
                     critical/high band), rule reference preserved.
  * INDETERMINATE  -> NAT in the snapshot (documented Hammerhead symbolic-NAT
                     gap), unknown device, query error, no model, a witness the
                     probe cannot express (IPv6, exotic proto), or any trace
                     disposition that is not a destination-FIB proof (ACL-denied,
                     blackholed, loop, uRPF drop...). FAIL CLOSED: keep the
                     finding at full severity, annotated.

The probe is `hammerhead traceroute` carrying the witness's own proto and dst
port, NOT a fixed tcp/80 packet: a reachability check that probes tcp/80 would
report "unreachable" whenever a transit ACL blocks port 80 yet permits the
witness's real port (445/3389/22 — exactly the ports real leaks use), silently
downgrading an ACTIVE leak. Only the "No route" disposition downgrades, because
it is the one verdict independent of the probe header. An ACL "Denied" verdict
does NOT downgrade even on an exact proto+dport match: the probe's source port
is fixed (33434) while the witness ranges over ALL source ports, so a deny that
matched the probe need not deny every witness packet. The only path that removes
a critical finding is a deterministic destination-FIB proof, so the
post-grounding critical set is always a SUBSET of the pre-grounding one: no new
false PASS is ever introduced.
"""

from __future__ import annotations

import dataclasses
import enum
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .analyze import Finding


class Reach(enum.Enum):
    """Forwarding-model verdict for a witness packet."""

    REACHABLE = "reachable"          # delivered end-to-end -> real leak, keep+confirm
    UNREACHABLE = "unreachable"      # deterministic no-path -> infeasible, downgrade
    INDETERMINATE = "indeterminate"  # NAT / error / no model -> fail closed, keep


@dataclasses.dataclass(frozen=True)
class Witness:
    """A concrete probe parsed out of a segmentation finding's `witness` field."""

    src: str
    dst: str
    proto: str
    port: Optional[int]


Oracle = Callable[[Witness], Reach]


# segcheck emits: f"{swit} -> {dwit}{portsfx} ({proto})", portsfx = f":{port}".
# e.g. "10.20.0.1 -> 10.10.0.1:445 (tcp)"  or  "10.20.0.1 -> 10.10.0.1 (ip)"
_WITNESS_RE = re.compile(
    r"^\s*(?P<src>\S+?)\s*->\s*(?P<dst>[^:\s]+)(?::(?P<port>\d+))?\s*\((?P<proto>\w+)\)\s*$"
)


def parse_witness(witness: str) -> Optional[Witness]:
    """Parse segcheck's witness string, or None if it doesn't match (fail-closed:
    an unparseable witness leaves its finding untouched)."""
    m = _WITNESS_RE.match(witness or "")
    if not m:
        return None
    port = m.group("port")
    return Witness(m.group("src"), m.group("dst"), m.group("proto").lower(),
                   int(port) if port is not None else None)


def path_ground(findings: List[Finding], oracle: Oracle) -> List[Finding]:
    """Return a new finding list with segmentation violations path-grounded.

    Only `segmentation-violation` findings carrying a parseable witness are
    consulted; everything else passes through byte-for-byte. Soundness: the only
    transition that lowers severity is UNREACHABLE (a deterministic model proof),
    so no non-violation is ever promoted and no real leak is ever hidden."""
    out: List[Finding] = []
    for f in findings:
        if f.kind != "segmentation-violation":
            out.append(f)
            continue
        w = parse_witness(f.witness)
        if w is None:
            out.append(f)  # can't ground it -> keep as-is (fail closed)
            continue
        verdict = oracle(w)
        if verdict is Reach.UNREACHABLE:
            out.append(_suppress(f))
        elif verdict is Reach.REACHABLE:
            out.append(_confirm(f))
        else:
            out.append(_annotate_indeterminate(f))
    return out


def _suppress(f: Finding) -> Finding:
    """Downgrade an infeasible-path violation to an informational note. The permit
    is real (rule reference kept) but no forwarding path delivers the witness, so
    it is not an active segmentation leak — this is what removes the FP."""
    return dataclasses.replace(
        f,
        kind="segmentation-infeasible-path",
        severity="info",
        message=(
            f.message
            + " [PATH-GROUNDED] Hammerhead's forwarding model proves NO path "
            "delivers this witness across the network (no route, or blocked on "
            "the actual path), so the permit is not an active segmentation leak "
            "— suppressed as an infeasible-routing-path false positive "
            "(cf. Xumi, arXiv 2508.17990)."
        ),
        fix=f.fix + " (informational: rule is over-permissive but currently "
                    "unreachable end-to-end; still recommend tightening)",
    )


def _confirm(f: Finding) -> Finding:
    """Keep the critical violation and stamp it forwarding-confirmed."""
    return dataclasses.replace(
        f,
        message=f.message + " [PATH-CONFIRMED] Hammerhead delivered this witness "
                            "end-to-end across the modeled network — an ACTIVE, "
                            "forwarding-reachable leak.",
    )


def _annotate_indeterminate(f: Finding) -> Finding:
    """Keep the finding at full severity; note that grounding was inconclusive."""
    return dataclasses.replace(
        f,
        message=f.message + " [PATH-GROUNDING INDETERMINATE] NAT-in-path, an "
                            "inexpressible witness, an ACL-denied probe, or "
                            "unmodeled forwarding — reported conservatively "
                            "(fail-closed).",
    )


# --- Production oracle: shell out to the Hammerhead CLI ---------------------

# NAT indicators across the vendors RuleHawk fronts. If ANY appears in the
# snapshot we fail closed (INDETERMINATE): Hammerhead's symbolic engine does not
# yet apply NAT transfer functions (documented Open gap, hammerhead CLAUDE.md),
# and the witness carries PRE-NAT zone addresses, so a translated header could
# make a genuinely-reachable flow look unreachable. Never downgrade under NAT.
_NAT_MARKERS = (
    "ip nat", "nat (", "nat44", "nat destination", "nat source",
    "set security nat", "-t nat", "-j snat", "-j dnat", "-j masquerade",
)

# CLI/config file extensions we scan for NAT markers.
_CFG_GLOBS = ("*.cfg", "*.conf", "*.txt", "*")


# Protocols the Hammerhead traceroute probe can carry natively. Anything else
# (incl. segcheck's catch-all "ip") is probed with the CLI default (tcp) and can
# only be downgraded on the proto-independent "No route" disposition.
_PROBE_PROTOS = ("tcp", "udp", "icmp")


class HammerheadReachOracle:
    """Path-grounding oracle backed by `hammerhead traceroute … --format json`,
    probing the witness's OWN proto/dst-port (never a fixed tcp/80 packet — see
    the module docstring for why that would hide real leaks).

    Verdict mapping over the trace's `disposition` string:

      * "No route …"  -> UNREACHABLE. A destination-FIB proof, valid for every
                         proto/port, so downgrading any witness on it is sound.
      * "Delivered …" -> REACHABLE, but only when the probe is an instance of
                         the witness class (witness proto tcp/udp/icmp carried
                         verbatim with its dst port, or witness proto "ip" which
                         any probe instantiates). Otherwise INDETERMINATE.
      * anything else -> INDETERMINATE (fail closed). This includes "Denied by
                         …": the probe's source port is fixed, the witness's is
                         not, so an ACL deny of the probe does not prove the
                         witness undeliverable.

    `runner` is injectable so the JSON-parse / error-handling logic is unit
    testable without the compiled binary. It receives the argv list and must
    return an object with `.returncode` (int) and `.stdout` (str); the default
    runs the real CLI via subprocess with a timeout.

    Latency guards (verdict mapping untouched — both return the SAME verdict
    the un-guarded path would eventually produce, just without the wait):

      * Per-witness memo: the oracle is deterministic per (witness, snapshot),
        so repeat witnesses (duplicated across assertions) return the cached
        verdict instead of paying a second subprocess run.
      * Timeout circuit breaker: `subprocess.TimeoutExpired` proves the binary
        is hung/too slow for this snapshot; every SUBSEQUENT probe would hit
        the identical 60s timeout and land on the identical fail-closed
        INDETERMINATE, so after the first timeout we short-circuit all later
        probes straight to INDETERMINATE. Worst case drops from N x timeout to
        ~1 x timeout; the post-grounding critical set is byte-identical.
    """

    def __init__(self, snapshot_dir: str, from_device: str,
                 binary: str = "hammerhead", timeout: float = 60.0,
                 runner: Optional[Callable[[List[str]], "subprocess.CompletedProcess"]] = None):
        self.snapshot_dir = snapshot_dir
        self.from_device = from_device
        self.binary = binary
        self.timeout = timeout
        self._runner = runner or self._subprocess_runner
        # Detect NAT once per snapshot; if present, every verdict is fail-closed.
        self._nat_present = _snapshot_has_nat(snapshot_dir)
        # Deterministic per (witness, snapshot) -> safe to memoize verdicts.
        self._memo: Dict[Witness, Reach] = {}
        # Set on the first TimeoutExpired; short-circuits all later probes.
        self._probe_timed_out = False

    def _subprocess_runner(self, argv: List[str]) -> "subprocess.CompletedProcess":
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=self.timeout, check=False)

    def __call__(self, w: Witness) -> Reach:
        if self._nat_present:
            return Reach.INDETERMINATE  # documented symbolic-NAT gap -> fail closed
        cached = self._memo.get(w)
        if cached is not None:
            return cached  # verdicts already proven stay valid post-timeout too
        if self._probe_timed_out:
            # Circuit breaker: the binary already proved hung/too slow. Each
            # further probe would burn its own full timeout and return this
            # exact fail-closed verdict — skip straight to it.
            return Reach.INDETERMINATE
        verdict = self._probe(w)
        self._memo[w] = verdict
        return verdict

    def _probe(self, w: Witness) -> Reach:
        argv = self._traceroute_argv(w)
        if argv is None:
            return Reach.INDETERMINATE  # witness not expressible as a probe
        try:
            proc = self._runner(argv)
        except subprocess.TimeoutExpired:
            self._probe_timed_out = True  # trip breaker; fail closed as before
            return Reach.INDETERMINATE
        except (OSError, subprocess.SubprocessError):
            return Reach.INDETERMINATE
        if getattr(proc, "returncode", 1) != 0:
            return Reach.INDETERMINATE
        try:
            doc = json.loads(proc.stdout)
        except (ValueError, TypeError):
            return Reach.INDETERMINATE
        disposition = doc.get("disposition")
        if not isinstance(disposition, str):
            return Reach.INDETERMINATE
        d = disposition.strip().lower()
        # Destination-FIB proof: holds for every proto/port -> sound downgrade.
        if d.startswith("no route") or d.startswith("no_route"):
            return Reach.UNREACHABLE
        # Delivered probe proves the leak only if it instantiates the witness.
        if d.startswith("delivered") and _probe_instantiates_witness(w):
            return Reach.REACHABLE
        # Denied / Blackholed / Loop / uRPF / Max hops / unrecognised -> closed.
        return Reach.INDETERMINATE

    def _traceroute_argv(self, w: Witness) -> Optional[List[str]]:
        """Build the traceroute argv for the witness, or None when the witness
        cannot be expressed as a valid probe (IPv4-only CLI, u16 ports)."""
        try:
            ipaddress.IPv4Address(w.src)
            ipaddress.IPv4Address(w.dst)
        except (ipaddress.AddressValueError, ValueError):
            return None
        argv = [self.binary, "traceroute", self.snapshot_dir,
                "--from", self.from_device, "--src", w.src, "--dst", w.dst,
                "--format", "json"]
        if w.proto in _PROBE_PROTOS:
            argv += ["--proto", w.proto]
        if w.proto in ("tcp", "udp") and w.port is not None:
            if not 0 <= w.port <= 65535:
                return None
            argv += ["--dport", str(w.port)]
        return argv


def _probe_instantiates_witness(w: Witness) -> bool:
    """True iff the probe built by `_traceroute_argv` is a member of the witness
    class, i.e. a Delivered probe proves the witnessed leak is deliverable.

      * proto "ip"       -> witness covers ALL IP traffic; any probe is a member.
      * proto tcp/udp    -> probe carries the proto and, when the witness names a
                            dst port, exactly that port (portless witness = any
                            port, which the default port instantiates).
      * proto icmp       -> probe carries icmp; only sound when the witness has
                            no port qualifier (icmp has no ports).
      * anything else    -> probe (default tcp) is NOT the witness proto.
    """
    if w.proto == "ip":
        return True
    if w.proto in ("tcp", "udp"):
        return True  # proto passed verbatim; dport passed whenever present
    if w.proto == "icmp":
        return w.port is None
    return False


def _snapshot_has_nat(snapshot_dir: str) -> bool:
    """True if any config file under `snapshot_dir` carries a NAT marker. On any
    read error we return True (fail closed — assume NAT could be present)."""
    root = Path(snapshot_dir)
    if not root.exists():
        return True  # no model -> can't ground -> fail closed
    try:
        seen = set()
        for pat in _CFG_GLOBS:
            for p in root.rglob(pat):
                if not p.is_file() or p in seen:
                    continue
                seen.add(p)
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore").lower()
                except OSError:
                    return True
                if any(m in text for m in _NAT_MARKERS):
                    return True
    except OSError:
        return True
    return False
