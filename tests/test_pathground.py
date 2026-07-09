"""Path-grounding — route segcheck witnesses through a forwarding oracle to
suppress infeasible-routing-path false positives WITHOUT ever hiding a real leak.

Every test injects a fake oracle so the logic is exercised hermetically (no
Hammerhead binary). The HammerheadReachOracle JSON/NAT/error handling is tested
separately with an injected `runner` and temp snapshot dirs.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.analyze import Finding  # noqa: E402
from rulehawk.pathground import (  # noqa: E402
    HammerheadReachOracle, Reach, Witness, parse_witness, path_ground)
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}

_LEAKY_ACL = ("ip access-list extended T\n"
              " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n")


def _seg_findings():
    aces, _ = parse_acls(_LEAKY_ACL)
    return check_segmentation(aces, _POLICY)


def _const_oracle(verdict):
    return lambda w: verdict


# --- witness parsing --------------------------------------------------------

def test_parse_witness_with_port():
    w = parse_witness("10.20.0.1 -> 10.10.0.1:445 (tcp)")
    assert w == Witness("10.20.0.1", "10.10.0.1", "tcp", 445)


def test_parse_witness_no_port_ip_proto():
    w = parse_witness("10.20.0.1 -> 10.10.0.1 (ip)")
    assert w == Witness("10.20.0.1", "10.10.0.1", "ip", None)


def test_parse_witness_roundtrips_real_segcheck_output():
    # The witness field a real violation carries must be parseable — otherwise
    # grounding silently no-ops. Guard the contract between segcheck and here.
    viol = next(f for f in _seg_findings() if f.kind == "segmentation-violation")
    assert parse_witness(viol.witness) is not None


def test_parse_witness_garbage_is_none():
    assert parse_witness("not a witness") is None
    assert parse_witness("") is None


# --- the three verdicts -----------------------------------------------------

def test_unreachable_suppresses_to_info():
    before = _seg_findings()
    assert any(f.kind == "segmentation-violation" and f.severity == "critical"
               for f in before)
    after = path_ground(before, _const_oracle(Reach.UNREACHABLE))
    assert not any(f.kind == "segmentation-violation" for f in after)
    supp = next(f for f in after if f.kind == "segmentation-infeasible-path")
    assert supp.severity == "info"
    assert "infeasible" in supp.message.lower()
    assert supp.rule_id and supp.rule  # rule reference preserved, not dropped


def test_reachable_keeps_critical_and_stamps_confirmed():
    after = path_ground(_seg_findings(), _const_oracle(Reach.REACHABLE))
    viol = next(f for f in after if f.kind == "segmentation-violation")
    assert viol.severity == "critical"
    assert "PATH-CONFIRMED" in viol.message


def test_indeterminate_keeps_critical_and_annotates():
    after = path_ground(_seg_findings(), _const_oracle(Reach.INDETERMINATE))
    viol = next(f for f in after if f.kind == "segmentation-violation")
    assert viol.severity == "critical"
    assert "INDETERMINATE" in viol.message


# --- soundness invariants ---------------------------------------------------

def test_non_segmentation_findings_pass_through_untouched():
    other = Finding("A:1", "overly-permissive", "critical", "m", "r")
    out = path_ground([other], _const_oracle(Reach.UNREACHABLE))
    assert out == [other]  # identical object, never grounded


def test_unparseable_witness_is_kept_fail_closed():
    bad = Finding("A:1", "segmentation-violation", "critical", "m", "r",
                  witness="garbage")
    out = path_ground([bad], _const_oracle(Reach.UNREACHABLE))
    assert out == [bad]  # cannot ground -> keep at full severity


def test_only_unreachable_ever_lowers_severity():
    # For any non-UNREACHABLE verdict the critical violation must survive; this
    # is the "never introduce a false PASS" invariant.
    for v in (Reach.REACHABLE, Reach.INDETERMINATE):
        after = path_ground(_seg_findings(), _const_oracle(v))
        assert any(f.kind == "segmentation-violation" and f.severity == "critical"
                   for f in after)


# --- before/after accuracy delta on a multi-router sample -------------------

def test_accuracy_delta_multi_router():
    """Two audited routers each flag a CORP->PCI permit. On R_edge the flow is
    forwarding-reachable (a REAL leak); on R_lab the destination is in an
    isolated island with no route (an infeasible-path FALSE POSITIVE). Grounding
    must keep exactly one critical and suppress exactly one."""
    r_edge = Finding("R_edge/T:10", "segmentation-violation", "critical",
                     "SEGMENTATION VIOLATION (CORP must not reach PCI): ...",
                     "permit tcp ...", witness="10.20.0.1 -> 10.10.0.1:445 (tcp)")
    r_lab = Finding("R_lab/T:10", "segmentation-violation", "critical",
                    "SEGMENTATION VIOLATION (CORP must not reach PCI): ...",
                    "permit tcp ...", witness="10.20.9.1 -> 10.10.9.1:445 (tcp)")
    reachable_srcs = {"10.20.0.1"}  # only the edge witness is forwarding-reachable

    def oracle(w):
        return Reach.REACHABLE if w.src in reachable_srcs else Reach.UNREACHABLE

    before = [r_edge, r_lab]
    after = path_ground(before, oracle)

    crit_before = [f for f in before if f.severity == "critical"]
    crit_after = [f for f in after if f.severity == "critical"]
    assert len(crit_before) == 2 and len(crit_after) == 1  # 50% FP reduction
    # The surviving critical is the genuinely reachable edge leak.
    assert crit_after[0].rule_id == "R_edge/T:10"
    assert "PATH-CONFIRMED" in crit_after[0].message
    # The lab finding is not lost — downgraded, rule reference intact.
    lab = next(f for f in after if f.rule_id == "R_lab/T:10")
    assert lab.kind == "segmentation-infeasible-path" and lab.severity == "info"


# --- HammerheadReachOracle: JSON / error / NAT handling (injected runner) ---

class _FakeProc:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout


def _oracle_with(tmp_path, returncode=0, stdout="", nat=False):
    d = tmp_path / "snap"
    d.mkdir()
    body = "interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
    if nat:
        body += "ip nat inside source list 1 interface Gi0/0 overload\n"
    (d / "r1.cfg").write_text(body)
    runner = lambda argv: _FakeProc(returncode, stdout)
    return HammerheadReachOracle(str(d), "R1", runner=runner)


def _trace(disposition):
    """A minimal `hammerhead traceroute --format json` document."""
    return json.dumps({"from": "R1", "src_ip": "10.20.0.1",
                       "dst_ip": "10.10.0.1", "protocol": "tcp",
                       "dst_port": 445, "hops": [],
                       "disposition": disposition})


_W = Witness("10.20.0.1", "10.10.0.1", "tcp", 445)


def test_oracle_maps_delivered_to_reachable(tmp_path):
    orc = _oracle_with(tmp_path, 0, _trace("Delivered"))
    assert orc(_W) is Reach.REACHABLE


def test_oracle_maps_no_route_to_unreachable(tmp_path):
    orc = _oracle_with(tmp_path, 0, _trace("No route at R7"))
    assert orc(_W) is Reach.UNREACHABLE


def test_oracle_tolerates_schema_token_no_route(tmp_path):
    # schema.rs documents lowercase tokens; accept `no_route` too.
    orc = _oracle_with(tmp_path, 0, _trace("no_route"))
    assert orc(_W) is Reach.UNREACHABLE


def test_oracle_nonzero_exit_is_indeterminate(tmp_path):
    orc = _oracle_with(tmp_path, 2, "unknown device")
    assert orc(_W) is Reach.INDETERMINATE


def test_oracle_bad_json_is_indeterminate(tmp_path):
    orc = _oracle_with(tmp_path, 0, "not json")
    assert orc(_W) is Reach.INDETERMINATE


def test_oracle_missing_disposition_is_indeterminate(tmp_path):
    orc = _oracle_with(tmp_path, 0, json.dumps({"from": "R1"}))
    assert orc(_W) is Reach.INDETERMINATE


def test_oracle_non_string_disposition_is_indeterminate(tmp_path):
    orc = _oracle_with(tmp_path, 0, json.dumps({"disposition": True}))
    assert orc(_W) is Reach.INDETERMINATE


# --- the tcp/80 false-PASS regression (BUILD packet 10) ----------------------

def test_oracle_probes_witness_proto_and_port_not_tcp80(tmp_path):
    """The probe must carry the witness tuple (tcp/445 here), never a fixed
    tcp/80 reachability check — that is the bug that let an ACL-denied port 80
    downgrade a deliverable port-445 leak."""
    d = tmp_path / "snap"
    d.mkdir()
    (d / "r1.cfg").write_text("interface Gi0/0\n")
    seen = []

    def capture(argv):
        seen.append(argv)
        return _FakeProc(0, _trace("Delivered"))

    orc = HammerheadReachOracle(str(d), "R1", runner=capture)
    assert orc(_W) is Reach.REACHABLE
    (argv,) = seen
    assert argv[1] == "traceroute"
    assert argv[argv.index("--proto") + 1] == "tcp"
    assert argv[argv.index("--dport") + 1] == "445"
    assert "reachability" not in argv


def test_oracle_acl_denied_probe_is_indeterminate_not_unreachable(tmp_path):
    """An ACL 'Denied' disposition must NOT downgrade: the probe's source port
    is fixed while the witness ranges over all source ports, so a denied probe
    does not prove the witness undeliverable. Fail closed."""
    orc = _oracle_with(
        tmp_path, 0, _trace('Denied by R2 ACL "TRANSIT" entry 3 (ingress)'))
    assert orc(_W) is Reach.INDETERMINATE


def test_transit_acl_deny_never_suppresses_the_leak_end_to_end(tmp_path):
    """Full-pipeline regression for the false PASS: a real tcp/445 CORP->PCI
    leak whose path ACL would deny a tcp/80 probe. The traceroute probe carries
    tcp/445 and is Delivered -> the finding must STAY critical, path-confirmed.
    (Under the old `hammerhead reachability` tcp/80 probe this leak was
    silently downgraded to info.)"""
    d = tmp_path / "snap"
    d.mkdir()
    (d / "r1.cfg").write_text("interface Gi0/0\n")

    def acl_aware(argv):
        dport = argv[argv.index("--dport") + 1] if "--dport" in argv else "80"
        if dport == "80":  # transit ACL blocks web ports...
            return _FakeProc(0, _trace('Denied by R2 ACL "TRANSIT" entry 1 (ingress)'))
        return _FakeProc(0, _trace("Delivered"))  # ...but permits the leak port

    orc = HammerheadReachOracle(str(d), "R1", runner=acl_aware)
    after = path_ground(_seg_findings(), orc)
    viol = next(f for f in after if f.kind == "segmentation-violation")
    assert viol.severity == "critical"
    assert "PATH-CONFIRMED" in viol.message
    assert not any(f.kind == "segmentation-infeasible-path" for f in after)


def test_oracle_other_dispositions_fail_closed(tmp_path):
    for i, disp in enumerate(("Blackholed at R3", "Unreachable at R3",
                              "Routing loop through R1 -> R2 -> R1",
                              "Max hops exceeded",
                              "uRPF dropped at R2 Gi0/1 (asymmetric path)",
                              "???")):
        base = tmp_path / str(i)
        base.mkdir()
        orc = _oracle_with(base, 0, _trace(disp))
        assert orc(_W) is Reach.INDETERMINATE, disp


# --- probe/witness instantiation rules ---------------------------------------

def _capturing_oracle(tmp_path, disposition):
    d = tmp_path / "snap"
    d.mkdir()
    (d / "r1.cfg").write_text("interface Gi0/0\n")
    seen = []

    def capture(argv):
        seen.append(argv)
        return _FakeProc(0, _trace(disposition))

    return HammerheadReachOracle(str(d), "R1", runner=capture), seen


def test_oracle_portless_tcp_witness_delivered_is_reachable(tmp_path):
    # "tcp any-port" witness: the default-port probe is an instance of it.
    orc, seen = _capturing_oracle(tmp_path, "Delivered")
    assert orc(Witness("10.20.0.1", "10.10.0.1", "tcp", None)) is Reach.REACHABLE
    (argv,) = seen
    assert argv[argv.index("--proto") + 1] == "tcp" and "--dport" not in argv


def test_oracle_ip_witness_delivered_is_reachable(tmp_path):
    # witness proto "ip" covers ALL IP traffic, so any delivered probe proves it;
    # no --proto/--dport is passed (CLI probes its default).
    orc, seen = _capturing_oracle(tmp_path, "Delivered")
    assert orc(Witness("10.20.0.1", "10.10.0.1", "ip", None)) is Reach.REACHABLE
    (argv,) = seen
    assert "--proto" not in argv and "--dport" not in argv


def test_oracle_icmp_witness_delivered_is_reachable(tmp_path):
    orc, seen = _capturing_oracle(tmp_path, "Delivered")
    assert orc(Witness("10.20.0.1", "10.10.0.1", "icmp", None)) is Reach.REACHABLE
    (argv,) = seen
    assert argv[argv.index("--proto") + 1] == "icmp" and "--dport" not in argv


def test_oracle_exotic_proto_delivered_is_indeterminate(tmp_path):
    # A tcp-default probe delivering says nothing about an esp/gre witness.
    orc = _oracle_with(tmp_path, 0, _trace("Delivered"))
    assert orc(Witness("10.20.0.1", "10.10.0.1", "esp", None)) is Reach.INDETERMINATE


def test_oracle_exotic_proto_no_route_still_unreachable(tmp_path):
    # ...but a destination-FIB "No route" proof holds for every proto.
    orc = _oracle_with(tmp_path, 0, _trace("No route at R7"))
    assert orc(Witness("10.20.0.1", "10.10.0.1", "esp", None)) is Reach.UNREACHABLE


def test_oracle_inexpressible_witness_fails_closed_without_running(tmp_path):
    d = tmp_path / "snap"
    d.mkdir()
    (d / "r1.cfg").write_text("interface Gi0/0\n")

    def boom(argv):
        raise AssertionError("runner must not be called for an invalid probe")

    orc = HammerheadReachOracle(str(d), "R1", runner=boom)
    assert orc(Witness("2001:db8::1", "10.10.0.1", "tcp", 445)) is Reach.INDETERMINATE
    assert orc(Witness("10.20.0.1", "10.10.0.1", "tcp", 70000)) is Reach.INDETERMINATE


def test_oracle_nat_in_snapshot_fails_closed(tmp_path):
    # NAT present -> INDETERMINATE without ever consulting the runner (which would
    # raise if called), because a translated header could hide a real leak.
    d = tmp_path / "snap"
    d.mkdir()
    (d / "r1.cfg").write_text("ip nat inside source static 10.20.0.1 10.10.0.1\n")

    def boom(argv):
        raise AssertionError("runner must not be called when NAT is present")

    orc = HammerheadReachOracle(str(d), "R1", runner=boom)
    assert orc(_W) is Reach.INDETERMINATE


def test_oracle_missing_snapshot_dir_fails_closed(tmp_path):
    orc = HammerheadReachOracle(str(tmp_path / "nope"), "R1",
                                runner=lambda a: _FakeProc(0, '{"reachable": false}'))
    assert orc(_W) is Reach.INDETERMINATE


def test_oracle_runner_exception_is_indeterminate(tmp_path):
    d = tmp_path / "snap"
    d.mkdir()
    (d / "r1.cfg").write_text("interface Gi0/0\n")

    def raiser(argv):
        raise OSError("binary not found")

    orc = HammerheadReachOracle(str(d), "R1", runner=raiser)
    assert orc(_W) is Reach.INDETERMINATE


# --- latency guards: per-witness memo + timeout circuit breaker (packet 21) --
# Both guards are pure latency fixes: they return the SAME verdict the
# un-guarded path would produce, so the post-grounding critical set is
# unchanged (no false PASS can be introduced).

import subprocess  # noqa: E402


def _counting_runner(stdout, returncode=0):
    calls = []

    def runner(argv):
        calls.append(argv)
        return _FakeProc(returncode, stdout)

    return runner, calls


def _clean_snapshot(tmp_path):
    d = tmp_path / "snap"
    d.mkdir()
    (d / "r1.cfg").write_text("interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n")
    return d


def test_oracle_memoizes_repeat_witness_single_subprocess(tmp_path):
    # Duplicate witnesses across assertions must pay ONE subprocess run, and
    # the cached verdict must be identical to the fresh one.
    d = _clean_snapshot(tmp_path)
    runner, calls = _counting_runner(_trace("Delivered"))
    orc = HammerheadReachOracle(str(d), "R1", runner=runner)
    assert orc(_W) is Reach.REACHABLE
    assert orc(_W) is Reach.REACHABLE  # served from memo
    assert len(calls) == 1


def test_oracle_memo_is_per_witness_not_global(tmp_path):
    # Distinct witnesses each get their own probe — the memo never shares a
    # verdict across different packets.
    d = _clean_snapshot(tmp_path)
    runner, calls = _counting_runner(_trace("No route at R7"))
    orc = HammerheadReachOracle(str(d), "R1", runner=runner)
    w2 = Witness("10.20.0.9", "10.10.0.9", "tcp", 3389)
    assert orc(_W) is Reach.UNREACHABLE
    assert orc(w2) is Reach.UNREACHABLE
    assert len(calls) == 2


def test_oracle_timeout_is_indeterminate_and_trips_breaker(tmp_path):
    # First TimeoutExpired -> fail-closed INDETERMINATE (as before), and every
    # LATER witness short-circuits to the same verdict without spawning another
    # doomed 60s probe: worst case N x timeout collapses to ~1 x timeout.
    d = _clean_snapshot(tmp_path)
    calls = []

    def hung(argv):
        calls.append(argv)
        raise subprocess.TimeoutExpired(cmd=argv, timeout=60.0)

    orc = HammerheadReachOracle(str(d), "R1", runner=hung)
    assert orc(_W) is Reach.INDETERMINATE
    assert orc(Witness("10.20.0.9", "10.10.0.9", "tcp", 3389)) is Reach.INDETERMINATE
    assert orc(Witness("10.20.0.7", "10.10.0.7", "udp", 53)) is Reach.INDETERMINATE
    assert len(calls) == 1  # only the first witness paid the timeout


def test_oracle_breaker_does_not_invalidate_earlier_proofs(tmp_path):
    # Verdicts proven BEFORE the timeout stay served from the memo afterwards:
    # the breaker only suppresses NEW probes, it never rewrites history.
    d = _clean_snapshot(tmp_path)
    state = {"hang": False, "calls": 0}

    def runner(argv):
        state["calls"] += 1
        if state["hang"]:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=60.0)
        return _FakeProc(0, _trace("No route at R7"))

    orc = HammerheadReachOracle(str(d), "R1", runner=runner)
    assert orc(_W) is Reach.UNREACHABLE  # proven while healthy
    state["hang"] = True
    w2 = Witness("10.20.0.9", "10.10.0.9", "tcp", 3389)
    assert orc(w2) is Reach.INDETERMINATE  # trips breaker
    assert orc(_W) is Reach.UNREACHABLE   # memo, no new subprocess
    assert orc(w2) is Reach.INDETERMINATE  # stays fail-closed
    assert state["calls"] == 2


def test_oracle_non_timeout_errors_do_not_trip_breaker(tmp_path):
    # An OSError (binary missing) is per-call INDETERMINATE but must NOT stop
    # later witnesses from probing — only a proven hang trips the breaker.
    d = _clean_snapshot(tmp_path)
    state = {"fail_once": True, "calls": 0}

    def runner(argv):
        state["calls"] += 1
        if state["fail_once"]:
            state["fail_once"] = False
            raise OSError("transient")
        return _FakeProc(0, _trace("Delivered"))

    orc = HammerheadReachOracle(str(d), "R1", runner=runner)
    assert orc(_W) is Reach.INDETERMINATE
    w2 = Witness("10.20.0.9", "10.10.0.9", "tcp", 3389)
    assert orc(w2) is Reach.REACHABLE  # breaker not tripped; probe ran
    assert state["calls"] == 2
