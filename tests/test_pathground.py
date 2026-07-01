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


_W = Witness("10.20.0.1", "10.10.0.1", "tcp", 445)


def test_oracle_maps_reachable_true(tmp_path):
    orc = _oracle_with(tmp_path, 0, json.dumps({"reachable": True}))
    assert orc(_W) is Reach.REACHABLE


def test_oracle_maps_reachable_false(tmp_path):
    orc = _oracle_with(tmp_path, 0, json.dumps({"reachable": False}))
    assert orc(_W) is Reach.UNREACHABLE


def test_oracle_nonzero_exit_is_indeterminate(tmp_path):
    orc = _oracle_with(tmp_path, 2, "unknown device")
    assert orc(_W) is Reach.INDETERMINATE


def test_oracle_bad_json_is_indeterminate(tmp_path):
    orc = _oracle_with(tmp_path, 0, "not json")
    assert orc(_W) is Reach.INDETERMINATE


def test_oracle_missing_field_is_indeterminate(tmp_path):
    orc = _oracle_with(tmp_path, 0, json.dumps({"from": "R1"}))
    assert orc(_W) is Reach.INDETERMINATE


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
