"""Service-port operator PRECISION — lt / gt / neq / source-port.

Cisco/ASA `lt P` / `gt P` (single contiguous ranges) and `neq P` (the exact
union of two contiguous ranges) are modeled PRECISELY, turning what used to be a
fail-closed INDETERMINATE into a precise PASS or CRITICAL. SOUNDNESS is the
cardinal rule: every modeled range is exact (never widened), so precision can
only sharpen a verdict — it can NEVER manufacture a false PASS. The mutation
guard at the bottom proves the range math is load-bearing.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.model import PORT_MAX, PORT_MIN, PortRange  # noqa: E402
from rulehawk.parse import _parse_port_op, _svc_port  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}
_SRC = "10.20.0.0 0.0.255.255"
_DST = "10.10.0.0 0.0.255.255"


def _kinds(acl_text, policy=_POLICY):
    aces, _ = parse_acls(acl_text)
    return {f.kind for f in check_segmentation(aces, policy)}


# --- (a) lt 446 covers 445 -> precise CRITICAL (was INDETERMINATE) ----------
def test_lt_446_covers_445_critical():
    acl = f"ip access-list extended T\n permit tcp {_SRC} {_DST} lt 446\n"
    kinds = _kinds(acl)
    assert "segmentation-violation" in kinds
    assert "segmentation-indeterminate" not in kinds


# --- (b) gt 444 covers 445 -> precise CRITICAL -----------------------------
def test_gt_444_covers_445_critical():
    acl = f"ip access-list extended T\n permit tcp {_SRC} {_DST} gt 444\n"
    kinds = _kinds(acl)
    assert "segmentation-violation" in kinds
    assert "segmentation-indeterminate" not in kinds


# --- (c) lt 445 does NOT cover 445 -> precise PASS --------------------------
def test_lt_445_excludes_445_precise_pass():
    # [0,444] genuinely does not include 445; with no other permit, CORP truly
    # cannot reach PCI:445 -> a precise PASS, never a false PASS.
    acl = f"ip access-list extended T\n permit tcp {_SRC} {_DST} lt 445\n"
    kinds = _kinds(acl)
    assert "segmentation-violation" not in kinds
    assert "segmentation-ok" in kinds


# --- (d) neq 80 covers 445 -> CRITICAL; neq 445 excludes 445 -> PASS --------
def test_neq_80_covers_445_critical():
    acl = f"ip access-list extended T\n permit tcp {_SRC} {_DST} neq 80\n"
    assert "segmentation-violation" in _kinds(acl)


def test_neq_445_never_segmentation_ok_when_445_in_complement():
    # Cardinal-rule guard: segmentation-ok is allowed ONLY because 445 sits in
    # NEITHER modeled neq range. For every neq P != 445, port 445 IS in the
    # complement, so the verdict must NEVER be segmentation-ok (it must be a
    # violation). This sweeps the boundary cases too (neq 444 / neq 446).
    for p in (1, 80, 444, 446, 3389, 65535):
        kinds = _kinds(f"ip access-list extended T\n permit tcp {_SRC} {_DST} neq {p}\n")
        assert "segmentation-ok" not in kinds, f"false PASS for neq {p}"
        assert "segmentation-violation" in kinds


# --- (e) a source-port constraint populates sport, not dport ---------------
def test_source_port_populates_sport_not_dport():
    # `permit tcp any eq 1024 host ... eq 445`: the FIRST operator is the SOURCE
    # port, the second the DESTINATION port. They must not be swapped.
    aces, _ = parse_acls(
        "ip access-list extended T\n permit tcp any eq 1024 host 10.0.0.9 eq 445\n")
    assert len(aces) == 1
    ace = aces[0]
    assert ace.src_port == PortRange(1024, 1024)
    assert ace.dst_port == PortRange(445, 445)


def test_source_port_operator_lt_populates_sport():
    aces, _ = parse_acls(
        "ip access-list extended T\n permit tcp any lt 1024 host 10.0.0.9 eq 80\n")
    ace = aces[0]
    assert ace.src_port == PortRange(PORT_MIN, 1023)  # src lt 1024
    assert ace.dst_port == PortRange(80, 80)          # dst eq 80


# --- object-group-service lt/gt now resolves precisely (was INDETERMINATE) --
def test_objgroup_service_lt_resolves_precise_critical():
    cfg = (
        "object-group service WEBISH tcp\n"
        " port-object lt 446\n"            # -> [0,445], covers 445
        "ip access-list extended T\n"
        f" permit tcp {_SRC} {_DST} object-group WEBISH\n")
    kinds = _kinds(cfg)
    assert "segmentation-violation" in kinds
    assert "segmentation-indeterminate" not in kinds


# --- degenerate boundaries stay sound (no crash, fail closed) --------------
def test_degenerate_lt0_gt65535_stay_imprecise():
    # lt 0 / gt 65535 match the empty set; we keep them fail-closed (ANY+imprecise)
    # rather than invent an empty range. Sound: never a false PASS.
    for op in ("lt 0", "gt 65535"):
        ranges, _, imprecise, _ = _parse_port_op(op.split(), 0)
        assert imprecise is True
        assert ranges == [PortRange(PORT_MIN, PORT_MAX)]


# --- MUTATION GUARD: the lt/gt/neq range math must be exact -----------------
def test_lt_gt_neq_range_math_is_exact():
    # Pin the exact arithmetic. If someone fat-fingers lt -> [MIN, P] (off-by-one)
    # or gt -> [P, MAX], or neq drops a sub-range, these equalities break AND the
    # precise PASS/CRITICAL segcheck tests above flip — proving the math is
    # load-bearing, not cosmetic.
    assert _parse_port_op(["lt", "446"], 0)[0] == [PortRange(PORT_MIN, 445)]
    assert _parse_port_op(["gt", "444"], 0)[0] == [PortRange(445, PORT_MAX)]
    assert _parse_port_op(["neq", "80"], 0)[0] == [
        PortRange(PORT_MIN, 79), PortRange(81, PORT_MAX)]
    # degenerate complement ends collapse to a single range
    assert _parse_port_op(["neq", "0"], 0)[0] == [PortRange(1, PORT_MAX)]
    assert _parse_port_op(["neq", str(PORT_MAX)], 0)[0] == [PortRange(PORT_MIN, 65534)]
    # object-group-service helper mirrors the same math
    assert _svc_port(["lt", "446"], 0) == PortRange(PORT_MIN, 445)
    assert _svc_port(["gt", "444"], 0) == PortRange(445, PORT_MAX)
    assert _svc_port(["neq", "80"], 0) is None       # neq stays fail-closed here
