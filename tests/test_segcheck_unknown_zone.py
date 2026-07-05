"""An assertion that names an undefined/misspelled/omitted zone must FAIL CLOSED.

Regression for the false-bill-of-health bug: `zones.get(sname, [])` returned []
for a zone not present in policy["zones"], so the witness loops never ran and the
checker emitted a confident `segmentation-ok` PASS for a check that never happened
— the exact false assurance RuleHawk exists to prevent. The fix must instead emit
a high-severity `segmentation-error` and NEVER a PASS.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk.segcheck import check_segmentation  # noqa: E402


def _find(policy):
    return check_segmentation([], policy)


def test_misspelled_src_zone_fails_closed_not_pass():
    # 'COORP' is a typo for a defined zone; PCI is real. Old code: green PASS.
    policy = {
        "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
        "must_not_reach": [{"src": "COORP", "dst": "PCI"}],
    }
    fs = _find(policy)
    kinds = {f.kind for f in fs}
    assert "segmentation-ok" not in kinds, "must NOT fabricate a PASS"
    assert kinds == {"segmentation-error"}
    err = fs[0]
    assert err.severity == "high"
    assert "COORP" in err.message          # names the offending zone
    assert "CORP" in err.message and "PCI" in err.message  # lists defined zones


def test_undefined_dst_zone_fails_closed():
    policy = {
        "zones": {"CORP": ["10.20.0.0/16"]},
        "must_not_reach": [{"src": "CORP", "dst": "PCI"}],  # PCI never defined
    }
    fs = _find(policy)
    assert [f.kind for f in fs] == ["segmentation-error"]
    assert fs[0].severity == "high"
    assert "PCI" in fs[0].message


def test_omitted_src_key_is_null_and_fails_closed():
    # sname = None (assertion missing 'src'). Old code hit the same PASS path.
    policy = {
        "zones": {"PCI": ["10.10.0.0/16"]},
        "must_not_reach": [{"dst": "PCI"}],
    }
    fs = _find(policy)
    assert [f.kind for f in fs] == ["segmentation-error"]
    assert "missing src zone" in fs[0].message


def test_both_zones_unknown_reported_together():
    policy = {
        "zones": {"CORP": ["10.20.0.0/16"]},
        "must_not_reach": [{"src": "X", "dst": "Y"}],
    }
    fs = _find(policy)
    assert [f.kind for f in fs] == ["segmentation-error"]
    msg = fs[0].message
    assert "'X'" in msg and "'Y'" in msg


def test_valid_zones_still_pass_or_evaluate():
    # Guardrail: the new branch does not disturb well-formed assertions.
    policy = {
        "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
        "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
    }
    fs = _find(policy)  # empty ACL -> default deny -> PASS
    assert [f.kind for f in fs] == ["segmentation-ok"]
    assert "segmentation-error" not in {f.kind for f in fs}
