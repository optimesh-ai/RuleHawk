"""Fail-closed on an unresolvable protocol in a policy assertion.

Sibling of tests/test_segcheck_unknown_zone.py. An unknown zone was already
fail-closed; an unknown PROTOCOL was not, and it is the same vacuous-confidence
hole one field over: a typo'd proto matches no specific-protocol rule, so the
isolation search finds no leak and reports a confident PASS for a check that
never ran.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.segcheck import _KNOWN_PROTO, check_segmentation  # noqa: E402

_ZONES = {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]}

# A specific-protocol ACL: nothing here matches a probe for a protocol the
# engine does not know, which is exactly what made the old PASS vacuous.
_ACL = ("ip access-list extended T\n"
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"
        " deny ip any any\n")


def _check(policy):
    aces, _ = parse_acls(_ACL)
    return check_segmentation(aces, policy)


def test_unknown_proto_never_certifies_isolation():
    """Regression: reported `PASS: CORP cannot reach PCI on tpc`."""
    f = _check({"zones": _ZONES,
                "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tpc"}]})
    assert not any(x.kind == "segmentation-ok" for x in f)
    err = next(x for x in f if x.kind == "segmentation-error")
    assert err.severity == "high"          # must not be silently ignorable
    assert "unknown protocol 'tpc'" in err.message
    assert "NOT checked" in err.message


def test_unknown_proto_does_not_invent_a_connectivity_failure():
    """must_reach inverts the hole: an unevaluatable assertion would otherwise
    report a phantom CONNECTIVITY BROKEN against a healthy network."""
    f = _check({"zones": _ZONES,
                "must_reach": [{"src": "CORP", "dst": "PCI", "proto": "tpc"}]})
    assert not any(x.kind.startswith("connectivity-") for x in f)
    assert any(x.kind == "segmentation-error" for x in f)


@pytest.mark.parametrize("proto", sorted(_KNOWN_PROTO))
def test_every_known_proto_is_still_evaluated(proto):
    """The guard must reject typos without rejecting real protocols."""
    kinds = {x.kind for x in _check(
        {"zones": _ZONES,
         "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": proto}]})}
    assert "segmentation-error" not in kinds, f"{proto} wrongly rejected"


@pytest.mark.parametrize("proto", ["tcp", "TCP", "Tcp"])
def test_proto_matching_is_case_insensitive(proto):
    kinds = {x.kind for x in _check(
        {"zones": _ZONES,
         "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": proto}]})}
    assert "segmentation-error" not in kinds


def test_documented_protos_are_all_accepted():
    """docs/policy.md advertises these by name — the guard must honor the doc."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    doc = open(os.path.join(root, "docs", "policy.md"), encoding="utf-8").read()
    section = doc.split("**Valid `proto` values:**", 1)[1][:400]
    import re
    for proto in set(re.findall(r"`([a-z0-9]+)`", section)):
        if proto in ("ports",):
            continue
        assert proto in _KNOWN_PROTO, \
            f"docs/policy.md advertises proto {proto!r} but the guard rejects it"


def test_known_proto_set_is_derived_not_hand_listed():
    """Sanity: the set tracks the engine's own protocol families, so adding
    protocol support cannot leave the validator behind."""
    from rulehawk.model import _ICMP_PROTOS, _PORTED, _WILDCARD_PROTO
    from rulehawk.parse import _PROTO_NUM
    assert _WILDCARD_PROTO <= _KNOWN_PROTO
    assert _PORTED <= _KNOWN_PROTO
    assert _ICMP_PROTOS <= _KNOWN_PROTO
    assert set(_PROTO_NUM.values()) <= _KNOWN_PROTO
