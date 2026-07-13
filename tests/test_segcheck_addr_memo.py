"""Large-audit tractability + verdict correctness (BUILD packet 8 successor).

The original file pinned an lru_cache over `ip_address(str)` that killed an
O(n^2) re-parse in the old single-witness evaluator. The exact space-subtraction
search that replaced that evaluator never round-trips addresses through strings
during the search (witness strings are rendered once, at report time), so the
memo — and the quadratic shape it patched — no longer exists. What that cache
ultimately protected is still worth pinning, on the same adversarial input:

  1. a large PASS audit (hundreds of scoped denies above a broad permit) stays
     tractable and terminates within the engine's own work budget — no
     "too complex to search" fail-closed downgrade on a config this ordinary;
  2. the verdicts on that input are exactly right: the permitted 3389 flow is a
     concrete CRITICAL violation, and the fully-denied flow is a genuine PASS.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_PORTLESS_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [
        {"src": "CORP", "dst": "PCI", "proto": "tcp"},  # portless -> heavy path
    ],
}


def _big_acl(n=400):
    """n scoped denies inside PCI, a permit on 3389, then a full-width deny.
    Port 3389 leaks (except on the /24s denied at 445? no — the denies are
    port-445-scoped, so 3389 is permitted across the whole /16)."""
    lines = ["ip access-list extended BIG"]
    for i in range(n):
        lines.append(f" deny tcp 10.20.0.0 0.0.255.255 10.10.{i % 256}.0 0.0.0.255 eq 445")
    lines.append(" permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 3389")
    lines.append(" deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255")
    return "\n".join(lines) + "\n"


def test_large_audit_finds_the_3389_leak_not_too_complex():
    # 400+ rules must neither blow the work budget (a "too complex" fail-closed
    # indeterminate) nor miss the leak: 3389 is permitted through every scoped
    # deny, so the portless assertion yields a concrete CRITICAL violation.
    aces, _ = parse_acls(_big_acl())
    findings = check_segmentation(aces, _PORTLESS_POLICY)
    kinds = {f.kind for f in findings}
    assert "segmentation-violation" in kinds
    assert "segmentation-indeterminate" not in kinds     # budget was enough
    viol = next(f for f in findings if f.kind == "segmentation-violation")
    assert ":3389" in viol.witness


def test_large_fully_denied_audit_is_a_genuine_pass():
    # Same shape without the permit: everything is denied -> honest PASS, and
    # again no budget-exhaustion downgrade.
    lines = ["ip access-list extended BIG"]
    for i in range(400):
        lines.append(f" deny tcp 10.20.0.0 0.0.255.255 10.10.{i % 256}.0 0.0.0.255 eq 445")
    lines.append(" deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255")
    aces, _ = parse_acls("\n".join(lines) + "\n")
    findings = check_segmentation(aces, _PORTLESS_POLICY)
    assert [f.kind for f in findings] == ["segmentation-ok"]
