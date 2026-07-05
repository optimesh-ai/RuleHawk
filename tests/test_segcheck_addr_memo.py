"""The witness-address parse in segcheck is memoized to kill an O(n^2) re-parse
on large PASS audits (BUILD packet 8). These tests pin BOTH properties that make
the memo safe: (1) it is a pure str->address cache that never changes a verdict,
and (2) it is actually reused across the many _rule_matches calls per witness.

ip_address(str) is a pure function of the string, so memoizing it cannot alter
any finding — we assert the produced findings are byte-identical to a run with
the cache disabled, and that the cache is genuinely hit (real O(n^2) collapse).
"""

from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk import segcheck  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [
        {"src": "CORP", "dst": "PCI", "proto": "tcp"},  # portless -> heavy path
    ],
}


def _findings_tuple(aces, policy):
    return [(f.rule_id, f.kind, f.severity, f.message, f.witness, f.fix)
            for f in check_segmentation(aces, policy)]


def _big_pass_acl(n=400):
    """n denies covering the forbidden CORP->PCI space, then a broad permit.
    The forbidden flow is provably denied (PASS) but the witness search evaluates
    the ordered stream once per candidate -> the exact O(n^2) re-parse shape."""
    lines = ["ip access-list extended BIG"]
    for i in range(n):
        # non-overlapping /24 denies inside PCI; keep the whole /16 covered enough
        # to exercise many rules while the final permit still leaks-then-denied.
        lines.append(f" deny tcp 10.20.0.0 0.0.255.255 10.10.{i % 256}.0 0.0.0.255 eq 445")
    lines.append(" permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 3389")
    lines.append(" deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255")
    return "\n".join(lines) + "\n"


def test_memo_is_a_bounded_lru_cache_over_ip_address():
    # Additive, sound: it must delegate to the real parser.
    assert segcheck._addr("10.10.0.1") == ipaddress.ip_address("10.10.0.1")
    assert segcheck._addr("2001:db8::1") == ipaddress.ip_address("2001:db8::1")
    info = segcheck._addr.cache_info()
    assert info.maxsize is not None and info.maxsize > 0  # bounded, not unbounded


def test_memo_does_not_change_findings():
    """Byte-identical verdicts with the cache disabled vs enabled — proof the
    optimization is purely a speedup, not a semantics change."""
    for text in (_big_pass_acl(),
                 "ip access-list extended V\n"
                 " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"):
        aces, _ = parse_acls(text)

        segcheck._addr.cache_clear()
        with_cache = _findings_tuple(aces, _POLICY)

        # Disable memoization by monkeypatching to the raw parser, then compare.
        orig = segcheck._addr
        try:
            segcheck._addr = ipaddress.ip_address  # type: ignore[assignment]
            no_cache = _findings_tuple(aces, _POLICY)
        finally:
            segcheck._addr = orig

        assert with_cache == no_cache


def test_memo_is_actually_reused_on_repeated_witness():
    """The witness (swit,dwit) is fixed per candidate, so a large stream must
    HIT the cache many times — that reuse is the whole point (O(n^2)->O(n))."""
    aces, _ = parse_acls(_big_pass_acl())
    segcheck._addr.cache_clear()
    check_segmentation(aces, _POLICY)
    info = segcheck._addr.cache_info()
    # Far more hits than misses: the same handful of witness strings are parsed
    # once and then served from cache across hundreds of rule evaluations.
    assert info.hits > info.misses
    assert info.hits > 100
