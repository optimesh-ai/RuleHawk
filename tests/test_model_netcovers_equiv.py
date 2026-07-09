"""Equivalence fuzz: the integer-math `_net_covers` must match `subnet_of`.

`_net_covers` was rewritten from `b.subnet_of(a)` to exact integer range
containment for performance (analyze() is quadratic in rules and _net_covers
is its hottest call). Soundness requires the rewrite be *semantically
identical* — a divergence in either direction is a bug:
  * new True where subnet_of says False  -> false shadow proof (false PASS-ish)
  * new False where subnet_of says True  -> missed finding

This test fuzzes random v4/v4, v6/v6 and mixed-version pairs and asserts
byte-for-byte agreement with the stdlib oracle, plus pins the known edges.
"""

import ipaddress
import random

import pytest

from rulehawk.model import _net_covers


def _oracle(a, b) -> bool:
    """The original implementation: subnet_of with the version pre-check."""
    if a.version != b.version:
        return False
    try:
        return b.subnet_of(a)
    except (TypeError, ValueError):
        return False


def _rand_net(rng: random.Random, version: int):
    if version == 4:
        bits, cls = 32, ipaddress.IPv4Network
        addr = rng.getrandbits(32)
    else:
        bits, cls = 128, ipaddress.IPv6Network
        addr = rng.getrandbits(128)
    plen = rng.randint(0, bits)
    return cls((addr, plen), strict=False)


def _rand_related_net(rng: random.Random, base):
    """A net near/inside `base` so containment cases actually occur."""
    bits = base.max_prefixlen
    plen = rng.randint(base.prefixlen, bits)
    span = int(base.broadcast_address) - int(base.network_address)
    addr = int(base.network_address) + (rng.getrandbits(64) % (span + 1))
    cls = type(base)
    return cls((addr, plen), strict=False)


@pytest.mark.parametrize("version", [4, 6])
def test_fuzz_matches_subnet_of_same_version(version):
    rng = random.Random(0xC0FFEE + version)
    trials = 20_000
    hits = 0
    for _ in range(trials):
        a = _rand_net(rng, version)
        # Half the pairs are 'related' (b sampled inside/near a) so we
        # exercise the True branch heavily, not just random disjoint nets.
        b = _rand_related_net(rng, a) if rng.random() < 0.5 else _rand_net(rng, version)
        expected = _oracle(a, b)
        assert _net_covers(a, b) == expected, f"mismatch: a={a} b={b}"
        # Symmetric direction too (covers is not symmetric — check both).
        assert _net_covers(b, a) == _oracle(b, a), f"mismatch: a={b} b={a}"
        hits += expected
    # Sanity: the fuzz must actually exercise the True branch.
    assert hits > trials // 10


def test_fuzz_mixed_versions_never_cover():
    rng = random.Random(0xBEEF)
    for _ in range(2_000):
        v4 = _rand_net(rng, 4)
        v6 = _rand_net(rng, 6)
        assert _net_covers(v4, v6) is False
        assert _net_covers(v6, v4) is False


@pytest.mark.parametrize(
    "a, b, expected",
    [
        # identical nets cover each other
        ("10.0.0.0/8", "10.0.0.0/8", True),
        ("::/0", "::/0", True),
        # default route covers everything
        ("0.0.0.0/0", "203.0.113.7/32", True),
        ("::/0", "2001:db8::/32", True),
        # strict containment
        ("10.0.0.0/8", "10.1.2.0/24", True),
        ("10.1.2.0/24", "10.0.0.0/8", False),
        # adjacent siblings do not cover
        ("10.0.0.0/24", "10.0.1.0/24", False),
        # host routes
        ("192.0.2.1/32", "192.0.2.1/32", True),
        ("192.0.2.1/32", "192.0.2.2/32", False),
        # widest-vs-narrowest extremes
        ("0.0.0.0/0", "0.0.0.0/32", True),
        ("255.255.255.255/32", "0.0.0.0/0", False),
        ("::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", True),
    ],
)
def test_known_edges(a, b, expected):
    an = ipaddress.ip_network(a)
    bn = ipaddress.ip_network(b)
    assert _net_covers(an, bn) is expected
    assert _oracle(an, bn) is expected  # the oracle agrees on the pins too


def test_mixed_version_pin():
    v4 = ipaddress.ip_network("0.0.0.0/0")
    v6 = ipaddress.ip_network("::/0")
    assert _net_covers(v4, v6) is False
    assert _net_covers(v6, v4) is False
