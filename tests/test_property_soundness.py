"""Property-based soundness oracle for the analysis engine.

The one promise RuleHawk must never break: when it says a rule is DEAD
(shadowed / redundant / union-shadowed), that rule truly can never be the
first match — deleting it changes nothing. A false claim here gets a
load-bearing firewall rule deleted.

This test is the mechanical check of that promise: generate hundreds of random
ACLs over a small, fully-enumerable packet universe, simulate exact first-match
semantics for EVERY packet in the universe, and assert:

  1. every covers(a, b) verdict is truth: each enumerated packet matching b
     also matches a;
  2. every dead/redundant finding names a rule that is never the first match
     for any enumerated packet.

Enumeration can only refute (a violation is a hard soundness bug); it cannot
prove claims over the full 2^104 packet space. That is the right trade: false
positives are the catastrophic direction, and this hunts exactly those.
Deterministic seeds keep the suite reproducible.
"""

from __future__ import annotations

import ipaddress
import itertools
import random

from rulehawk.analyze import analyze
from rulehawk.model import ACE, PortRange, covers

# --------------------------------------------------------------------------- #
# a tiny, fully-enumerable packet universe
# --------------------------------------------------------------------------- #
_ADDRS = [ipaddress.ip_address(f"10.0.0.{i}") for i in range(8)]   # 10.0.0.0/29
_PORTS = [0, 21, 22, 80, 443, 65535]
_PACKET_PROTOS = ["tcp", "udp", "icmp"]
_ICMP_TYPES = [None, "echo", "echo-reply"]

# Networks the generator may pick for src/dst (all within/over the universe).
_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/0", "10.0.0.0/29", "10.0.0.0/30", "10.0.0.4/30",
    "10.0.0.0/31", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/31",
    "10.0.0.0/32", "10.0.0.1/32", "10.0.0.3/32", "10.0.0.5/32", "10.0.0.7/32",
)]
_RANGES = [PortRange(), PortRange(0, 21), PortRange(22, 22), PortRange(22, 443),
           PortRange(80, 80), PortRange(80, 443), PortRange(443, 443),
           PortRange(443, 65535), PortRange(65535, 65535)]
_ACE_PROTOS = ["ip", "tcp", "udp", "icmp"]


def _packets():
    """Every packet in the universe: (proto, src, dst, sport, dport, icmp_type).
    tcp/udp vary over ports; icmp varies over types (ports fixed)."""
    for proto in ("tcp", "udp"):
        for src, dst, sp, dp in itertools.product(_ADDRS, _ADDRS, _PORTS, _PORTS):
            yield (proto, src, dst, sp, dp, None)
    for src, dst, it in itertools.product(_ADDRS, _ADDRS, _ICMP_TYPES[1:]):
        yield ("icmp", src, dst, 0, 0, it)


_ALL_PACKETS = list(_packets())


def _matches(a: ACE, pkt) -> bool:
    """Ground-truth: does this ACE match this concrete packet?

    Mirrors real first-match semantics for EXACT rules. Imprecise/stateful
    rules have no exact space, so the generator never emits them as exact
    (they get their own generator arm to exercise the soundness gates).
    """
    proto, src, dst, sp, dp, icmp_type = pkt
    if a.proto not in ("ip",) and a.proto != proto:
        return False
    if src not in a.src or dst not in a.dst:
        return False
    if proto in ("tcp", "udp"):
        if not (a.src_port.contains(sp) and a.dst_port.contains(dp)):
            return False
    if proto == "icmp" and a.proto == "icmp" and a.icmp_type is not None:
        if a.icmp_type != icmp_type:
            return False
    return True


def _first_match(aces, pkt):
    for a in aces:
        if a.imprecise or a.stateful:
            # An inexact rule's true space is unknowable to the oracle; treat it
            # as "could match anything" is unsound for the oracle itself, so the
            # generator only emits them where the claim under test must already
            # ignore them. Skipping = the rule matched nothing, which is one
            # legal concretization of its space.
            continue
        if _matches(a, pkt):
            return a
    return None


def _random_ace(rng: random.Random, seq: int, allow_inexact: bool) -> ACE:
    proto = rng.choice(_ACE_PROTOS)
    kw = {}
    if proto in ("tcp", "udp"):
        kw["src_port"] = rng.choice(_RANGES)
        kw["dst_port"] = rng.choice(_RANGES)
    if proto == "icmp" and rng.random() < 0.5:
        kw["icmp_type"] = rng.choice(_ICMP_TYPES[1:])
    if allow_inexact:
        r = rng.random()
        if r < 0.10:
            kw["imprecise"] = True
        elif r < 0.15 and proto == "tcp":
            kw["stateful"] = True
    return ACE(seq=seq, action=rng.choice(["permit", "deny"]),
               proto=proto, src=rng.choice(_NETS), dst=rng.choice(_NETS),
               raw=f"rule-{seq}", acl="FUZZ", **kw)


_DEAD_KINDS = {
    "redundant", "union-redundant",
    "intent-inversion-permit-dead", "intent-inversion-deny-dead",
    "union-shadowed-permit-dead", "union-shadowed-deny-dead",
}


def test_covers_verdicts_are_truth_under_enumeration():
    rng = random.Random(1337)
    pairs = 0
    while pairs < 400:
        a = _random_ace(rng, 1, allow_inexact=True)
        b = _random_ace(rng, 2, allow_inexact=True)
        if not covers(a, b):
            continue
        pairs += 1
        for pkt in _ALL_PACKETS:
            if _matches(b, pkt):
                assert _matches(a, pkt), (
                    f"covers() lied: {a} claims to cover {b} "
                    f"but packet {pkt} matches b and not a")
    assert pairs == 400  # the generator actually produced positive verdicts


def test_every_dead_claim_survives_exhaustive_first_match_simulation():
    rng = random.Random(20260708)
    dead_claims_checked = 0
    for trial in range(150):
        n = rng.randint(3, 9)
        aces = [_random_ace(rng, i + 1, allow_inexact=True) for i in range(n)]
        findings = [f for f in analyze(aces) if f.kind in _DEAD_KINDS]
        if not findings:
            continue
        dead = {f.rule_id for f in findings}
        by_id = {f"{a.acl}:{a.seq}": a for a in aces}
        for pkt in _ALL_PACKETS:
            hit = _first_match(aces, pkt)
            if hit is None:
                continue
            rid = f"{hit.acl}:{hit.seq}"
            assert rid not in dead, (
                f"SOUNDNESS BUG (trial {trial}): {by_id[rid]} was reported "
                f"dead ({[f.kind for f in findings if f.rule_id == rid]}) but "
                f"is the FIRST MATCH for packet {pkt}")
        dead_claims_checked += len(dead)
    # The generator must actually exercise the detector, not vacuously pass.
    assert dead_claims_checked >= 50, (
        f"generator produced too few dead-rule claims ({dead_claims_checked}) "
        f"— tune it, don't let the oracle go blind")


def test_redundant_claims_removal_is_behavior_preserving():
    """Stronger check for same-action redundancy: deleting the rule leaves the
    first-match ACTION identical for every packet."""
    rng = random.Random(424242)
    checked = 0
    for _ in range(400):
        n = rng.randint(3, 8)
        aces = [_random_ace(rng, i + 1, allow_inexact=False) for i in range(n)]
        redundant = [f for f in analyze(aces)
                     if f.kind in ("redundant", "union-redundant")]
        for f in redundant:
            seq = int(f.rule_id.split(":")[1])
            without = [a for a in aces if a.seq != seq]
            for pkt in _ALL_PACKETS:
                before = _first_match(aces, pkt)
                after = _first_match(without, pkt)
                b_act = before.action if before else None
                a_act = after.action if after else None
                assert b_act == a_act, (
                    f"removing 'redundant' rule {f.rule_id} changed the verdict "
                    f"for {pkt}: {b_act} -> {a_act}")
            checked += 1
    assert checked >= 20, f"too few redundancy claims exercised ({checked})"
