"""Boundary + random packet sampling for the differential oracles.

For each ACE the sampler builds packets on and just outside every edge of its
match space (first/last address of each prefix and the neighbours outside it,
each end of each port range and the port beyond it), plus packets inside it,
plus uniformly random packets. Edges are where a parser that mis-reads a
mask, an open port range or an inclusive bound disagrees with the device."""

from __future__ import annotations

import ipaddress
import random
from typing import List

from rulehawk.model import ACE, _PORTED, _WILDCARD_PROTO

from .rhsim import ICMP_NUM, Pkt, icmp_type_num

# Destinations/sources the probe harness can't use: the kernel drops these
# (martians, multicast, broadcast) before the filter table ever sees them, and
# 198.18.255.0/24 holds the probe router's own interface addresses.
_BAD = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3", "198.18.255.0/24")]


def usable(a: str) -> bool:
    ip = ipaddress.ip_address(a)
    return ip.version == 4 and not any(ip in n for n in _BAD)


def _addr_cands(net) -> List[str]:
    lo, hi = int(net.network_address), int(net.broadcast_address)
    c = {lo, hi, lo - 1, hi + 1, (lo + hi) // 2, min(lo + 1, hi)}
    return [str(ipaddress.IPv4Address(x)) for x in c if 0 <= x < 2 ** 32]


def _port_cands(pr) -> List[int]:
    c = {pr.lo, pr.hi, pr.lo - 1, pr.hi + 1, (pr.lo + pr.hi) // 2}
    return [p for p in c if 0 <= p <= 65535]


def _rand_addr(rng) -> str:
    while True:
        a = str(ipaddress.IPv4Address(rng.randrange(1 << 24, 224 << 24)))
        if usable(a):
            return a


def sample(aces: List[ACE], rng: random.Random, per_ace: int = 8,
           n_random: int = 40) -> List[Pkt]:
    v4 = [a for a in aces if a.src.version == 4 and a.dst.version == 4]
    pool_addr = set()
    pool_port = {0, 1, 22, 53, 80, 443, 1023, 1024, 65535}
    pool_icmp = {0, 3, 8, 11}
    for a in v4:
        pool_addr.update(_addr_cands(a.src))
        pool_addr.update(_addr_cands(a.dst))
        pool_port.update(_port_cands(a.src_port))
        pool_port.update(_port_cands(a.dst_port))
        if a.icmp_type:
            t, _ = icmp_type_num(a.icmp_type)
            if t is not None and t >= 0:
                pool_icmp.add(t)
    pool_addr = sorted(x for x in pool_addr if usable(x)) or [_rand_addr(rng)]
    pool_port = sorted(pool_port)
    out: List[Pkt] = []

    def mk(proto, s, d, sp, dp, it):
        if proto == "tcp" or proto == "udp":
            return Pkt(proto, s, d, sp, dp)
        if proto == "icmp":
            return Pkt("icmp", s, d, icmp_type=it, icmp_code=rng.choice([0, 0, 1]))
        return Pkt(proto, s, d)

    for a in v4:
        sc = [x for x in _addr_cands(a.src) if usable(x)] or pool_addr
        dc = [x for x in _addr_cands(a.dst) if usable(x)] or pool_addr
        spc = _port_cands(a.src_port) if a.proto in _PORTED else pool_port
        dpc = _port_cands(a.dst_port) if a.proto in _PORTED else pool_port
        for _ in range(per_ace):
            if a.proto in _WILDCARD_PROTO:
                proto = rng.choice(["tcp", "udp", "icmp", "gre"])
            elif a.proto in ("tcp", "udp", "icmp"):
                proto = a.proto
            else:
                proto = rng.choice([a.proto, "tcp"])
            it = None
            if proto == "icmp":
                t, _ = icmp_type_num(a.icmp_type)
                it = t if (t is not None and t >= 0 and rng.random() < 0.6) \
                    else rng.choice(sorted(pool_icmp))
            out.append(mk(proto, rng.choice(sc), rng.choice(dc), rng.choice(spc),
                          rng.choice(dpc), it))
    for _ in range(n_random):
        proto = rng.choice(["tcp", "tcp", "udp", "icmp", "gre"])
        s = rng.choice(pool_addr) if rng.random() < 0.7 else _rand_addr(rng)
        d = rng.choice(pool_addr) if rng.random() < 0.7 else _rand_addr(rng)
        sp = rng.choice(pool_port) if rng.random() < 0.8 else rng.randrange(65536)
        dp = rng.choice(pool_port) if rng.random() < 0.8 else rng.randrange(65536)
        out.append(mk(proto, s, d, sp, dp, rng.choice(sorted(pool_icmp))))
    return out
