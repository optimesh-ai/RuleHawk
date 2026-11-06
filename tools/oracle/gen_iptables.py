"""Random iptables-save rulesets over a small, collision-prone universe.

Rules draw addresses and ports from small pools so that rules overlap, shadow
each other and leave narrow gaps — the cases a first-match model gets wrong.
Every construct RuleHawk claims to model (CIDRs, port ranges and open ranges,
multiport, ICMP types, conntrack states, REJECT, LOG, comments, custom-chain
`-j`/`-g`, RETURN, chain policies) appears, plus a few it must flag as
imprecise (negation, `-i`, `--syn`, unknown modules)."""

from __future__ import annotations

import random

NETS = ["10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/26", "10.0.0.64/26",
        "10.0.0.5/32", "10.0.0.130/32", "10.0.1.0/24", "10.0.0.0/16", "10.0.0.0/8",
        "192.168.1.0/24", "192.168.1.10", "172.16.0.0/12", "0.0.0.0/0"]
PORTS = ["22", "53", "80", "443", "1000:2000", "1500:1600", "0:1023", "1024:65535",
         ":100", "8000:", "3389", "65535", "1"]
MULTI = ["22,80,443", "53,1000:1100", "80:90,443", "22"]
ICMP = ["echo-request", "echo-reply", "8", "0", "destination-unreachable", "3/1",
        "time-exceeded", "any"]
STATES = ["NEW", "ESTABLISHED,RELATED", "NEW,ESTABLISHED", "INVALID", "RELATED"]


def _rule(rng: random.Random, chain: str, customs, in_custom: bool) -> str:
    p = []
    if rng.random() < 0.55:
        p += ["-s", rng.choice(NETS)] if rng.random() > 0.05 else ["!", "-s", rng.choice(NETS[:-1])]
    if rng.random() < 0.55:
        p += ["-d", rng.choice(NETS)] if rng.random() > 0.05 else ["!", "-d", rng.choice(NETS[:-1])]
    proto = rng.choices(["tcp", "udp", "icmp", None, "gre", "6", "17", "all"],
                        [30, 22, 12, 18, 3, 3, 3, 3])[0]
    if proto:
        p += ["-p", proto]
    if proto in ("tcp", "udp", "6", "17"):
        r = rng.random()
        if r < 0.45:
            p += ["--dport", rng.choice(PORTS)]
        elif r < 0.6:
            p += ["-m", "multiport", "--dports", rng.choice(MULTI)]
        elif r < 0.68:
            p += ["--sport", rng.choice(PORTS)]
        elif r < 0.72:
            p += ["--sport", rng.choice(PORTS), "--dport", rng.choice(PORTS)]
        if proto in ("tcp", "6") and rng.random() < 0.04:
            p += ["--syn"]
    if proto == "icmp" and rng.random() < 0.7:
        p += ["--icmp-type", rng.choice(ICMP)]
    if rng.random() < 0.12:
        p += ["-m", "conntrack", "--ctstate", rng.choice(STATES)]
    if rng.random() < 0.03:
        p += ["-i", "vr0"]
    if rng.random() < 0.08:
        p += ["-m", "comment", "--comment", '"rule note"']
    if rng.random() < 0.03:
        p += ["-m", "limit", "--limit", "5/sec"]
    tg = rng.random()
    if customs and not in_custom and tg < 0.12:
        p += [rng.choice(["-j", "-j", "-g"]), rng.choice(customs)]
    elif in_custom and tg < 0.08:
        p += ["-j", "RETURN"]
    elif tg < 0.17:
        p += ["-j", "LOG"]
    else:
        t = rng.choices(["ACCEPT", "DROP", "REJECT"], [50, 35, 15])[0]
        p += ["-j", t]
        if t == "REJECT" and rng.random() < 0.5:
            p += ["--reject-with", "icmp-port-unreachable"]
    return "-A " + chain + " " + " ".join(p)


def random_ruleset(rng: random.Random, n_rules=(4, 14)) -> str:
    customs = [f"C{i}" for i in range(rng.choice([0, 0, 1, 2]))]
    out = ["*filter"]
    for ch in ("INPUT", "FORWARD", "OUTPUT"):
        pol = rng.choice(["ACCEPT", "DROP"]) if ch != "OUTPUT" else "ACCEPT"
        out.append(f":{ch} {pol} [0:0]")
    for c in customs:
        out.append(f":{c} - [0:0]")
    for ch in ("INPUT", "FORWARD"):
        for _ in range(rng.randint(*n_rules)):
            out.append(_rule(rng, ch, customs, False))
    for c in customs:
        for _ in range(rng.randint(1, 5)):
            out.append(_rule(rng, c, [], True))
    out.append("COMMIT")
    return "\n".join(out) + "\n"
