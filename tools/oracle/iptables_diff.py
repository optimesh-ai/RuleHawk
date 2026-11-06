"""Differential test: RuleHawk's iptables model vs the real Linux kernel.

    python -m tools.oracle.iptables_diff --random 200 --seed 1
    python -m tools.oracle.iptables_diff path/to/rules.save ...

Needs Docker and the oracle image (tools/oracle/Dockerfile.kernel); the probe
runs in privileged containers named rh-kernel-<n> (started on demand).

Three checks per ruleset and per base chain (FORWARD via forwarding, INPUT via
local delivery):
  (ii)  verdicts — boundary + random packets: kernel accept/drop vs RuleHawk's
        first-match permit/deny ("unknown" when RuleHawk's first match is an
        imprecise rule: RuleHawk would say INDETERMINATE, not a verdict);
  (dead) every rule RuleHawk calls dead/redundant must count 0 packets in the
        kernel after the batch — any count refutes the claim. Probes aimed
        INSIDE each dead rule's space, including conntrack-INVALID packets
        (TCP SYN+FIN), are added so a refutation is actually looked for;
  (i)   witnesses — every must_not_reach witness RuleHawk emits (for a policy
        auto-built from the ruleset's own addresses) is sent alone; the kernel
        must accept it and count it on the rule RuleHawk cites.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import random
import re
import subprocess
import sys
from typing import Dict, List

from rulehawk.analyze import analyze
from rulehawk.parse_iptables import parse_iptables
from rulehawk.segcheck import check_segmentation

from . import gen_iptables
from .packets import sample, usable
from .rhsim import ICMP_NUM, Pkt, by_acl, verdict

_DEAD = {"redundant", "intent-inversion-permit-dead", "intent-inversion-deny-dead",
         "union-redundant", "union-shadowed-deny-dead", "union-shadowed-permit-dead"}
IMAGE = "rh-kernel-oracle"


def ensure_containers(n: int, oracle_dir: str) -> List[str]:
    names = []
    running = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                             capture_output=True, text=True).stdout.split()
    for i in range(n):
        name = f"rh-kernel-{i}"
        if name not in running:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            subprocess.run(["docker", "run", "-d", "--name", name, "--privileged",
                            "-v", f"{oracle_dir}:/oracle:ro", "--entrypoint", "sleep",
                            IMAGE, "infinity"], check=True, capture_output=True)
        names.append(name)
    return names


def probe(container: str, ruleset: str, mode: str, pkts: List[dict], attribute=False):
    req = json.dumps({"ruleset": ruleset, "mode": mode, "packets": pkts,
                      "attribute": attribute})
    r = subprocess.run(["docker", "exec", "-i", container, "python3",
                        "/oracle/kernel_probe.py"], input=req, capture_output=True,
                       text=True, timeout=600)
    if r.returncode:
        raise RuntimeError(f"probe failed: {r.stderr[-2000:]}")
    return json.loads(r.stdout)


def pkt_dict(p: Pkt, flags: int = 0x02) -> dict:
    d = {"proto": p.proto, "src": p.src, "dst": p.dst, "sport": p.sport,
         "dport": p.dport, "icmp_type": p.icmp_type, "icmp_code": p.icmp_code}
    if p.proto == "tcp":
        d["flags"] = flags
    return d


def rule_index_map(text: str) -> Dict[int, tuple]:
    """source line -> (chain, 1-based index in chain) for `-A` lines (save form
    without -I/-R, so file order is chain order)."""
    m, cnt = {}, {}
    if re.search(r"(?m)^\s*(-I|-R|iptables\s+-I|iptables\s+-R)\b", text):
        return m
    for ln, raw in enumerate(text.splitlines(), 1):
        mm = re.match(r"^\s*(?:iptables\s+)?-A\s+(\S+)", raw)
        if mm:
            ch = mm.group(1)
            cnt[ch] = cnt.get(ch, 0) + 1
            m[ln] = (ch, cnt[ch])
    return m


def _witness_pkt(w: str):
    """segcheck witness `src[:sport] -> dst[:dport] (proto [icmp-type])` -> Pkt.
    The "ip" probe (a protocol no rule names) is not a concrete packet: None."""
    m = re.match(r"^([^:\s]+)(?::(\d+))? -> ([^:\s]+)(?::(\d+))? \((\w+)(?: ([\w-]+))?\)$", w)
    if not m:
        return None
    src, sport, dst, port, proto, ity = m.groups()
    if proto not in ("tcp", "udp", "icmp"):
        return None
    it = None
    if proto == "icmp":
        it = ICMP_NUM.get(ity or "echo", None)
        if it is None:
            return None
    return Pkt(proto, src, dst, int(sport) if sport else 40000, int(port or 0),
               icmp_type=it)


def auto_policy(aces) -> dict:
    """must_not_reach between pairs of the ruleset's own (v4) prefixes."""
    nets = sorted({str(a.src) for a in aces if a.src.version == 4 and a.src.prefixlen}
                  | {str(a.dst) for a in aces if a.dst.version == 4 and a.dst.prefixlen})
    zones = {f"Z{i}": [n] for i, n in enumerate(nets[:8])}
    zones["ANY"] = ["0.0.0.0/0"]
    names = list(zones)
    mnr = []
    for s in names:
        for d in names:
            if s != d:
                mnr.append({"src": s, "dst": d, "proto": "ip"})
    return {"zones": zones, "must_not_reach": mnr}


def run_one(container: str, name: str, text: str, rng: random.Random) -> dict:
    aces, notes = parse_iptables(text)
    res = {"name": name, "cmp": 0, "agree": 0, "unknown": 0, "disagree": [],
           "dead_claims": 0, "dead_checked": 0, "dead_refuted": [],
           "witness": 0, "witness_ok": 0, "witness_bad": [], "load_error": None}
    acls = by_acl(aces)
    findings = analyze(aces)
    linemap = rule_index_map(text)
    dead = [f for f in findings if f.kind in _DEAD]
    res["dead_claims"] = len(dead)
    ace_by_id = {f"{a.acl}:{a.seq}": a for a in aces}
    lines_per_chain_line = {}
    for a in aces:
        lines_per_chain_line.setdefault((a.acl, a.line), []).append(a)
    for chain, mode in (("FORWARD", "forward"), ("INPUT", "input")):
        chain_aces = acls.get(chain)
        if not chain_aces:
            continue
        pkts = [p for p in sample(chain_aces, rng) if usable(p.src) and usable(p.dst)]
        # Conntrack keeps state across the probe burst in BOTH modes: a later
        # probe whose 5-tuple equals an earlier one, or its reverse, is no
        # longer NEW (a forwarded GRE a->b makes b->a ESTABLISHED and a
        # NEW-only ACCEPT then misses it). Keep each flow once.
        pkts = one_per_flow(pkts)
        # RuleHawk models host-hook (INPUT/OUTPUT) jumps to user chains as
        # surfaced notes only (no decision), so per-packet INPUT verdicts are
        # not a RuleHawk claim there; class them separately.
        hook_jump = chain != "FORWARD" and re.search(
            rf"(?m)^\s*(?:iptables\s+)?-[AI]\s+{chain}\b.*\s-[jg]\s+(?!ACCEPT|DROP|REJECT|LOG|RETURN)\S+", text)
        dicts = [pkt_dict(p) for p in pkts]
        # dead-rule probes: inside each dead rule's space, SYN and SYN+FIN
        chain_dead = [f for f in dead if f.rule_id.startswith(chain + ":")]
        extra = []
        for f in chain_dead:
            b = ace_by_id.get(f.rule_id)
            if b is None or b.src.version != 4:
                continue
            for p in sample([b], rng, per_ace=6, n_random=0):
                if usable(p.src) and usable(p.dst) and b.src.num_addresses and \
                        ipaddress.ip_address(p.src) in b.src and \
                        ipaddress.ip_address(p.dst) in b.dst:
                    extra.append(pkt_dict(p))
                    if p.proto == "tcp":
                        extra.append(pkt_dict(p, flags=0x03))   # SYN+FIN: INVALID
        out = probe(container, text, mode, dicts + extra)
        if out.get("load_error"):
            res["load_error"] = out["load_error"]
            return res
        for p, kv in zip(pkts, out["verdicts"][:len(pkts)]):
            rv, ace = verdict(chain_aces, p)
            if rv == "unknown":
                res["unknown"] += 1
                continue
            res["cmp"] += 1
            if (rv == "permit") == (kv == "accept"):
                res["agree"] += 1
            else:
                # Unsolicited ICMP replies/errors are never NEW to conntrack
                # (INVALID/UNTRACKED), so state-matching rules treat them
                # differently from the connection-initiating packets RuleHawk
                # models. Kept, but classed separately.
                cls = ("icmp-non-initiating" if p.proto == "icmp"
                       and p.icmp_type not in (8, 13) else
                       "host-hook-jump" if hook_jump else "model")
                res["disagree"].append({"class": cls, "chain": chain, "pkt": str(p), "kernel": kv,
                                        "rulehawk": rv,
                                        "rh_rule": ace.raw if ace else "(implicit/policy)",
                                        "rh_line": ace.line if ace else 0})
        counts = {(c, i): n for c, i, n in out.get("counters", [])}
        for f in chain_dead:
            b = ace_by_id.get(f.rule_id)
            if b is None or b.line not in linemap:
                continue
            if len(lines_per_chain_line.get((b.acl, b.line), [])) != 1 or \
                    "resolved jump" in b.raw or linemap[b.line][0] != b.acl:
                continue      # multiport/jump expansion: kernel rule != one ACE
            res["dead_checked"] += 1
            kidx = linemap[b.line]
            if counts.get(kidx, 0) > 0:
                res["dead_refuted"].append({"kind": f.kind, "rule": f.rule_id,
                                            "raw": b.raw, "line": b.line,
                                            "kernel_pkts": counts[kidx],
                                            "cited": f.cited})
    # (i) witnesses (FORWARD only: segcheck's transit path)
    pol = auto_policy([a for a in aces if a.transit])
    wf = [f for f in check_segmentation(aces, pol)
          if f.kind == "segmentation-violation" and f.witness][:15]
    wpk, wmeta = [], []
    for f in wf:
        p = _witness_pkt(f.witness)
        if p is None or not (usable(p.src) and usable(p.dst)):
            continue
        cited = [ace_by_id[f.rule_id]] if f.rule_id in ace_by_id else []
        wpk.append(pkt_dict(p))
        wmeta.append((f, p, cited))
    if wpk and "FORWARD" in acls:
        out = probe(container, text, "forward", wpk, attribute=True)
        for (f, p, cited), kv, hits in zip(wmeta, out["verdicts"], out["hits"]):
            res["witness"] += 1
            hitset = {(c, i) for c, i in hits}
            ok = kv == "accept"
            if ok and cited and cited[0].line in linemap:
                ok = linemap[cited[0].line] in hitset
            if ok:
                res["witness_ok"] += 1
            else:
                res["witness_bad"].append({"class": "icmp-non-initiating"
                                           if p.proto == "icmp" and p.icmp_type not in (8, 13)
                                           else "model",
                                           "witness": f.witness, "pkt": str(p),
                                           "kernel": kv, "rule": f.rule,
                                           "hits": hits})
    return res


def one_per_flow(pkts):
    """Drop probes whose 5-tuple (or its reverse) was already sent."""
    seen_t, kept = set(), []
    for p in pkts:
        t = (p.proto, p.src, p.sport, p.dst, p.dport)
        r = (p.proto, p.dst, p.dport, p.src, p.sport)
        if t in seen_t or r in seen_t:
            continue
        seen_t.add(t)
        kept.append(p)
    return kept


def run_many(work, jobs: int = 4, seed: int = 1):
    """Run every (name, ruleset-text) through the kernel; (totals, results)."""
    import os
    import queue
    oracle_dir = os.path.dirname(os.path.abspath(__file__))
    cons = ensure_containers(jobs, oracle_dir)
    pool = queue.Queue()
    for c in cons:
        pool.put(c)

    def task(k, n, t):
        c = pool.get()          # one ruleset per container at a time
        try:
            return run_one(c, n, t, random.Random(seed * 7919 + k))
        finally:
            pool.put(c)

    results = []
    with cf.ThreadPoolExecutor(len(cons)) as ex:
        futs = [ex.submit(task, k, n, t) for k, (n, t) in enumerate(work)]
        for (n, t), fu in zip(work, futs):
            try:
                results.append(fu.result())
            except Exception as e:      # noqa: BLE001
                results.append({"name": n, "error": str(e)})
    tot = {k: sum(r.get(k, 0) for r in results if isinstance(r.get(k, 0), int))
           for k in ("cmp", "agree", "unknown", "dead_claims", "dead_checked",
                     "witness", "witness_ok")}
    for k in ("disagree", "witness_bad"):
        tot[k] = sum(len(r.get(k, [])) for r in results)
        tot[k + "_model"] = sum(1 for r in results for x in r.get(k, [])
                                if x.get("class") == "model")
    tot["dead_refuted"] = sum(len(r.get("dead_refuted", [])) for r in results)
    tot["rulesets"] = len(results)
    tot["load_errors"] = sum(1 for r in results if r.get("load_error"))
    tot["errors"] = sum(1 for r in results if r.get("error"))
    return tot, results


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--random", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--json", default="")
    a = ap.parse_args(argv)
    work = []
    rng = random.Random(a.seed)
    for i in range(a.random):
        work.append((f"random-{a.seed}-{i}", gen_iptables.random_ruleset(rng)))
    for f in a.files:
        work.append((f, open(f, encoding="utf-8", errors="replace").read()))
    tot, results = run_many(work, a.jobs, a.seed)
    print(json.dumps(tot, indent=1))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"totals": tot, "results": results,
                       "rulesets": {n: t for n, t in work}}, fh, indent=1)
    bad = (tot["disagree_model"] + tot["witness_bad_model"] + tot["dead_refuted"]
           + tot["errors"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
