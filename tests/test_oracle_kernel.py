"""Differential test against the real Linux kernel (opt-in: needs Docker).

    RULEHAWK_KERNEL_ORACLE=1 python -m pytest tests/test_oracle_kernel.py

Builds tools/oracle/Dockerfile.kernel, loads random iptables rulesets into a
privileged container's netfilter, sends crafted packets and asserts RuleHawk's
model never disagrees with the kernel outside the two documented classes
(unsolicited ICMP replies/errors, which conntrack never sees as NEW; and
INPUT/OUTPUT jumps to user chains, which RuleHawk surfaces but does not decide).
Skipped in the normal suite. CI runs it from .github/workflows/oracle.yml.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

pytestmark = pytest.mark.skipif(
    os.environ.get("RULEHAWK_KERNEL_ORACLE") != "1" or not shutil.which("docker"),
    reason="kernel oracle is opt-in (RULEHAWK_KERNEL_ORACLE=1, needs Docker)")


@pytest.fixture(scope="module")
def image():
    d = os.path.join(ROOT, "tools", "oracle")
    subprocess.run(["docker", "build", "-q", "-t", "rh-kernel-oracle", "-f",
                    os.path.join(d, "Dockerfile.kernel"), d], check=True)
    return "rh-kernel-oracle"


def test_random_rulesets_agree_with_the_kernel(image):
    import random

    from tools.oracle import gen_iptables
    from tools.oracle.iptables_diff import run_many
    n = int(os.environ.get("RULEHAWK_ORACLE_N", "60"))
    seed = int(os.environ.get("RULEHAWK_ORACLE_SEED", "3"))
    rng = random.Random(seed)
    work = [(f"random-{seed}-{i}", gen_iptables.random_ruleset(rng)) for i in range(n)]
    tot, results = run_many(work, jobs=4, seed=seed)
    print(tot)
    assert tot["errors"] == 0 and tot["load_errors"] == 0, tot
    assert tot["cmp"] > 1000 and tot["witness"] > 50, tot
    assert tot["dead_refuted"] == 0, [r["dead_refuted"] for r in results if r.get("dead_refuted")]
    assert tot["disagree_model"] == 0, [x for r in results for x in r.get("disagree", [])
                                        if x["class"] == "model"][:5]
    assert tot["witness_bad_model"] == 0, [x for r in results for x in r.get("witness_bad", [])
                                           if x["class"] == "model"][:5]


def test_samples_agree_with_the_kernel(image):
    from tools.oracle.iptables_diff import run_many
    path = os.path.join(ROOT, "samples", "iptables_save.txt")
    tot, results = run_many([(path, open(path).read())], jobs=1)
    assert tot["errors"] == 0 and tot["dead_refuted"] == 0, results
    assert tot["disagree_model"] == 0 and tot["witness_bad_model"] == 0, results


# --- capture: only the probe itself reads "accept" (seed 10, ruleset 142) ---
# A self-addressed ICMP echo hitting REJECT drew an ICMP error with the same
# outer (proto, src, dst) as the probe, quoting its tag; the oracle read that
# as the probe getting through. tests/test_oracle_probe_capture.py covers the
# frame matching without Docker; these ask the kernel. RFC 5737 addresses.

_HOST, _PEER, _FAR = "192.0.2.130", "198.51.100.7", "203.0.113.9"


def _rules(chain, target):
    return ("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
            f":OUTPUT ACCEPT [0:0]\n-A {chain} -j {target}\nCOMMIT\n")


def _pkt(proto, src, dst, **kw):
    d = {"proto": proto, "src": src, "dst": dst, "sport": None, "dport": None,
         "icmp_type": None, "icmp_code": None}
    if proto == "icmp":
        d.update(icmp_type=8, icmp_code=0)
    if proto in ("tcp", "udp"):
        d.update(sport=40000, dport=443 if proto == "tcp" else 53)
    d.update(kw)
    return d


def _kernel(ruleset, mode, pkts):
    from tools.oracle.iptables_diff import ensure_containers, probe
    [c] = ensure_containers(1, os.path.join(ROOT, "tools", "oracle"))
    out = probe(c, ruleset, mode, pkts)
    assert out["load_error"] is None, out
    return out["verdicts"]


@pytest.mark.parametrize("reject_with", ["icmp-port-unreachable", "icmp-net-unreachable",
                                         "icmp-host-unreachable", "icmp-admin-prohibited"])
def test_self_addressed_packet_hitting_reject_reads_deny(image, reject_with):
    rs = _rules("INPUT", f"REJECT --reject-with {reject_with}")
    pk = [_pkt("icmp", _HOST, _HOST), _pkt("icmp", _HOST, _HOST, icmp_type=13),
          _pkt("udp", _HOST, _HOST)]
    assert _kernel(rs, "input", pk) == ["drop"] * len(pk)


def test_self_addressed_tcp_hitting_reject_with_reset_reads_deny(image):
    rs = _rules("INPUT", "REJECT --reject-with tcp-reset")
    assert _kernel(rs, "input", [_pkt("tcp", _HOST, _HOST)]) == ["drop"]


def test_reject_with_non_local_source_reads_deny(image):
    rs = _rules("INPUT", "REJECT --reject-with icmp-port-unreachable")
    assert _kernel(rs, "input", [_pkt("icmp", _PEER, _HOST)]) == ["drop"]
    rs = _rules("FORWARD", "REJECT --reject-with icmp-port-unreachable")
    assert _kernel(rs, "forward", [_pkt("icmp", _PEER, _FAR),
                                   _pkt("udp", _PEER, _FAR)]) == ["drop", "drop"]


def test_true_accept_still_reads_accept(image):
    """The capture check must not blind the oracle to real accepts."""
    pk = [_pkt("icmp", _HOST, _HOST), _pkt("icmp", _PEER, _HOST), _pkt("tcp", _PEER, _HOST),
          _pkt("udp", _PEER, _HOST), _pkt("gre", _PEER, _HOST)]
    assert _kernel(_rules("INPUT", "ACCEPT"), "input", pk) == ["accept"] * len(pk)
    pk = [_pkt("icmp", _PEER, _FAR), _pkt("tcp", _PEER, _FAR), _pkt("udp", _PEER, _FAR),
          _pkt("gre", _PEER, _FAR)]
    assert _kernel(_rules("FORWARD", "ACCEPT"), "forward", pk) == ["accept"] * len(pk)


def test_drop_reads_drop(image):
    pk = [_pkt("icmp", _HOST, _HOST), _pkt("tcp", _PEER, _HOST)]
    assert _kernel(_rules("INPUT", "DROP"), "input", pk) == ["drop", "drop"]
    pk = [_pkt("icmp", _PEER, _FAR), _pkt("udp", _PEER, _FAR)]
    assert _kernel(_rules("FORWARD", "DROP"), "forward", pk) == ["drop", "drop"]


def test_seed_10_ruleset_142_agrees_with_the_kernel(image):
    """The nightly disagreement, pinned: the workflow seeds from run_number,
    so this replays seed 10's ruleset 142 with the exact per-ruleset RNG
    run_many gives it (seed * 7919 + index)."""
    import random

    from tools.oracle import gen_iptables
    from tools.oracle.iptables_diff import ensure_containers, run_one
    rng = random.Random(10)
    for _ in range(143):
        text = gen_iptables.random_ruleset(rng)
    [c] = ensure_containers(1, os.path.join(ROOT, "tools", "oracle"))
    res = run_one(c, "random-10-142", text, random.Random(10 * 7919 + 142))
    assert res["load_error"] is None and res["cmp"] > 0, res
    assert [x for x in res["disagree"] if x["class"] == "model"] == [], res["disagree"]
    assert [x for x in res["witness_bad"] if x["class"] == "model"] == [], res["witness_bad"]
