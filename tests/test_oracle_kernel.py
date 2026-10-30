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
