"""Differential test against Batfish (opt-in: needs a Batfish service).

    docker run -d -p 9996:9996 -p 9997:9997 batfish/allinone
    pip install pybatfish
    RULEHAWK_BATFISH_ORACLE=1 python -m pytest tests/test_oracle_batfish.py

Random ACLs are rendered into IOS, ASA, EOS, NX-OS and Junos (brace form,
plus Junos with prefix-lists / `port` / implicit-accept terms in brace and
`set` form). Each one is loaded into Batfish and RuleHawk, and the test
asserts that:
  * every line RuleHawk proves dead is unreachable in Batfish;
  * per-packet permit/deny verdicts agree;
  * every must_not_reach witness RuleHawk cites is permitted by Batfish on
    the cited line.
Skipped in the normal suite. CI runs it from .github/workflows/oracle.yml.
"""

from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

pytestmark = pytest.mark.skipif(
    os.environ.get("RULEHAWK_BATFISH_ORACLE") != "1",
    reason="Batfish oracle is opt-in (RULEHAWK_BATFISH_ORACLE=1, needs a Batfish service)")

VENDORS = "ios,asa,eos,nxos,junos,junosx,junosset"


def test_random_acls_agree_with_batfish():
    from tools.oracle.bf_diff import main_run
    n = int(os.environ.get("RULEHAWK_ORACLE_N", "12"))
    seed = int(os.environ.get("RULEHAWK_ORACLE_SEED", "2"))
    tot, res, _ = main_run(n_random=n, seed=seed, vendors=VENDORS, batch=21, pkts=120)
    print(tot)
    assert tot["configs"] == n * len(VENDORS.split(",")), tot
    assert tot["cmp"] > 500 and tot["witness"] > 20, tot
    bad = {h: {k: r[k] for k in ("disagree", "dead_refuted", "witness_bad")}
           for h, r in res.items() if r["disagree"] or r["dead_refuted"] or r["witness_bad"]}
    assert not bad, list(bad.items())[:3]
