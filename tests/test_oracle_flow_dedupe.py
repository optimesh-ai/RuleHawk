"""Kernel-oracle harness: probes must each start a NEW conntrack flow.

Found by the nightly oracle (seed 2): in FORWARD mode a GRE probe b->a sent
after a->b was ESTABLISHED, so a `--ctstate NEW -j ACCEPT` rule missed it and
the harness reported a false model disagreement. The one-flow-per-tuple
filter, once INPUT-only, now applies to every chain."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.oracle.iptables_diff import one_per_flow  # noqa: E402
from tools.oracle.rhsim import Pkt  # noqa: E402


def test_reverse_and_duplicate_flows_are_dropped():
    a = Pkt("gre", "10.0.0.127", "10.0.0.128")
    b = Pkt("gre", "10.0.0.128", "10.0.0.127")
    c = Pkt("tcp", "10.0.0.1", "10.0.0.2", 1000, 80)
    d = Pkt("tcp", "10.0.0.2", "10.0.0.1", 80, 1000)
    e = Pkt("tcp", "10.0.0.2", "10.0.0.1", 81, 1000)
    assert one_per_flow([a, b, c, c, d, e]) == [a, c, e]
