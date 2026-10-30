# Differential oracles

Ground-truth checks for RuleHawk's parsers and first-match model. Not part of
the package or the normal test suite.

- `iptables_diff.py` loads iptables rulesets into a real Linux kernel (a
  privileged container built from `Dockerfile.kernel`), sends crafted packets
  with `kernel_probe.py`, and compares accept/drop, per-rule counters and
  segmentation witnesses with RuleHawk. `gen_iptables.py` makes random
  rulesets; `packets.py` samples boundary and random packets; `rhsim.py` is
  RuleHawk's own per-packet verdict.

      docker build -t rh-kernel-oracle -f tools/oracle/Dockerfile.kernel tools/oracle
      python -m tools.oracle.iptables_diff --random 200 --seed 3 --jobs 4
      python -m tools.oracle.iptables_diff path/to/rules.v4

  CI: `.github/workflows/oracle.yml` (nightly + manual) runs
  `tests/test_oracle_kernel.py` with `RULEHAWK_KERNEL_ORACLE=1`.

Disagreement classes that are not RuleHawk claims, kept and counted apart:

- `icmp-non-initiating`: unsolicited ICMP replies/errors are never NEW to
  conntrack (INVALID/UNTRACKED). RuleHawk models connection-initiating
  packets.
- `host-hook-jump`: an INPUT/OUTPUT jump to a user chain. RuleHawk surfaces
  these and analyses the user chain on its own; it makes no per-packet INPUT
  claim.
