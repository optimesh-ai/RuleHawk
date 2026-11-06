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

## Batfish (IOS, ASA, EOS, NX-OS, Junos)

`bf_diff.py` loads configs into a Batfish service and compares, per config:
dead lines vs `filterLineReachability`, boundary/random packets vs
`testFilters` (first-match verdict and the matching line), and every
must_not_reach witness vs `testFilters` on the cited line. `gen_acl.py`
renders one random abstract ACL into every syntax, including Junos with
prefix-lists, direction-agnostic `port` and implicit-accept terms, in brace
(`junosx`) and `set` (`junosset`) form.

    docker run -d -p 9996:9996 -p 9997:9997 batfish/allinone
    pip install pybatfish
    python -m tools.oracle.bf_diff --random 40 --batch 20 --pkts 150
    python -m tools.oracle.bf_diff --files ios:a.cfg junos:b.conf
    python -m tools.oracle.bf_diff --file-list corpus.txt   # vendor:path lines

`testFilters` takes ~1 s per packet on Apple Silicon (x86 image under
Rosetta) — keep batches at ~20 configs. CI: the `batfish` job in
`.github/workflows/oracle.yml` runs `tests/test_oracle_batfish.py` with
`RULEHAWK_BATFISH_ORACLE=1` against a digest-pinned image.

Known oracle limits: Batfish rejects port 0 flows and treats a TCP flow as a
bare SYN; it does not know some Arista service names (`multihop-bfd`, `sbfd`,
`lsp-ping`, `netconf-ssh`). Lines Batfish finds unreachable that RuleHawk does
not flag (`rh_missed`) are completeness gaps, not unsound claims: RuleHawk only
proves a line dead from a single covering rule or a union of rules along ONE
dimension (src or dst), never across port ranges and never from an imprecise
rule.
