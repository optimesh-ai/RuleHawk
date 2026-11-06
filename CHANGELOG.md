# Changelog

## 0.3.2: Fail-closed stopgap

RuleHawk no longer emits PASS, on any surface. Wherever it used to report a
pass (a clean run, `segmentation-ok`, `connectivity-ok`, "policy is clean", a
✅ PR comment or step summary, `VERDICT: PASS`), it now reports **UNKNOWN**,
with reason code `fail-closed-stopgap` and the message "fail-closed stopgap
pending soundness review".

**FAIL is unchanged:** the same findings, severities, messages, witness
packets and SARIF results, and the same exit 1.

### Why

RuleHawk could print PASS on configurations it could not fully read or model
(for example an ACL with no interface binding, a line it did not model, or a
vendor default it does not model). A wrong PASS is worse than an honest
UNKNOWN: it says a boundary holds when nothing proved it. Until RuleHawk can
prove a PASS, no run reports one. PASS returns, where proven, in the next
release.

### Exit codes

| Run | 0.3.1 | 0.3.2 |
|---|---|---|
| nothing at or above the threshold (with or without a policy) | `0` PASS | **`3` UNKNOWN** |
| a finding at or above the threshold | `1` FAIL | `1` FAIL (unchanged) |
| a config parsed to zero rules, or invalid input or usage | `2` | `2` (unchanged) |
| `--fail-on none` (advisory) | `0`, reported PASS | `0`, reported UNKNOWN (or FAIL), never PASS |

Precedence: 2, then 1, then 3. The single-file CLI (`rulehawk FILE`) uses the
same codes with its fixed critical/high threshold, so a clean config now exits
3, including a hygiene-only run with no policy. `--help` still exits 0.

### What each surface reports

- CLI text: `VERDICT: UNKNOWN (exit 3) — fail-closed-stopgap: fail-closed
  stopgap pending soundness review`. `--json` adds `verdict` (`FAIL` |
  `UNKNOWN`) and `reasons`, and `verdict` / `reasons` on each finding.
- Policy assertions: `segmentation-ok` is now `segmentation-unknown` and
  `connectivity-ok` is now `connectivity-unknown` (info, verdict UNKNOWN, with
  the stopgap reason; a `must_reach` witness packet is still shown).
- `rulehawk gate`: JSON `verdict`, `enforced`, `reasons` and
  `undecided_assertions`; `passed` is always false. The PR comment and step
  summary lead with **UNKNOWN** and the reason; the console prints
  `VERDICT: UNKNOWN (exit 3)`. SARIF carries the FAIL findings unchanged and
  no pass result.
- GitHub Action: exit 3 fails the check with an error annotation naming the
  stopgap. New outputs `verdict` and `exit-code`; `passed` is never true.
  Under `fail-on: none` the step succeeds with a warning that names the
  verdict. If the gate step is skipped or aborts before RuleHawk records an
  exit code, the check fails with "No verdict was recorded" (0.3.1 read a
  missing exit code as 0, and could read an earlier RuleHawk step's). The exit
  code is now the gate step's own output, not a file shared by every
  RuleHawk step in the job.
- The hosted page is served from the main line, not from 0.3.x; its stopgap
  ships in 0.4.1.

### If you use `optimesh-ai/RuleHawk@v1`

When `v1` moves to the stopgap, a workflow with `fail-on` set (the default is
`high`) fails its RuleHawk check with exit 3 on every run that does not
already fail, until PASS returns in the next release. Steps that read
`outputs.passed` see `false`. To keep a non-blocking run meanwhile, set
`fail-on: none`: the step exits 0 and reports the verdict without enforcing
it.

`fail-on: none` turns off **all** blocking, not just UNKNOWN: a FAIL (exit 1)
and a config that parses to zero rules (exit 2) no longer fail the step
either. To keep blocking on everything except UNKNOWN, keep `fail-on` at
your threshold, let the RuleHawk step continue on error, and fail the job
unless the step failed with exit code 3:

```yaml
- id: rh
  uses: optimesh-ai/RuleHawk@v1
  continue-on-error: true
  with:
    configs: 'firewall/**/*.txt'
    fail-on: high
- if: steps.rh.outcome == 'failure' && steps.rh.outputs.exit-code != '3'
  run: exit 1
```

This blocks on FAIL (exit 1), on exit 2, on a crash, and when the step failed
before RuleHawk recorded an exit code (a setup failure, or "gate did not
complete"). Only an explicit UNKNOWN (exit 3) passes.

### Other changes you may notice

- CLI text output now carries a `VERDICT:` line on every run, FAIL runs
  included, so the text output is not byte-identical to 0.3.1; the findings
  themselves are unchanged.
- SARIF: a run that is UNKNOWN with no FAIL findings uploads an **empty**
  SARIF file. GitHub code scanning reads that as "no alerts", and it can close
  alerts left open by an earlier run. It is not a pass; read the check's
  verdict, not the alert count.
