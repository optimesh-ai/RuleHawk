# Changelog

## 0.4.1: Fail-closed stopgap

RuleHawk no longer emits PASS or VERIFIED, on any surface. Wherever it used to
report a pass (a clean run, `segmentation-ok`, `connectivity-ok`, "policy is
clean", a VERIFIED evidence claim, an MCP `PASS` or `NO_NEW_RISK`, a ✅ PR
comment, the hosted page's "Segmentation holds"), it now reports **UNKNOWN**,
with reason code `fail-closed-stopgap` and the message "fail-closed stopgap
pending soundness review".

**FAIL is unchanged:** the same findings, severities, messages, witness
packets, SARIF results and failed evidence claims, and the same exit 1.

### Why

RuleHawk could print PASS on configurations it could not fully read or model
(for example an ACL with no interface binding, a line it did not model, or a
vendor default it does not model). A wrong PASS is worse than an honest
UNKNOWN: it says a boundary holds when nothing proved it. Until RuleHawk can
prove a PASS, no run reports one. PASS returns, where proven, in the next
release.

### Exit codes

| Run | 0.4.0 | 0.4.1 |
|---|---|---|
| nothing at or above the threshold (with or without a policy) | `0` PASS | **`3` UNKNOWN** |
| a finding at or above the threshold | `1` FAIL | `1` FAIL (unchanged) |
| a config parsed to zero rules, or invalid input or usage | `2` | `2` (unchanged) |
| `--fail-on none` (advisory) | `0`, reported PASS | `0`, reported UNKNOWN (or FAIL), never PASS |

Precedence: 2, then 1, then 3. The single-file CLI (`rulehawk FILE`) uses the
same codes with its fixed critical/high threshold, so a clean config now exits
3, including a hygiene-only run with no policy. `rulehawk combine` keeps its
own codes (1 FAIL, 2 UNKNOWN; 0 only when no check is enforced, and it never
reports PASS): a check that reports UNKNOWN makes it exit 2, and a `fail-on
none` check is shown as "UNKNOWN (not enforced)" or "FAIL (not enforced)"
without changing its exit code, so the headline can read FAIL while combine
exits 2. `--help` still exits 0.

### What each surface reports

- CLI text: `VERDICT: UNKNOWN (exit 3) — fail-closed-stopgap: fail-closed
  stopgap pending soundness review`. `--json` adds `verdict` (`FAIL` |
  `UNKNOWN`) and `reasons`, and `verdict` / `reasons` on each finding.
- Policy assertions: `segmentation-ok` is now `segmentation-unknown` and
  `connectivity-ok` is now `connectivity-unknown` (info, verdict UNKNOWN, with
  the stopgap reason; a `must_reach` witness packet is still shown).
- `--evidence`: an unproven claim is `INDETERMINATE` with `reasons`, never
  `VERIFIED`. FAILED and ACCEPTED_RISK claims are unchanged.
- `rulehawk gate`: JSON `verdict`, `enforced`, `reasons` and
  `undecided_assertions`; `passed` is always false. The PR comment and step
  summary lead with **UNKNOWN** and the reason; the console prints
  `VERDICT: UNKNOWN (exit 3)`. SARIF carries the FAIL findings unchanged and
  no pass result.
- GitHub Action: exit 3 fails the check with an error annotation naming the
  stopgap. New outputs `verdict` and `exit-code`; `passed` is never true.
  Under `fail-on: none` the step succeeds with a warning that names the
  verdict. The exit code is now the gate step's own output, not a file shared
  by every RuleHawk step in the job: a step whose gate was skipped or aborted
  fails with "gate did not complete" instead of reading an earlier step's.
- `rulehawk combine` and `optimesh-ai/RuleHawk/comment`: a gate result with
  exit 3 is UNKNOWN; new `--verdict PATH`; `fail-on none` checks are shown but
  not enforced. A result file from a gate before 0.4.1 (`passed: true`) is read
  as UNKNOWN, never PASS, and the comment action never maps an exit 0 to PASS:
  its `verdict` output is `FAIL` or `UNKNOWN`, and it no longer prints "Every
  RuleHawk check in this run passed."
- MCP server: `rulehawk_audit` returns `UNKNOWN` (with `reasons` and
  `segmentation_unknown`) where it returned `PASS`, and `rulehawk_compare`
  returns `UNKNOWN` where it returned `NO_NEW_RISK`.
- Hosted page: shows the verdict UNKNOWN and the reason. It no longer says
  "Segmentation holds" or "No issues found".

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
complete"). Only an explicit UNKNOWN (exit 3) passes. Do not use it on a
step with `share-results: true`: on an UNKNOWN run it would also hide a failed
result upload (see docs/github-action.md).

### Other changes you may notice

- CLI text output now carries a `VERDICT:` line on every run, FAIL runs
  included, so the text output is not byte-identical to 0.4.0; the findings
  themselves are unchanged.
- A run whose only findings are accepted risks (`--accept`) exited 0 in 0.4.0
  and now exits 3 (UNKNOWN).
- Evidence control rows that read REVIEW now read UNKNOWN.
- MCP `rulehawk_audit`: `segmentation_passed` is now always empty (`[]`);
  undecided assertions are listed in `segmentation_unknown`.
- SARIF: a run that is UNKNOWN with no FAIL findings uploads an **empty**
  SARIF file. GitHub code scanning reads that as "no alerts", and it can close
  alerts left open by an earlier run. It is not a pass; read the check's
  verdict, not the alert count.
