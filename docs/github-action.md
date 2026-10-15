# RuleHawk GitHub Action

A composite Action that audits your firewall/ACL configs on every pull request and
gates the merge. It wraps the `rulehawk gate` subcommand (`rulehawk/gate.py`).

It is **pure Python with zero dependencies**, so it runs straight from its own
checkout — **no `pip install`, no Docker image pull**. A full repo audit is
typically well under a second. Your config never leaves the runner.

**What the gate does not check.** It audits the ACL/filter rules in the changed
files. It does not evaluate what the change does to forwarding, NAT or routing,
or its blast radius across devices; the PR comment states this in one line. When
a live segmentation violation or a broken `must_reach` flow raises that
question, the comment adds one line pointing at [Hammerhead](https://optimesh.ai/#trial),
which verifies network changes offline before merge.

## Quick start

```yaml
# .github/workflows/rulehawk.yml
name: Firewall segmentation gate
on:
  pull_request:
    paths: ['firewall/**', '.rulehawk/policy.json']
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # upload SARIF → inline annotations on the PR diff
  pull-requests: write     # post/update the sticky review comment

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: optimesh-ai/RuleHawk@v1
        with:
          configs: firewall/**/*.txt
          policy:  .rulehawk/policy.json
          fail-on: high
```

A copy-pasteable, runnable example (with a live "bad PR" demo) lives in the
[`rulehawk-demo`](https://github.com/optimesh-ai/rulehawk-demo) repo.

## Inputs

| Input | Default | Description |
|---|---|---|
| `configs` | — (**required**) | Files/globs to audit, whitespace or newline separated. Recursive `**` supported (e.g. `firewall/**/*.conf`). |
| `policy` | `''` | Path to a segmentation policy JSON (zones + `must_not_reach`; see [`policy.md`](policy.md)). Omit for hygiene checks only. |
| `fail-on` | `high` | Fail the check at this severity or worse: `critical` \| `high` \| `medium` \| `low` \| `none`. `none` is advisory (never blocks). |
| `vendor` | `auto` | Force a vendor for every file: `auto` \| `ios` \| `junos` \| `panos` \| `iptables` \| `nxos` \| `eos` \| `aws-sg`. |
| `comment` | `true` | Post/update a single sticky PR comment with the findings. Several gate steps in one job share that one comment, headed by the worst verdict (see [Several checks on one PR](#several-checks-on-one-pr)). |
| `label` | `''` | A short name for this check in the PR comment, e.g. `PCI segmentation`. Defaults to the configs and policy it checked. |
| `share-results` | `false` | Upload this check's result as a workflow artifact, so a later job running `optimesh-ai/RuleHawk/comment` can put every check of the run in one comment. |
| `evidence` | `false` | Emit a **compliance-evidence artifact** (JSON + markdown) for the run: provenance (SHA-256 of every config audited, tool version, timestamp), `VERIFIED`/`FAILED` policy attestations, and PCI DSS / NIST 800-53 / ISO 27001 / CIS / SOC 2 / HIPAA control references. Paths land in the `evidence-file` / `evidence-md-file` outputs. |
| `upload-sarif` | `true` | Upload SARIF to code scanning so findings annotate the exact diff line. |
| `working-directory` | `.` | Directory to run the audit in. |
| `python-version` | `''` | Optionally set up a specific Python (≥3.9). Empty uses the runner's `python3` — the fast path. |

## Outputs

| Output | Description |
|---|---|
| `passed` | `true` when no finding met the `fail-on` threshold (and every file parsed). |
| `score` | Lowest hygiene score (0–100) across the audited files. |
| `worst-severity` | Highest severity found: `critical` \| `high` \| `medium` \| `low` \| `none`. |
| `evidence-file` | Path to the compliance-evidence JSON artifact (empty unless `evidence: true`). |
| `evidence-md-file` | Path to the same artifact rendered as a markdown document (empty unless `evidence: true`). |
| `sarif-file` | Path to the generated SARIF report. |
| `result-file` | Path to this check's result record, the input to `rulehawk combine` and `optimesh-ai/RuleHawk/comment`. |

## Several checks on one PR

A PR is often checked more than once: hygiene and segmentation over every
config, and a connectivity proof over the configs that own an egress path. The
PR still gets **one** comment, and its headline is the **worst** verdict:
**FAIL** if any check failed, **UNKNOWN** if a check that should have reported
did not, **PASS** only when every check passed. A passing check never hides a
failing one.

**Several gate steps in one job** need nothing extra. Each step's comment
includes every check the job has run so far, so the comment the last step
posts covers them all:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: optimesh-ai/RuleHawk@v1
    with: {configs: 'firewall/**/*.txt', policy: .rulehawk/segmentation.json, label: Segmentation}
  - uses: optimesh-ai/RuleHawk@v1
    if: always()            # run the second proof even when the first fails
    with: {configs: firewall/edge.cfg, policy: .rulehawk/egress.json, label: Egress}
```

**Checks in separate jobs** each post to the same comment, so with `comment:
true` in parallel jobs the last job to finish replaces the others' verdict. Set
`comment: false` and `share-results: true` on every gate step, and add one job
that combines them:

```yaml
jobs:
  segmentation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: optimesh-ai/RuleHawk@v1
        with: {configs: 'firewall/**/*.txt', policy: .rulehawk/segmentation.json,
               label: Segmentation, comment: false, share-results: true}
  egress:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: optimesh-ai/RuleHawk@v1
        with: {configs: firewall/edge.cfg, policy: .rulehawk/egress.json,
               label: Egress, comment: false, share-results: true, upload-sarif: false}
  verdict:
    needs: [segmentation, egress]
    if: ${{ !cancelled() }}         # report a failed job too, not only a green run
    runs-on: ubuntu-latest
    steps:
      - uses: optimesh-ai/RuleHawk/comment@v1
        with:
          expect: 2                 # one per gate step that shares its result
          jobs: ${{ toJSON(needs) }}
```

`optimesh-ai/RuleHawk/comment` inputs:

| Input | Default | Description |
|---|---|---|
| `expect` | — (**required**) | How many checks must report: one per gate step with `share-results: true`. Fewer make the verdict `UNKNOWN`, never `PASS`, so a crashed, cancelled or skipped job cannot read as a pass. |
| `jobs` | — (**required**) | Pass `${{ toJSON(needs) }}`. A gate job that did not succeed, but whose results show no failure (a re-run whose result never uploaded leaves the first attempt's PASS behind), makes the verdict `UNKNOWN`. |
| `results` | `''` | Result files or directories to combine. Empty downloads this run's `rulehawk-results-*` artifacts. |
| `comment` | `true` | Post/update the sticky PR comment on `pull_request` events. |
| `fail` | `true` | Fail the step unless the combined verdict is `PASS`. |

Its outputs are `verdict` (`PASS` \| `FAIL` \| `UNKNOWN`) and `comment-file`.
After *Re-run failed jobs*, only each job's newest attempt counts: a job that
re-ran replaces all of its earlier results, so a check skipped on the re-run
is not still passing. Matrix legs share one job id, so re-running only some
legs leaves the verdict `UNKNOWN` until the whole job re-runs. Do not put
`continue-on-error` on a gate step that shares its result: it would also hide a
failed upload, and on a re-run the previous attempt's result would stand. The
same combination runs locally: `rulehawk combine results/ --expect 2 --comment
comment.md` (exit 0 PASS, 1 FAIL, 2 UNKNOWN). The comment is only ever written by
the workflow's `GITHUB_TOKEN` (`github-actions[bot]`), and only that account's
marked comment is updated.

## Continuous compliance evidence

Turn on `evidence: true` and upload the artifact to get a dated, hashed audit
trail that builds itself on every change — instead of reconstructing segmentation
proof once a year for an assessor:

```yaml
- uses: optimesh-ai/RuleHawk@v1
  id: gate
  with:
    configs:  firewall/**/*.txt
    policy:   .rulehawk/policy.json
    evidence: true
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: segmentation-evidence
    path: |
      ${{ steps.gate.outputs.evidence-file }}
      ${{ steps.gate.outputs.evidence-md-file }}
```

One artifact covers every config in the run, and a failed claim names the config
that broke it. Three honesty properties are enforced by tests, and matter when an
assessor reads the output:

* **`VERIFIED` means proved.** Only a passing assertion earns it; with no policy
  the artifact makes no isolation claim at all and says so.
* **An unparseable config poisons the run.** If any supplied config fails to
  parse, *no* claim is marked verified — the leak could be in the file that was
  never read. The report states that coverage is incomplete.
* **The claim is scoped to the rulesets audited, never to the network.** With no
  routing or NAT model, a pass proves "no audited ruleset permits this flow",
  which is the exact wording the artifact carries.

## Exit codes / verdict

| Code | Meaning |
|---|---|
| `0` | Clean — no finding at/above `fail-on`, every file parsed. |
| `1` | One or more findings at/above `fail-on`. |
| `2` | **Fail-closed** — a file parsed to *zero* rules or could not be read (suppressed only by `fail-on: none`), a `configs` pattern matched **no files** (a typo'd path must not mean "never audited, green check"), an unknown `vendor`/flag, or an unwritable output path. RuleHawk will not certify isolation it could not verify. |

The Action maps both `1` and `2` to a red check. Even on failure it still uploads
SARIF and posts the comment first, so the gate always reports its value.

## What you get

- **Inline diff annotations** — SARIF results land on the exact source line of each
  finding (exact for all five vendors, thanks to per-rule line tracking). They show
  in the *Files changed* tab and the Security tab, bucketed by severity.
- **A single sticky comment** — one comment per PR, updated in place each push
  (keyed by a hidden `<!-- rulehawk-gate -->` marker on a comment the workflow's
  own token wrote), led by the worst verdict and the segmentation witness packets.
- **A job summary** — the full report on the run page (`$GITHUB_STEP_SUMMARY`).

## Permissions & fork PRs

The consumer workflow needs:

```yaml
permissions:
  contents: read
  security-events: write   # only if upload-sarif: true
  pull-requests: write     # only if comment: true
```

For **pull requests from forks**, GitHub issues a read-only `GITHUB_TOKEN`, so SARIF
upload and comment posting are not permitted. The Action degrades gracefully — the
gate check still runs and blocks the merge — but the inline annotations/comment are
skipped. If your firewall repo accepts fork PRs and you want full reporting on them,
run the gate on `pull_request` (for the check) and do the reporting in a privileged
`workflow_run` job. For a single-repo config workflow (the common case — the network
team pushes branches to the same repo) the quick-start above is all you need.

## Releasing / versioning (maintainers)

Consumers pin a **moving major tag** (`@v1`). After cutting a release `vX.Y.Z`, move
`v1` to it:

```bash
git tag -fa v1 -m "v1 -> vX.Y.Z" && git push origin v1 --force
```

The Action's package is vendored in this repo (the action repo *is* RuleHawk), so
there is nothing to publish — `@v1` resolves to the engine + `action.yml` at the tag.
The web demo's vendored copy under `docs/rulehawk/` is kept byte-identical by
`make sync-web` (enforced by `tests/test_hosted_parity.py`).

## Run it locally

The Action runs exactly this — so you can reproduce any CI result on your laptop:

```bash
rulehawk gate firewall/**/*.txt --policy policy.json --fail-on high \
  --sarif rulehawk.sarif --summary - --json -
```
