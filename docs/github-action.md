# RuleHawk GitHub Action

A composite Action that audits your firewall/ACL configs on every pull request and
gates the merge. It wraps the `rulehawk gate` subcommand (`rulehawk/gate.py`).

It is **pure Python with zero dependencies**, so it runs straight from its own
checkout — **no `pip install`, no Docker image pull**. A full repo audit is
typically well under a second. Your config never leaves the runner.

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
[`acme-firewall-configs`](https://github.com/optimesh-ai/acme-firewall-configs) repo.

## Inputs

| Input | Default | Description |
|---|---|---|
| `configs` | — (**required**) | Files/globs to audit, whitespace or newline separated. Recursive `**` supported (e.g. `firewall/**/*.conf`). |
| `policy` | `''` | Path to a segmentation policy JSON (zones + `must_not_reach`; see [`policy.md`](policy.md)). Omit for hygiene checks only. |
| `fail-on` | `high` | Fail the check at this severity or worse: `critical` \| `high` \| `medium` \| `low` \| `none`. `none` is advisory (never blocks). |
| `vendor` | `auto` | Force a vendor for every file: `auto` \| `ios` \| `junos` \| `panos` \| `iptables`. |
| `comment` | `true` | Post/update a single sticky PR comment with the findings. |
| `upload-sarif` | `true` | Upload SARIF to code scanning so findings annotate the exact diff line. |
| `working-directory` | `.` | Directory to run the audit in. |
| `python-version` | `''` | Optionally set up a specific Python (≥3.9). Empty uses the runner's `python3` — the fast path. |

## Outputs

| Output | Description |
|---|---|
| `passed` | `true` when no finding met the `fail-on` threshold (and every file parsed). |
| `score` | Lowest hygiene score (0–100) across the audited files. |
| `worst-severity` | Highest severity found: `critical` \| `high` \| `medium` \| `low` \| `none`. |
| `sarif-file` | Path to the generated SARIF report. |

## Exit codes / verdict

| Code | Meaning |
|---|---|
| `0` | Clean — no finding at/above `fail-on`, every file parsed. |
| `1` | One or more findings at/above `fail-on`. |
| `2` | **Fail-closed** — a file parsed to *zero* rules or could not be read. RuleHawk will not certify isolation it could not verify; check the vendor/format or set `vendor`. (Suppressed only by `fail-on: none`.) |

The Action maps both `1` and `2` to a red check. Even on failure it still uploads
SARIF and posts the comment first, so the gate always reports its value.

## What you get

- **Inline diff annotations** — SARIF results land on the exact source line of each
  finding (exact for all five vendors, thanks to per-rule line tracking). They show
  in the *Files changed* tab and the Security tab, bucketed by severity.
- **A single sticky comment** — one comment per PR, updated in place each push
  (keyed by a hidden `<!-- rulehawk-gate -->` marker), led by the segmentation
  witness packets.
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
