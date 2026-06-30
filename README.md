# RuleHawk

**Paste your firewall/ACL config → get a ranked list of dead, shadowed, and
dangerously-permissive rules in seconds.** No agent, no integration, no account.

```
python -m rulehawk samples/ios_acl.txt                         # human report
python -m rulehawk samples/ios_acl.txt --json                  # machine/CI report
cat acl.txt | python -m rulehawk -                             # stdin
python -m rulehawk samples/ios_acl.txt --policy samples/policy.json   # + segmentation
pip install -e .   # then:  rulehawk acl.txt
```

Exit code is non-zero when a critical/high finding exists → drop it in CI.

## CI gate — audit a whole repo on every PR (GitHub Action)
Keep your firewall configs in git and let RuleHawk gate every change. The
`rulehawk gate` subcommand audits many files at once and emits a SARIF report
(inline diff annotations), a sticky PR comment, and a job summary; it fails the
check at a severity threshold you choose:

```
rulehawk gate firewall/**/*.txt --policy policy.json --fail-on high
```

As a GitHub Action it's a **composite, pure-Python, zero-install** step (no Docker
pull, no `pip install` — it runs from its own checkout; a full repo audits in
under a second) and your config never leaves the runner:

```yaml
permissions: { contents: read, security-events: write, pull-requests: write }
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

A bad change that opens CORP→PCI on SMB/445 gets blocked with the witness packet
`10.20.0.1 -> 10.10.0.1:445` annotated on the exact line. A file that parses to
**zero** rules **fails closed** (exit 2) — RuleHawk never certifies isolation it
could not verify. See [`docs/github-action.md`](docs/github-action.md) for all
inputs/outputs and the [worked example repo](https://github.com/optimesh-ai/acme-firewall-configs)
for a copy-pasteable setup with a live bad-PR demo.

## Segmentation-intent (the audit/compliance layer)
Declare zones + `must_not_reach` rules in a JSON policy, and RuleHawk proves
isolation or reports a **concrete witness packet** the ACL wrongly permits — the
auditor-grade evidence a manual review or a $100k AlgoSec deploy produces today:

```
SEGMENTATION VIOLATION (CORP must not reach PCI): the ACL PERMITS
10.20.0.1 -> 10.10.0.1:445 (tcp) via rule 8.
```
An earlier `deny` that already blocks the flow yields PASS (no false alarm); a
rule we can't model exactly (neq/complex mask) is flagged "indeterminate, review"
rather than a false pass. See `samples/policy.json` for an example and
[`docs/policy.md`](docs/policy.md) for the full policy schema.

## What it finds (today)
- **Intent inversions** — a `permit` that never fires because an earlier `deny`
  covers it (silent connectivity loss), or a `deny` that never fires because an
  earlier `permit` covers it (silent security hole). Each cites the exact rule.
- **Redundant rules** — safe-to-delete duplicates (with a cleanup plan).
- **Overly-permissive** — `permit ip any any` and broad `any` rules.
- **Dangerous exposure** — sensitive services (telnet/SMB/RDP/DB/...) permitted
  from `any` source.
- A hygiene **score** and an exportable **JSON** report.

## Vendors today
Cisco IOS extended ACLs, Cisco NX-OS access-lists, Cisco ASA access-lists (with
object-group resolution), Arista EOS access-lists, Juniper Junos firewall filters
(brace form), Palo Alto PAN-OS security policy (set format), and Linux
iptables/ip6tables filter rules — vendor auto-detected.
(Roadmap: FortiGate, AWS Security Groups/NACLs, nftables.)

## Scope & limits (what it does *not* model)
RuleHawk is a fast, sound **config-change gate**, not a network-wide reachability
simulator. It reasons about the **layer-3/4 packet space** only
`(action, proto, src-net, dst-net, src-port, dst-port, icmp-type)`:
- **NAT is not modeled** — it audits the filter (ACL/policy) layer; verify address
  translation separately (ASA `nat`/`static` are out of scope; the iptables `nat`
  table is surfaced as a note).
- **No routing/topology** — each config is an independent first-match context, so a
  `segmentation-violation` means "a ruleset on the path permits the forbidden flow,"
  not a full end-to-end reachability proof (that's [Batfish](https://github.com/batfish/batfish)).
- **L7/identity** (PAN-OS app-ID, source-user), `time-range`, `inactive`, interface
  bindings, and fragments are over-approximated/treated conservatively and surfaced
  as notes — RuleHawk errs toward over-reporting and **fails closed**, never toward a
  false "isolated."

## Why it exists
Firewall-rule sprawl and segmentation proof are an acute, recurring pain — and the
heavyweight tools (AlgoSec/Tufin/FireMon) price out the mid-market. RuleHawk is the
zero-setup, self-serve, multi-vendor auditor for everyone they miss: paste a config,
get findings you can verify by eye in seconds.

## Adoption analytics (opt-in, privacy-preserving)
RuleHawk's core promise is that **your config never leaves your browser.** The
hosted tool (`docs/index.html`) keeps that promise even with analytics on: it
emits only anonymous *usage* metadata, never config text or findings. Everything
is **off by default** — set two constants at the top of the `<script>` in
`docs/index.html`:

- `ANALYTICS_ENDPOINT` — a URL that accepts a JSON `POST`. Empty = nothing is
  ever sent. When set, RuleHawk beacons (via `navigator.sendBeacon`, so it never
  blocks the UI):
  - `page_view` — a visit, with the `?ref=` campaign tag and referrer.
  - `scan_run` — that an audit ran, a coarse size **bucket** (e.g. `50-199`,
    never the exact count), and whether a segmentation policy was used.
    **Never the config, never the findings.**
  - `cta_click` / `lead_capture` — interaction with the results call-to-action.

  Point it at any collector: a Cloudflare Worker, a Plausible/Umami proxy, or
  your own endpoint.
- `LEAD_ENDPOINT` — optional. When set, the results panel shows a "notify me"
  email field. On submit it posts the email plus the **finding counts the user
  already sees on screen** (criticals / highs / rules) — still never the config.
  Empty = no email field is shown.

**Campaign attribution:** append `?ref=<tag>` to the demo link in outreach
(e.g. `…/RuleHawk/?ref=acme-netlead`) and the tag rides along on every event, so
you can see which outreach actually got opened and used — without any config
telemetry.

The privacy banner on the page auto-discloses usage counting **only when
`ANALYTICS_ENDPOINT` is set**, so what the page claims and what it does stay in
sync.

## License
Apache-2.0 — see `LICENSE`.

## Layout
- `rulehawk/model.py` — normalized ACE + `covers()` (packet-space containment).
- `rulehawk/parse.py` — IOS/ASA parser (unmodeled lines are surfaced, not dropped).
- `rulehawk/parse_nxos.py` / `parse_eos.py` / `parse_junos.py` / `parse_panos.py` / `parse_iptables.py` — vendor frontends.
- `rulehawk/analyze.py` — the rule-space analysis engine (the core IP).
- `rulehawk/segcheck.py` — segmentation-intent proof (witness packets).
- `rulehawk/report.py` — text + JSON reports.
- `rulehawk/gate.py` — the CI gate: multi-file audit → SARIF + PR comment + summary.
- `rulehawk/cli.py` — `python -m rulehawk` (+ the `gate` subcommand).
- `action.yml` — the composite GitHub Action (see `docs/github-action.md`).
- `tests/` — correctness tests for the analysis engine and the gate.
