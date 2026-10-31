# RuleHawk

> **Free and open source (Apache-2.0).** Runs on your machine or
> [in your browser](https://optimesh-ai.github.io/RuleHawk/), with no account, no API key
> and no subscription, and your config never leaves your machine. Built and maintained by
> [Optimesh](https://optimesh.ai); for checks across routing and reachability too, see
> [where RuleHawk stops](#where-rulehawk-stops-and-hammerhead-starts).

**Point it at a firewall/ACL config → get a ranked list of dead, shadowed, and
dangerously-permissive rules, each with the line to change.** Free, local, no
account, no API key.

RuleHawk tells you a rule is wrong and shows the packet that proves it. It
audits the rule layer only, so it does not tell you what a change breaks on your
network; see [*Scope & limits*](#scope--limits-what-it-does-not-model).

## Try it

```
pip install "git+https://github.com/optimesh-ai/RuleHawk"     # Python 3.9+, no dependencies
rulehawk - <<'EOF'
ip access-list extended EDGE_IN
 permit tcp any any eq 3389
 permit ip any any
 deny tcp any any eq 22
EOF
```

One of the three findings it prints:

```
[CRITICAL] intent-inversion-deny-dead  (EDGE_IN:3)
   rule : deny tcp any any eq 22
   line : 4
   cause: permit ip any any
   why  : This deny NEVER takes effect — an earlier permit (rule 2) already
          allows the same traffic. The traffic you meant to block is ALLOWED.
   fix  : move rule 3 (line 4) above rule 2 (line 3)
```

Then `rulehawk edge-fw.txt` for one config, `rulehawk gate configs/` for a
directory, `--json` for machines. Exit code is non-zero on a critical/high
finding (1) or when nothing could be audited (2), so it drops into CI.
**[Quickstart](docs/quickstart.md)**: install, first audit, agents (Claude, Cursor,
NetClaw) and what to do when something goes wrong.

## CI gate — audit a whole repo on every PR (GitHub Action)
Keep your firewall configs in git and let RuleHawk check the rule layer of every
change. The `rulehawk gate` subcommand audits many files at once and emits a SARIF report
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
inputs/outputs and the [worked example repo](https://github.com/optimesh-ai/rulehawk-demo)
for a copy-pasteable setup with a live bad-PR demo.

The gate audits the **rules in the changed files**, not the change's effect on
forwarding, and every PR comment says so in one line.

## Use it from an agent (MCP server + skill)
RuleHawk ships a local MCP server, so an agent can audit a firewall change
before it pushes it. It runs over stdio, reads only the files you point it at,
makes no network calls and writes nothing.

```
pip install "rulehawk[mcp] @ git+https://github.com/optimesh-ai/RuleHawk"   # Python 3.10+
rulehawk-mcp --version
claude mcp add --transport stdio rulehawk --env RULEHAWK_MCP_ROOT="$PWD" -- rulehawk-mcp
```

| Tool | What it does |
|---|---|
| `rulehawk_audit` | Audit a config file or a directory: verdict `PASS` / `FAIL` / `INCOMPLETE` / `ERROR`, the blocking findings, and what was and wasn't analysed |
| `rulehawk_list_findings` | Every finding, worst first, filterable by severity and kind, each with a stable id |
| `rulehawk_explain_finding` | One finding by id (rule, source line, witness, fix), or what a finding kind means |
| `rulehawk_compare` | Before vs after (files or directories): the findings a change introduces or resolves, and the rules it adds |
| `rulehawk_supported_inputs` | The formats RuleHawk reads and what it does not model |

Every result carries a `coverage` block (files analysed, files **not**
analysed and why, config lines the parser could not model) and the scope
statement: rule layer only, routing/NAT/topology not evaluated. A file no
parser recognises makes the result `INCOMPLETE`, never `PASS`; errors carry an
`error_code` and a `hint`. `rulehawk_compare` is a rule-layer finding delta
matched on rule text, not a forwarding diff. `RULEHAWK_MCP_ROOT` confines the
server to one directory, and relative paths resolve against it.

Claude Desktop, Cursor, NetClaw and `uvx` setups:
[docs/quickstart.md](docs/quickstart.md#3-let-an-agent-call-it-mcp).

**The skill.** [`skills/rulehawk-preflight/SKILL.md`](skills/rulehawk-preflight/SKILL.md)
teaches an agent to run the audit before it pushes an ACL or firewall change,
and to stop on a high or critical finding, or on input RuleHawk could not
read, unless a human overrides. Copy the folder into your agent's skills
directory (for Claude Code, `~/.claude/skills/` or `.claude/skills/`).

## Segmentation-intent (the audit/compliance layer)
Declare zones + `must_not_reach` rules in a JSON policy, and RuleHawk proves the
ACL isolates them or reports a **concrete witness packet** the ACL wrongly permits — the
auditor-grade evidence a manual review or a $100k AlgoSec deploy produces today:

```
SEGMENTATION VIOLATION (CORP must not reach PCI): the ACL PERMITS
10.20.0.1 -> 10.10.0.1:445 (tcp) via rule 8.
```
An earlier `deny` that already blocks the flow yields PASS (no false alarm); a
rule we can't model exactly (neq/complex mask) is flagged "indeterminate, review"
rather than a false pass. See `samples/policy.json` for an example and
[`docs/policy.md`](docs/policy.md) for the full policy schema.

The policy also takes **`must_reach`** — positive connectivity assertions for
deployment prechecks ("users must reach the Zscaler/proxy egress ranges on
80/443", "the appliance must reach its update CDN"). A provably permitted flow
is attested with a concrete witness packet (`connectivity-ok`); a flow no
ruleset permits **fails the gate** (`connectivity-broken`, high) before the
rollout ships instead of during it. Filter-layer proof only — routing/NAT and
the proxy itself are out of scope (see *Scope & limits*).

### Path-grounded segmentation (Hammerhead customers)
This requires a licensed Hammerhead install (licensed separately; see
[Hammerhead pricing](https://optimesh.ai/#pricing)) and a Hammerhead snapshot of
the network; RuleHawk alone cannot do it. With both, RuleHawk can verify each
segmentation-violation witness against
Hammerhead's forwarding model (`hammerhead traceroute`), so violations on
routing paths that can't actually deliver the packet are suppressed to
informational, while confirmed leaks are stamped **path-confirmed**:

```
rulehawk config.txt --policy policy.json --hh-snapshot DIR --hh-from DEVICE
```

`DIR` is the Hammerhead snapshot directory and `DEVICE` is the source device the
witness packet originates from. **Soundness rule:** only a deterministic,
NAT-free "not delivered" verdict ever downgrades a finding — NAT on the path, an
oracle error, or an unknown device all **fail closed** and the violation is kept
(see `rulehawk/pathground.py`). So does a degraded model: from Hammerhead 0.2.2,
when Hammerhead could not read part of the snapshot it still answers but exits 3,
and RuleHawk keeps the violation and names the unread lines and devices in it.

When `DEVICE` is a Cisco ASA, Hammerhead decides the witness by the interface
the packet arrives on (interface security levels), so a host-sourced probe with
no received interface is Unknown and the violation is kept. Name that interface
with `--hh-ingress NAME` (the ASA `nameif`, e.g. `inside`); RuleHawk passes it as
`hammerhead traceroute --ingress NAME` and never picks one itself.

## Compliance evidence (`--evidence`)
A finding is not evidence. Auditors and GRC platforms need to know *what was
audited, when, with which tool*, which *requirement* it speaks to, and — the part
tools usually skip — an explicit record of what **passed**:

```
rulehawk acl.txt --policy policy.json --evidence     > evidence.json
rulehawk acl.txt --policy policy.json --evidence-md  > evidence.md   # for a human
```

```jsonc
{
  "coverage": { "subjects": 2, "subjects_audited": 2, "complete": true },
  "subjects": [ { "sha256": "sha256:7c80ba76…", "vendor": "ios-asa", "rules_parsed": 10 } ],
  "attestations": [
    { "claim": "DMZ cannot reach PCI", "status": "VERIFIED",
      "basis": "no audited ruleset permits this flow" },
    { "claim": "CORP cannot reach PCI on tcp/445", "status": "FAILED",
      "witness": "10.20.0.1 -> 10.10.0.1:445 (tcp)",   // the packet, not a screenshot
      "failed_on": [ { "subject": "edge-fw.txt", "witness": "10.20.0.1 -> …" } ] }
  ],
  "controls": [ { "framework": "PCI-DSS-4.0", "control": "11.4.5", "status": "FAILED" }, … ]
}
```

Findings and attestations cross-reference **PCI DSS v4.0, NIST SP 800-53 Rev. 5,
ISO/IEC 27001:2022, CIS v8, SOC 2 (TSC 2017), and the HIPAA Security Rule**, so an
evidence vault has somewhere to file the result. Each `subjects[].sha256` is the
digest of the *exact bytes audited* — re-hash with `sha256sum` and it matches,
which is what makes the artifact re-verifiable rather than merely printed.

Four honesty rules are enforced by tests, not convention:
- **A control appears only when something audited bears on it.** No padding the
  artifact with untested requirements to look thorough.
- **`VERIFIED` means something was proved.** Only a passing assertion earns it.
  With no policy the artifact makes *no isolation claim at all* and says so.
- **An unaudited config poisons the claim.** If any supplied config fails to
  parse, *no* attestation in that run is `VERIFIED` — the leak could be in the
  file we couldn't read, and the report says coverage is incomplete.
- **The claim is scoped to the rulesets audited, never to the network.** With no
  routing or NAT model, a pass proves "no audited ruleset permits this flow" —
  the exact sentence the artifact carries.

`tool.generator` records whether an artifact came from the CLI, CI, or the hosted
page: evidence a pipeline produced on every merge is not evidence someone
generated by hand in a browser, and a reviewer is entitled to tell them apart.

For the whole fleet on every PR, set `evidence: true` on the Action — see
[`docs/github-action.md`](docs/github-action.md#continuous-compliance-evidence).

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
(brace form), Palo Alto PAN-OS security policy (set format), Linux
iptables/ip6tables filter rules, and **AWS Security Groups**
(`aws ec2 describe-security-groups` JSON) — vendor auto-detected.
(Roadmap: FortiGate, AWS Network ACLs, nftables.)

```
aws ec2 describe-security-groups > sgs.json
rulehawk sgs.json --policy policy.json          # same audit, same evidence
```

Security Groups are allow-only and order-independent, so the shadowing analysis
correctly produces nothing for them — but segmentation is *exact* (a permit-only
ruleset is precisely the union of its permits, which is what the engine's
implicit default-deny already models), and least-privilege is where the value is:
`0.0.0.0/0` on 22/3389/3306 is the archetypal cloud exposure. A source RuleHawk
cannot resolve from the export — a `UserIdGroupPairs` reference to another group,
or a prefix list — is never dropped and never guessed: it becomes one opaque
`imprecise` rule, so that part of the space stays **indeterminate** rather than
silently passing.

## Where RuleHawk stops (and Hammerhead starts)

| Question | RuleHawk (free, Apache-2.0) | Hammerhead |
|---|---|---|
| Which rules are shadowed, dead, redundant, any-any, or expose risky services? | Yes | — |
| Does this ACL permit a flow my policy forbids? (witness packet) | Yes, per ruleset | Yes |
| Is that packet actually delivered across routing, NAT and topology? | No | Yes |
| What does this change (or the fix) break, before I push? | No | Yes |
| Blast radius of a change across multiple devices | No | Yes |

**Checking changes, not just rules?** [Hammerhead](https://optimesh.ai) runs the
change against a model of your whole network (routing, reachability and
segmentation) and tells you what it breaks before you push.

Every report states that scope (JSON: `verification_boundary`). When a result
raises a question only a forwarding model can answer (a live segmentation
violation, or a broken `must_reach` flow) the report adds one "next step" line
pointing at [Hammerhead](https://optimesh.ai/#trial) (access by request). It stays quiet for hygiene-only
results, for `*-indeterminate` findings (those need the rule fixed, not a
forwarding model), for accepted risks, and for findings Hammerhead has already
path-grounded.

## Scope & limits (what it does *not* model)
RuleHawk is a fast, sound **rule-layer gate** for config changes, not a
network-wide reachability or change-impact verifier. It reasons about the
**layer-3/4 packet space** only
`(action, proto, src-net, dst-net, src-port, dst-port, icmp-type)`:
- **NAT is not modeled** — it audits the filter (ACL/policy) layer; verify address
  translation separately (ASA `nat`/`static` are out of scope; the iptables `nat`
  table is surfaced as a note).
- **No routing/topology** — each config is an independent first-match context, so a
  `segmentation-violation` means "a ruleset on the path permits the forbidden flow,"
  not a full end-to-end reachability proof (that needs a forwarding model such as
  [Batfish](https://github.com/batfish/batfish), or [Hammerhead](https://optimesh.ai)
  to also verify a change offline before you push).
- **L7/identity** (PAN-OS app-ID, source-user), `time-range`, `inactive`, interface
  bindings, and fragments are over-approximated/treated conservatively and surfaced
  as notes — RuleHawk errs toward over-reporting and **fails closed**, never toward a
  false "isolated."

## Hosted page analytics
The hosted page sends nothing unless its operator sets an endpoint, and never
sends config text or findings. See [docs/hosted-analytics.md](docs/hosted-analytics.md).

## License
RuleHawk is Apache-2.0 — see `LICENSE`. This licence covers RuleHawk only;
Hammerhead is proprietary and licensed separately.

## Layout
- `rulehawk/model.py` — normalized ACE + `covers()` (packet-space containment).
- `rulehawk/parse.py` — IOS/ASA parser (unmodeled lines are surfaced, not dropped).
- `rulehawk/parse_nxos.py` / `parse_eos.py` / `parse_junos.py` / `parse_panos.py` / `parse_iptables.py` — vendor frontends.
- `rulehawk/analyze.py` — the rule-space analysis engine (the core IP).
- `rulehawk/segcheck.py` — segmentation-intent proof (witness packets).
- `rulehawk/pathground.py` — Hammerhead path-grounding of segmentation witnesses (`--hh-snapshot`/`--hh-from`).
- `rulehawk/boundary.py` — the verification boundary: the scope every report states, and when a finding needs a forwarding model.
- `rulehawk/report.py` — text + JSON reports.
- `rulehawk/gate.py` — the CI gate: multi-file audit → SARIF + PR comment + summary.
- `rulehawk/cli.py` — `python -m rulehawk` (+ the `gate` subcommand).
- `rulehawk/mcp_server.py` — the MCP server (`rulehawk-mcp`, the optional `mcp` extra); not loaded by the hosted tool.
- `skills/rulehawk-preflight/` — the agent skill that runs the audit before a firewall change is pushed.
- `action.yml` — the composite GitHub Action (see `docs/github-action.md`).
- `tests/` — correctness tests for the analysis engine and the gate.
- `scripts/check_vendor_sync.py` — stdlib-only sync guard (called by the test suite).

## Contributing — keeping the hosted tool in sync

`docs/rulehawk/` is a vendored copy of the canonical engine (`rulehawk/`) that
the public hosted tool loads client-side via Pyodide.  **These two trees must
remain byte-identical at all times.**  If they drift the hosted page silently
serves a stale parser while the CLI is already fixed — this has happened before.

**Workflow:**

1. Edit the engine under `rulehawk/` (never edit `docs/rulehawk/` directly).
2. Re-sync the vendored copy: `make sync-web`
3. Confirm byte-identity: `make check-vendor-sync` (exits 0 if in sync).
4. Commit both `rulehawk/` and `docs/rulehawk/` changes together.

CI enforces this automatically: `tests/test_vendor_sync.py` runs on every
`python -m pytest` invocation and will fail the build if any `.py` file drifts.

<!-- mcp-name: io.github.optimesh-ai/rulehawk -->
