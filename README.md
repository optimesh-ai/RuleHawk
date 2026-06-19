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
rather than a false pass. See `samples/policy.json`.

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
Cisco IOS extended ACLs, Cisco ASA access-lists. (Roadmap: NX-OS, Juniper,
Palo Alto, AWS Security Groups/NACLs, iptables/nftables.)

## Why it exists
Firewall-rule sprawl and segmentation proof are an acute, recurring pain — and the
heavyweight tools (AlgoSec/Tufin/FireMon) price out the mid-market. RuleHawk is the
zero-setup, self-serve, multi-vendor auditor for everyone they miss: paste a config,
get findings you can verify by eye in seconds.

## License
Apache-2.0 — see `LICENSE`.

## Layout
- `rulehawk/model.py` — normalized ACE + `covers()` (packet-space containment).
- `rulehawk/parse.py` — IOS/ASA parser (unmodeled lines are surfaced, not dropped).
- `rulehawk/analyze.py` — the rule-space analysis engine (the core IP).
- `rulehawk/report.py` — text + JSON reports.
- `rulehawk/cli.py` — `python -m rulehawk`.
- `tests/` — correctness tests for the analysis engine.
