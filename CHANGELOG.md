# Changelog

## 0.5.0 (unreleased)

RuleHawk now fails closed. It no longer prints PASS or `VERIFIED` on an
answer it cannot support: such an answer is the new **UNKNOWN** verdict, with
a machine-readable reason code and a message, and the CLI and `rulehawk gate`
exit **3**.

### New: the UNKNOWN verdict

- New finding kinds `segmentation-unknown` and `connectivity-unknown`
  (medium). Every policy-assertion finding now carries `verdict`
  (`PASS` | `FAIL` | `UNKNOWN`) and `reasons` (`[{"code": ..., "message": ...}]`); `*-indeterminate` and `segmentation-error` findings are
  `UNKNOWN`. The reason codes are listed in `rulehawk.failclosed.REASONS`.
- `--json` adds `assertion_verdict` and per-finding `verdict`/`reasons`; the
  text report prints the verdict and one line per reason.
- `rulehawk gate`: JSON `verdict` (`PASS` | `FAIL` | `UNKNOWN` | `ADVISORY`)
  and `undecided_assertions`; the PR comment leads with **UNKNOWN** and lists
  each unproven assertion; the console prints `VERDICT: UNKNOWN (exit 3,
  fail-closed)`.
- `--evidence`: an unproven claim is `INDETERMINATE` with `reasons`, never
  `VERIFIED`.
- MCP server: `rulehawk_audit` and `rulehawk_compare` return `UNKNOWN`, and the
  audit lists `segmentation_unknown`.
- GitHub Action: exit 3 fails the check with its own error annotation; new
  outputs `verdict` and `exit-code`; `passed` is true only on PASS.
- `rulehawk combine` and `optimesh-ai/RuleHawk/comment` read a gate result
  with exit 3 as UNKNOWN (combine keeps its own exit codes: 0 PASS, 1 FAIL,
  2 UNKNOWN).
- Pages demo: shows UNKNOWN and the reason rows.

### Exit codes

`0` PASS · `1` FAIL · `2` parse failure or invalid input · `3` UNKNOWN (new).
UNKNOWN never shares the PASS code. Precedence: 2, then 1, then 3, then 0.
`--fail-on none` stays advisory and exits 0, but it reports the real
verdict (FAIL / UNKNOWN / ADVISORY, "not enforced"), never PASS unless the
run is one.

### False-PASS fixes (each was `segmentation-ok`, exit 0 and `VERIFIED` in 0.4.0)

- Empty search: no ACL bound to a transit interface or `access-group`, zero
  rules parsed, or the search never ran -> UNKNOWN (`no-transit-filter`,
  `no-rules-parsed`, `search-not-run`). Counterexamples 01, 18.
- iptables rules only in INPUT/OUTPUT, asked a transit question -> UNKNOWN
  (`iptables-host-chain-only`). 01.
- Any parse note in the evaluated config -> UNKNOWN (`parse-note`). 02, 05, 09, 15.
- ACL role is not a transit packet filter (`line vty` `access-class`, SNMP,
  route-map / PBR / class-map `match`, NAT, crypto, distribute-list) or is
  unknown -> UNKNOWN (`acl-not-packet-filter`, `acl-role-unknown`). 10.
- An interface or `access-group` bound to an ACL with no parsed rule (Cisco:
  "If an access list is referenced by a name, but the access list does not
  exist, all packets pass.") -> UNKNOWN (`acl-binding-undefined`).
- ASA `nameif` / `security-level` semantics -> UNKNOWN (`asa-security-levels`). 11.
- Junos SRX security policies and logical systems -> UNKNOWN
  (`junos-srx-policies`, `junos-logical-systems`; also `junos-groups`). 08, 09.
- PAN-OS `default-security-rules`, and any search that reaches the end of the
  rulebase -> UNKNOWN (`panos-default-security-rules`, `panos-implicit-default`). 06.
- PAN-OS `source-user`, `schedule`, `category`, HIP and device fields ->
  UNKNOWN (`panos-unmodeled-rule-field`). 07.
- iptables chain with no `-P` / `:CHAIN POLICY` (kernel default ACCEPT) ->
  UNKNOWN (`iptables-chain-policy-unset`). 02.
- iptables `-p 0` -> UNKNOWN (`iptables-proto-zero`). 03.
- ip6tables input -> UNKNOWN (`ip6tables-family`); a context with no rule of
  the packet's family -> UNKNOWN (`acl-family-mismatch`). 04.
- iptables `-D` deletes -> UNKNOWN (`iptables-delete`). 05.
- IPv6 implicit ND permits on IOS and NX-OS -> UNKNOWN (`ipv6-implicit-nd`). 12b, 19.
- ICMPv6 type canonicalisation -> UNKNOWN (`icmpv6-canonicalisation`). 12, 13.
- `established` (a stateless TCP bit test) -> UNKNOWN (`tcp-established`). 16.
- Non-initial fragments past an L4 entry -> UNKNOWN (`l4-fragments`). 17.
- IOS lock-and-key `dynamic` entries -> UNKNOWN (`ios-dynamic-entry`). 15.
- nftables input (no frontend) -> UNKNOWN (`nftables-unsupported`). 18.
- IOS numbered ACLs: the mask is always a wildcard (Cisco: "ACLs use a
  wildcard mask (also called an inverse mask)"); a numbered `access-list N`
  line never auto-detects a netmask. In a config with a PIX/ASA marker, or
  with the ASA-only `line N` keyword, the mask is ambiguous -> UNKNOWN
  (`numbered-acl-mask-ambiguous`). A nonzero address with mask
  `255.255.255.255` -> UNKNOWN (`ios-wildcard-all-ones`). 14.
- An unrecognised vendor label -> UNKNOWN (`vendor-unknown`).
- An interface that admits a family unfiltered plus another that emits it
  unfiltered, or one interface with no filter in either direction (a
  hairpin between a primary and a secondary subnet), is a way across the
  device that meets no audited rule -> UNKNOWN (`unfiltered-path`;
  IOS/NX-OS/EOS and Junos, per address family). A Junos unit family other
  than inet/inet6 (mpls, iso, ccc, ...) counts as unfiltered. ASA interface
  coverage is not modelled and is blocked; `access-group NAME global` now
  counts as an ASA marker. An ACL bound only on `shutdown` interfaces covers
  nothing -> UNKNOWN (`acl-role-unknown`).
- PAN-OS rule fields are an allowlist: a field RuleHawk neither models nor
  knows to be harmless (`source-imsi`, `source-imei`, `source-nw-slice`, or
  any unknown name) is a parse note -> UNKNOWN (`parse-note`). Each field
  takes one value or a `[ ]` list, so an unknown field is never swallowed as
  the previous field's value. A rule with `profile-setting` blocks a
  connectivity OK (`panos-security-profile`); isolation is unaffected.
- Cisco: banner text (`banner motd|login|exec|incoming ...`, delimited or
  Arista `EOF` form) is skipped, never parsed as ACL lines; a banner whose
  delimiter cannot be determined or that never closes is a parse note.
  `no access-list N` and other ACL deletions are not replayed: a parse note
  -> UNKNOWN.
- iptables-restore input with more than one `*filter` block is a parse note
  -> UNKNOWN (restore replaces the table at each block).
- iptables rules that match ports or other L4 fields, which a non-initial
  fragment never matches -> UNKNOWN (`iptables-fragments`).
- A violation that Hammerhead path-grounding suppresses (one witness proven
  unreachable) -> UNKNOWN (`pathground-witness-only`), never PASS; it still
  blocks the run.
- PAN-OS: an empty address-group no longer widens to ANY exactly; the rule is
  imprecise, so the assertion is indeterminate (UNKNOWN), never a PASS.

### Fixes

- `--evidence` no longer crashes with a TypeError on a scalar `ports` value
  (`"ports": 445`); it attests the same claim as `[445]`.
- server.json: the `uvx --from` pin no longer names a PyPI release
  (`rulehawk` is not on PyPI); it uses the documented git install, pinned to
  the `v0.5.0` tag.
- New sample `samples/bound_edge.txt`: a bound, fully modelled config whose
  PASS is genuinely supported. `samples/adv_realistic.txt` (unbound) is now
  UNKNOWN.
- Vendor detection: classic IOS (for example IOS 15.2) with
  `interface Ethernet0/0` is no longer labelled NX-OS. `interface Ethernet`
  alone is now a weak marker that an IOS marker (`version 15.2`,
  `boot-start-marker`, `ip access-list extended`, `Building configuration`)
  overrides.

### Compatibility

- **`@v1` now resolves to 0.5.0.** The moving Action tag `v1` pointed at
  0.3.1; it now points at this release, so `optimesh-ai/RuleHawk@v1` jumps
  from 0.3.1 to 0.5.0, including everything in 0.4.0 (and
  `optimesh-ai/RuleHawk/comment@v1`, which 0.3.1 did not have, starts to
  resolve). UNKNOWN exits 3 and the Action fails the check on it,
  so some previously green `@v1` runs turn red. Opt-out: pin
  `optimesh-ai/RuleHawk@v0.3.1` until you have read the reason codes.
  Workflows pinned to a SHA, `v0.3.1` or `v0.4.0` do not change.
- A run that exited 0 with PASS in 0.4.0 can now exit 3 with UNKNOWN. This
  hits most often on a config whose ACLs have no `ip access-group` /
  `access-group` binding (a bare ACL snippet), a config with any parse note,
  any L4 rule on IOS/Junos (`l4-fragments`), and any iptables rule that
  matches ports or other L4 fields (`iptables-fragments`). CI that treats
  non-zero as failure will go red; read the reason codes, then bind the ACL
  or fix the note. `fail-on: none` keeps the job from failing, but it no
  longer turns these into a PASS: the job reports UNKNOWN (not enforced) and
  `passed` is false.
- `fail-on: none` / `--fail-on none`: the gate JSON and result record
  `verdict` is now the real verdict (`PASS`, `ADVISORY`, `UNKNOWN` or
  `FAIL`; it used to be `ADVISORY` always), with a new `enforced: false`.
  `passed` is true only when that verdict is PASS (it used to be true on
  every advisory run). The console, the PR comment, `rulehawk combine` and
  the Action outputs show the verdict marked "not enforced"; the exit code
  is still 0, and combine's exit code counts enforced checks only. A result
  record from an earlier version with `fail_on: none` and `passed: true` but
  no real verdict is read as UNKNOWN by `rulehawk combine`.
- MCP `rulehawk_compare` returns `UNKNOWN` where it used to return
  `NO_NEW_RISK` when the after-config has an assertion RuleHawk cannot
  prove; only `NO_NEW_RISK` is an all-clear.
- PASS messages now end with their scope ("no audited ruleset permits this
  flow; assumes every interface is in the file; routing, NAT and topology
  not evaluated"); match on the `verdict` field, not the message text.
- An indeterminate assertion used to exit 0 below the threshold; it now exits 3.
- A violation suppressed by Hammerhead path-grounding used to exit 0; it is now UNKNOWN (`pathground-witness-only`) and exits 3.
- The evidence schema stays `rulehawk.evidence/v1`; `reasons` is additive.
- New JSON fields are additive; no field was removed or renamed.
