# Changelog

## 0.5.0 (unreleased)

RuleHawk now fails closed on the conditions listed under "False-PASS
fixes" below: where one of them applies, an answer that used to print PASS
or `VERIFIED` is the new **UNKNOWN** verdict, with a machine-readable reason
code and a message, and the CLI and `rulehawk gate` exit **3**. A PASS still
rests on the assumptions under "Known limits"; it is not a proof about the
device.

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
- PAN-OS and iptables: every input line is consumed by a modelled handler or
  gets a parse note citing its line number -> UNKNOWN (`parse-note`). On
  PAN-OS that covers `delete`, `edit` / `top` / `up` with relative `set`
  lines, `rename`, `move`, NAT, PBF and decryption rules, and any subtree
  outside a short allowlist (management plane, tags, zone / application /
  profile definitions, `network`), each justified in the code. On iptables
  it covers shell lines, `-X`, `-E`, unknown verbs and malformed headers
  (`-Z`, `-L` and `-S` change nothing and are consumed).
- nftables text next to parsed rules (a `table ... {` block, an `nft`
  command, `flush ruleset`) -> UNKNOWN (`nftables-present`), not only when
  no rule parsed.
- A removed, reset or deactivated binding -> UNKNOWN (`acl-binding-negated`):
  `no` or `default` before `ip access-group`, `ipv6 traffic-filter`,
  `ip port access-group`, `access-class` or ASA `access-group`, a top-level
  `no interface` or `default interface` (or `no int`, `default inte`, ...),
  Junos `inactive:` on an interface,
  unit, family, filter binding or filter, and set-form `deactivate` /
  `delete` of an interface or a filter. The removal is not applied.
- Cisco IOS / ASA / NX-OS / EOS interfaces are an allowlist: every line in
  an `interface` stanza other than Loopback / Null must be one that cannot
  change a transit packet's fate (the list is in the README and in
  `rulehawk/failclosed.py`, each entry with its reason). Any other line, any
  `default` form, any abbreviated keyword (`no ip access-gr F in`) and an
  abbreviated `int X` header -> UNKNOWN (`interface-feature-unmodeled`; the
  detail names the keyword, not the line). `no ip address` (exact forms) and
  `media-type WORD` are on the list.
- Every frontend splits lines at a newline only. Any other control, format
  or separator character, or a space other than ASCII space, is a parse note
  -> UNKNOWN. A CR before the newline is dropped only in Cisco configs and
  AWS JSON; in iptables, PAN-OS set and Junos input it is a parse note.
- Cisco configs are read by one lexer that every Cisco check and the ACL /
  object-group parser use. Interface, ACL and object-group mode end at a
  header, `exit` or one of a short list of top-level commands (listed in the
  README), indented or not. An ACL entry or object-group member after a mode
  change is in no named ACL (parse note). An unindented line in those modes
  that is not on the list, or an indented top-level command there -> UNKNOWN
  (`stanza-boundary-ambiguous`). Lines after `end` (or a global `exit`) are
  a parse note and no ACL is read from them. Interface names are case-folded
  and a separately written number is joined, so `GigabitEthernet 0/2` is its
  own port and repeated stanzas merge in order.
- Cisco ACL mode is an allowlist: inside an ACL only ACL-entry lines stay
  in the ACL (sequence number, `permit`, `deny`, `remark`, `evaluate`,
  `dynamic`, `no` / `default` of those, NX-OS `statistics per-entry`). Any
  other line, indented or not (an unlisted global command such as
  `ntp server`, an abbreviation such as `ex`, `hostn`) -> UNKNOWN
  (`stanza-boundary-ambiguous`). `ex`/`exi`/`en` are read as `exit`/`end`.
  An `exit` after a line that opens no known sub-mode (`hostname`, `ip
  route`) ends configuration mode (later lines are a parse note); an `exit`
  after an unchecked sub-mode body -> UNKNOWN.
- Line accounting: every line of an object on the evaluated path ends read
  (every word in the model) or noted. The frontends fill one ledger and one
  check notes any line nothing read: Cisco ACL lines, ACL headers, flat
  `access-list` lines and forwarding interface lines; every iptables and
  PAN-OS line; every Junos term. A line the lexer keeps in ACL mode but the
  parser does not read (`default 10`, `30 xyzzy`) -> parse note -> UNKNOWN.
- Cisco ACL numbering: an unnumbered entry is numbered the last number + 10
  (Cisco IOS XE 17 and NX-OS), the ACL is evaluated in number order, and an
  order that differs from the text is a parse note. A mixed ACL such as
  `deny ...` then `5 permit ...` used to be evaluated in text order (PASS);
  it is now FAIL when the permit leaks, else UNKNOWN.
- Cisco ACL deletions: `no N` (IOS IPv4, NX-OS, EOS) and `no sequence N`
  (IOS IPv6) delete entry N and are a parse note (FAIL when the leak is
  proven, else UNKNOWN). `default N`, `default sequence N`, `default
  remark` and every other `no` form in ACL mode -> parse note. They used to
  be skipped (PASS with the entry still in place).
- Cisco sequence-number forms per vendor and family: `N` on IOS IPv4, NX-OS
  and EOS; `sequence N` on IOS IPv6. Any other form (IOS IPv4 `sequence 10
  permit ...`, IOS IPv6 `10 permit ...`) -> parse note.
- Cisco `exit` after an opener that is not complete (`router`, `router
  ospf`, `line`, `line vty`, `route-map`, `vrf definition`, `control-plane
  xyzzy`) -> UNKNOWN; `management` is not read as a sub-mode on IOS.
- `statistics per-entry` alone no longer labels a file NX-OS; outside NX-OS
  the line is a parse note.
- Standard ACL entries: any word after the source other than `log` /
  `log-input` -> parse note, imprecise.
- iptables-restore: a table block without `COMMIT`, a `COMMIT` outside a
  block and any line outside a block -> parse note.
- `rulehawk gate`: a failed policy assertion blocks at every `--fail-on`
  threshold (a broken `must_reach`, HIGH, used to exit 0 at `critical`).
- Junos: braces that do not balance, and a `#` glued to a word (`x#y`), are
  parse notes -> UNKNOWN.
- PAN-OS: a quoted rule or object name with leading or trailing whitespace
  (`rules "d "`) is a parse note -> UNKNOWN.
- Junos: `#`, `/*`, `*/`, a brace, a bracket or `;` inside a quoted string,
  an unclosed string or block comment, and `/*` inside a `#` comment are
  parse notes -> UNKNOWN (the tokenizer strips comments and splits on braces
  without regard to quotes).
- Cisco VLAN ACLs (`vlan access-map`, `vlan filter`) -> UNKNOWN
  (`vlan-filter`).
- Junos: a statement keyword written in upper case (Junos keywords are
  lower-case only) -> UNKNOWN (`junos-keyword-case`).
- Cisco features that drop, inspect, rewrite or bypass traffic outside the
  ACLs, on any line -> UNKNOWN: zone-based firewall (`zone security`,
  `zone-member security`, `zone-pair security`; `zone-firewall`), `ip
  inspect` / CBAC (`stateful-inspection`), any `service-policy`
  (`qos-policy`), `ip` / `ipv6 policy route-map`, `ip local policy`,
  `service-policy type pbr` (`policy-routing`), and any `mpls` line,
  `tag-switching`, `xconnect`, `l2vpn` or `pseudowire` (`mpls-forwarding`).
- iptables with no FORWARD policy at all -> UNKNOWN
  (`iptables-chain-policy-unset`), also when no rule is in FORWARD (a user
  chain nothing jumps to). The policy is the one the parser applied from a
  `-P FORWARD` / `--policy FORWARD` command or a `:FORWARD` line; text in a
  comment, a `--comment` or a `--log-prefix` sets nothing.
- iptables: a line is dispatched on its first verb. A line that carries a
  second verb or a shell separator (`;`, `&&`, `|`) is a parse note, and a
  word in a rule that is no option's value (iptables rejects the line)
  makes the rule imprecise with a parse note. A chain policy is only
  `ACCEPT` or `DROP`, exact case (iptables(8): "The policy target must be
  either ACCEPT or DROP"); `-P FORWARD REJECT`, `drop` or `:FORWARD REJECT`
  sets nothing and is a parse note.
- must_reach: connectivity OK now needs every audited rule context to
  permit the whole flow. One permitting and another denying part of it
  (an egress ACL on the destination interface) -> UNKNOWN
  (`reach-not-every-context`).
- PAN-OS: a name defined as more than one kind (address and address-group
  share a namespace, as do service and service-group) or in more than one
  `shared` / vsys / device-group scope is unresolved (imprecise) and noted
  -> UNKNOWN (`object-scope-ambiguous`). A rule's names are looked up in its
  own vsys or device-group, then `shared` (a firewall rulebase: the firewall
  objects, then `shared`); a name defined only elsewhere is noted -> UNKNOWN
  (`object-scope-ambiguous`).
- NAT in the config -> UNKNOWN (`nat-present`): any Cisco `ip nat` or
  `ipv6 nat` line, `nat64`, `nat66`, ASA `nat (...)` /
  `static (...)`, the PAN-OS NAT rulebase, Junos security/services NAT, the
  iptables nat table.

### Known limits (a PASS still rests on these)

- Routing, NAT translation and topology are not evaluated, and every
  interface is assumed to be in the file. NAT is detected (`nat-present`)
  but never applied.
- Every frontend accounts for every line of an object on the evaluated
  path (Junos per term); a line it does not read is a parse note. Every PASS
  prints these per-vendor limits next to the verdict (text, `--json`
  `scope`, `--evidence`, gate, MCP, hosted page):
  - On every vendor a line ends at \n only, and a control or separator character on any line is UNKNOWN (a CR before the newline is accepted only in Cisco configs and AWS JSON); every line of an object on the evaluated path (a Cisco ACL, ACL header, flat access-list or forwarding interface line, every iptables and PAN-OS line, every Junos term) is either read into the model, every word of it, or makes the answer UNKNOWN.
  - Cisco reads ACLs, allowlisted interface lines and the listed global features (zone firewall, ip inspect, service-policy, policy routing, MPLS / xconnect, VLAN filters, NAT); interface, ACL and object-group mode end at a header, `exit` or a recognised top-level command, indented or not; inside an ACL a line is read only if it is a `permit` or `deny` entry, a `remark` or `exit`, with the sequence-number form of its vendor and family (`N` on IOS IPv4, NX-OS and EOS, `sequence N` on IOS IPv6); an unnumbered entry is numbered the last number + 10 and the ACL is evaluated in number order; `no N` (IOS IPv4, NX-OS, EOS) and `no sequence N` (IOS IPv6) delete that entry; NX-OS `statistics per-entry` is read on NX-OS only; an ACL whose number order differs from its text or that has a deletion, and every other line in an ACL (`default`, `evaluate`, `dynamic`, another `no` or sequence form, any other command), are UNKNOWN; any other line in interface mode, an unindented line in those modes that is not a recognised top-level command, `ex` or `en` for `exit` or `end`, an `exit` after a line that opens no known sub-mode, after an opener that is not complete (`router`, `line vty`) or after a sub-mode body that is not checked, and any line after `end` are UNKNOWN; other global commands are not read.
  - PAN-OS resolves an object name only in the rule's own vsys or device-group and in shared; device-group inheritance is not followed; a quoted name with leading or trailing whitespace is UNKNOWN.
  - iptables reads the filter table; a chain's policy comes only from a parsed -P or :CHAIN line naming ACCEPT or DROP (exact case); an iptables-restore table block without `COMMIT`, and a line outside a table block, are UNKNOWN.
  - Junos reads firewall filters and their interface bindings; SRX security zones or policies, a comment marker, brace, bracket or `;` inside a quoted string, a `#` glued to a word, and braces that do not balance make the answer UNKNOWN.
- RuleHawk models the L3/L4 packet space.
- iptables: only the filter table is modelled; other tables are noted.
- A pasted snippet is audited as if it were the whole config.

### Fixes

- The hosted page's `report_json.vendor` is the parsed vendor (it read
  `ios-asa` for every input).
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
  no real verdict is read as UNKNOWN by `rulehawk combine`, which exits 2.
- MCP `rulehawk_compare` returns `UNKNOWN` where it used to return
  `NO_NEW_RISK` when the after-config has an assertion RuleHawk cannot
  prove; only `NO_NEW_RISK` is an all-clear.
- PASS messages now end with their scope ("no audited ruleset permits this
  flow; assumes every interface is in the file; routing, NAT and topology
  not evaluated; known limits: ..." followed by the per-vendor limits under
  Known limits); match on the `verdict` field, not the message text. The
  `--json` report adds a `scope` object (`statement`, `must_not_reach`,
  `must_reach`, `known_limits`).
- PAN-OS set files and iptables scripts with lines RuleHawk does not
  model (a shell `echo`, an `edit` block, a NAT rule) now carry a parse note
  per line and are UNKNOWN; so is any input with nftables text, NAT, or a
  binding removed as listed under `acl-binding-negated` above.
- Cisco configs with interface lines outside the allowlist (an `ip verify`,
  a `vrf forwarding`, a `standby`, a sub-interface `encapsulation`) or a
  `service-policy`, PBR, zone, `ip inspect` or MPLS line are UNKNOWN. The
  PASS scope text now ends with the known limits.
- must_reach with several rule contexts: connectivity OK used to need one
  context permitting the whole flow; it now needs every one (else
  UNKNOWN). The connectivity scope text reads "every audited ruleset
  permits the whole flow".
- An indeterminate assertion used to exit 0 below the threshold; it now exits 3.
- A violation suppressed by Hammerhead path-grounding used to exit 0; it is now UNKNOWN (`pathground-witness-only`) and exits 3.
- The evidence schema stays `rulehawk.evidence/v1`; `reasons` is additive.
- New JSON fields are additive; no field was removed or renamed.
