# Changelog

## Unreleased

### One exit-code table (#42 phase 2)

Every command now takes its exit codes from one table, `rulehawk/exitcodes.py`.
README, `docs/github-action.md` and the `--help` of `rulehawk`, `rulehawk gate`
and `rulehawk combine` are generated from it. No exit code changes in this
release: 1 FAIL, 2 parse failure, invalid input or usage, 3 UNKNOWN (combine:
2), 0 only for the advisory `--fail-on none`, a combine with no enforced
check, or `--help`. PASS is still never reported.

Every would-be all-clear (PASS, VERIFIED, NO_NEW_RISK, `passed: true`, an
enforced exit 0) now goes through one function, `rulehawk.allclear.emit`. It
gives the stopgap's answer (UNKNOWN, exit 3) because its compiled-in switch is
off; it is not read from the environment, and nothing overrides it at run
time. Tests fail on an all-clear outside that module that is not on a pinned,
reviewed exemption list: an all-clear literal; an exit-code constant or exit
call worth 0; a PASS or VERIFIED constant, keyed by what the use does (a
comparison by the whole condition it sits in); an assignment to, or a
`setattr`/`delattr`/`vars` call on, a name bound to `allclear`; any reference
to `allclear.certified` (a call, the function held as a value, or an import of
it by name); a `passed` name, attribute, keyword argument, dict key or
`["passed"]` item given anything but an `allclear.passed()` call, by
assignment (an augmented one always counts), by `setattr(x, "passed", ...)`,
`x.setdefault("passed", ...)` or `x.__setitem__("passed", ...)`, or by a
`return` in a function named `passed`, and any `passed` bound by unpacking or
as a `for`, `with` or comprehension target; in any engine module (both
copies), `sys.modules`, `exec`/`eval`/`compile`, an `importlib` import,
`__dict__` and the other rebinding dunders, `setattr`/`delattr` on anything
but `self`, or an absolute `rulehawk` import; outside their own
files, a private (`_name`) attribute of `allclear` or `exitcodes`, either
module object used as a value, `getattr`/`hasattr`/`setattr`/`delattr`/`type`/
`vars`/`dir` on either or on a member of either, a method call on a member of
either, or an assignment to or deletion of a member of `exitcodes`; any
`operator.attrgetter` or `methodcaller`; or an environment write naming
RULEHAWK_*. This is a static scan of spellings and structure, not of data
flow: it catches the forms listed here, a spelling it does not recognise
remains possible, and code review is the backstop. An override gated on an
environment variable that no test sets is not caught by the behavioural tests
either.
`allclear.py` itself may import nothing but `typing` and `exitcodes`, may
use no decorator, dunder attribute or environment and module hooks, has a
fixed list of top-level statements, and is pinned whole, byte for byte, in
both copies. The stopgap's guard blocks in `action.yml`,
`comment/action.yml`, `docs/index.html` and `docs/worker.js` are pinned byte
for byte as the 0.4.1 stopgap wrote them (`scripts/gen_stopgap_guards.py`
re-derives the pins from git), and both Actions' enforce steps are run under
bash.

### Dialect boundary, computed in shadow only (#42 phase 2)

A file can only ever be certified if it clears a boundary check on its raw
lines: exactly one non-Cisco dialect is detected (every detector runs; there is
no first match), and `--vendor`, read through its aliases, names no other;
no Cisco-family form fires (the IOS, ASA, NX-OS and EOS marker lines, the
NX-OS and EOS detectors, the IOS/ASA parser finding a rule, a top-level
`interface X` or ` ip access-group X in|out` line, or a Cisco-shaped line
inside a comment); no line holds a line separator other than LF, or a
backslash together with a quote; in iptables, no `#` stands anywhere but at
line start or inside a quote closed on its line, and no line holds both quote
kinds or a `<<`; no line starts with a pager prompt or ends in a backslash
continuation; and no comment or quoted string runs onto a second line. Only Junos, PAN-OS and iptables are planned
to be certifiable; an AWS security-group file clears the boundary but stays
uncertified.
This release computes that check and nothing reads it: verdicts, exit codes and
every output are unchanged, and PASS is still never reported. With
`RULEHAWK_SHADOW=1` in the environment, `rulehawk FILE --json` and
`rulehawk gate --json` add a `shadow` block per file: the dialects detected,
the Cisco lines that vetoed, `would_pass: false`, and the first reason the
file could not be certified (`dialect-not-exclusive`, `dialect-undetected`,
`line-not-allowlisted`, or `file-uncertified` when it clears the boundary,
since no grammar exists yet). The block is for testing the allowlist; it is
not an interface, the Action and the MCP server never set the variable, and it
may change in any release.

### Citation registry for the allowlist grammar (#42 phase 2)

`rulehawk/citations.py` records the first-party Junos documentation rows the
allowlist grammar may rest on: the URL, the page title, the release the page
states, a verbatim quote confirmed by a second fetch, and the dates. Rows not
yet confirmed are listed as pending and cannot be cited. It is data only: no
verdict, exit code or output changes, and PASS is still never reported.

### Junos grammar, computed in shadow only (#42 phase 2)

`rulehawk/grammar_junos.py` is the first allowlist grammar: the Junos brace
form, with a production only for a construct a cited row covers (interfaces
with `unit`, `family inet`, `address` and `filter input`; firewall filters
with terms, `source-address` and `destination-address` lists, and
`then accept` / `then discard`). It reads LF line ends, printable ASCII,
four-space indentation per level, single spaces between tokens, exact
lowercase keywords, and whole-line comments; a Junos tag (`delete:`,
`replace:`, `inactive:` ...) or a set-form command matches nothing. The
citation registry gains the rows it rests on. Nothing reads the result:
verdicts, exit codes and every output are unchanged, and PASS is still never
reported. With `RULEHAWK_SHADOW=1`, a file the boundary lets through as Junos
gets a `grammar` entry in its `shadow` block, and its blocking reason becomes
the grammar's (`line-not-allowlisted`, `parse-ambiguous`, or
`config-incomplete` for a file that ends inside a stanza) or, when it parses,
still `file-uncertified`: parsing is not a certificate, and `would_pass` stays
false.

After review, the grammar also takes off, at their line, the forms whose
Junos meaning differs from a statement-by-statement reading: a stanza or a
single-valued leaf (`then`, `input`, `address`) written twice
(`write-merge-uncited`), the same interface address on two units, a term
with no `then`, a match prefix with host bits set, out-of-range unit and
interface names, and a filter reference with no filter
(`config-incomplete`). A tag in a comment means no parse. The grammar entry's
key is `parses`, and it lists under `pending` the uncited rows the parse
rests on (unit number, interface name, IPv4 prefix, address-list meaning).
The grammar is imported only in a shadow run, so a row that went pending
cannot affect a run with the switch unset; a shadow run then reports
`grammar_unavailable` and stays `file-uncertified`.

### PAN-OS grammar, computed in shadow only (#42 phase 2)

`rulehawk/grammar_panos.py` is the second allowlist grammar: PAN-OS set
form, and of it only a whole security rule on one line,
`set rulebase security rules NAME from any to any source ADDR destination
ADDR application any service any action allow|deny`, with an address `any` or
one IPv4 prefix. Zone names, address objects, lists, quotes, per-attribute
lines, a rule name set twice, `move`, `delete`, `disabled`, `vsys` and every
other construct match nothing, because no fetched first-party row covers them
yet. The citation registry gains the PAN-OS rows (the 11.1 "Components of a
Security Policy Rule" page and two knowledge-base articles) and lists rule
order, release scope, lexing and set-CLI list semantics as pending. Nothing
reads the result: verdicts, exit codes and every output are unchanged. With
`RULEHAWK_SHADOW=1`, a file the boundary lets through as PAN-OS gets a
`grammar` entry in its `shadow` block, as Junos files do, and `would_pass`
stays false. The #51 review rules apply here too: a rule name written twice
is `write-merge-uncited`, a prefix with host bits is off, and the rule-name
character set and the prefix form are listed under `pending`.
After the #52 review, the grammar reads one security rule per file: a second
rule is off at its line, and the predefined names `intrazone-default` and
`interzone-default` (in any case) are never a user rule's name. The default
rules' fall-through, the meaning of `any`, the rule-type default and session
semantics are pending rows, and every production lists the file-level rows
(release scope, lexing, list semantics and those four) under `pending`; the
Junos productions now list `junos-lexing` and `junos-evolved-scope` too. The
one-line form is cited from a knowledge-base article that sets several
attributes on one line. Rule order (quoted from the unversioned "Security
Policy Rules" page, which states evaluation order but not where a new rule
lands) and the grammar's fixed token order stay pending, in every
production's `needs`. A grammar that fails to load for any reason leaves a shadow run
`file-uncertified` with a `grammar_unavailable` entry.

### iptables grammar, computed in shadow only (#42 phase 2)

`rulehawk/grammar_iptables.py` is the third allowlist grammar: `iptables`
commands one per line, `iptables -P CHAIN ACCEPT|DROP` and
`iptables -A CHAIN [-s PREFIX] [-d PREFIX] -j ACCEPT|DROP`, on the filter
table's INPUT, FORWARD and OUTPUT chains, with every row quoted from
iptables(8) 1.8.13. No shell syntax is read (shebang, comments, variables,
quotes, functions, conditionals, heredocs, `exit`), nor any other command,
match, target, long or abbreviated option, or the iptables-save format. A
chain policy set twice is `write-merge-uncited` and the same rule appended
twice is off. The script's scope (the rule set it runs against), lexing,
release scope and the save format are pending rows. Nothing reads the
result: verdicts, exit codes and every output are unchanged. With
`RULEHAWK_SHADOW=1`, an iptables file gets a `grammar` entry, and
`would_pass` stays false.
After the #53 review, every production lists the script scope, lexing and
release scope under `pending`; the script-scope row says that only the filter
table is read, and that the security, nat, mangle and raw tables, ip6tables
and nftables are not seen; and the filter-chains row quotes OUTPUT too.

### Final model and merge rules, computed in shadow only (#42 phase 2)

Every production of the Junos, PAN-OS and iptables grammars now declares the
write it makes: an attribute and a merge rule (`create`, `append-in-order`
or `error`; none replaces or deletes, because no row cites that). The final
model is the fold of every write in text order, and a second write to one
(object, attribute) is `write-merge-uncited`. Ordered children rest on a
cited order row (Junos term order, iptables append order); PAN-OS rule order
is not cited (the unversioned "Security Policy Rules" page states evaluation
order, not where a new rule lands), so each PAN-OS rule records
`panos-rule-order` under `pending`, and a PAN-OS file holds one rule. Nothing reads the model: verdicts, exit codes and every output
are unchanged. With `RULEHAWK_SHADOW=1`, a file the grammar parses gets a
`model` entry beside `grammar`, and `would_pass` stays false.

### Zone placement, computed in shadow only (#42 phase 2)

With `RULEHAWK_SHADOW=1` and a policy, a file the grammar parses gets a
`placement` entry read from its final model. Addressed Junos units are
segments; a segment that overlaps two asserted zones is
`zones-share-segment` (design rule (a)). A zone not contained in a segment
of its own is unpinned: the entry then carries the placement assumption
(`scope_assumptions`, `headline_assumptions`, row `zone-placement-assumed`),
and `blocking_reason_strict` gives `zone-placement-unpinned` for the strict
mode. Bridging, PAN-OS zones, static routes and `rule-type` have no grammar
production, so files holding them do not parse. Nothing reads the result:
verdicts, exit codes and every output are unchanged, `would_pass` stays
false, and no `--strict-placement` option is added yet.

### No file is certified, so code scanning and MCP coverage say so (#42 phase 2)

**Under the stopgap, every config gets a standing `rulehawk/uncertified`
note (SARIF level `note`) in code scanning.** RuleHawk certifies no file in
this release, so the SARIF report of every file in every dialect carries one
`rulehawk/uncertified` result at level `note`: "<file> is not certified. ... a
run with nothing flagged is UNKNOWN, not a clean result." An empty SARIF run no
longer stands for a clean file. The note sits on line 1, and its fingerprint is
the rule id plus the file path (no line number), so it is one alert per file
that stays open across runs instead of churning; a file given twice (`a.cfg`
and `./a.cfg`) gets one note. It is level `note` so a repository that blocks
merges on code-scanning warnings or errors is not newly blocked; the exit code
(3) is still what fails the check. Findings, their levels, fingerprints and
lines are unchanged.

**Cisco-family configs are planned to keep this note permanently (a later
release).** When certificates ship, a certified file will lose its note. The
plan is that a Cisco-family file (IOS, IOS XE, NX-OS, ASA, EOS, IOS XR) will
not be certified, so it will keep its `rulehawk/uncertified` note.

The MCP server's `coverage.state` is now `partial` unless every file is
certified, which none is: a file that parsed with every line modelled used to
report `complete` and now reports `partial`, with an explanation that gives
the number of uncertified files, and a new count,
`coverage.files_uncertified`: every input file that is not certified, analysed
or not (in this release, every input). `incomplete` (an input not analysed) is
unchanged, and so are every verdict and exit code.

### Compatibility

- **`rulehawk/uncertified` in code scanning:** every config in every dialect
  gets one `rulehawk/uncertified` note, from this release until the flip that
  restores certified answers. After the flip, Cisco-family configs are
  planned to keep it. A SARIF consumer that counts results, or treats
  any result as non-clean, now sees one result per file; filter on `ruleId`
  to skip it.
- **MCP `coverage.state`** is `partial`, never `complete`, until a file is
  certified. A client that went ahead on `complete` will not go ahead; it
  already could not on the verdict, which is never PASS in 0.4.1.
- **Exit code 4 is reserved for ACCEPTED** (a run whose only violations are
  covered by a risk acceptance). It is not emitted by this release, and no
  command uses 4 for anything else. When ACCEPTED ships, such a run exits 4 on
  `rulehawk FILE`, `rulehawk gate` and `rulehawk combine`.
- **Upgrading from 0.4.0 or earlier straight to the release that ships
  ACCEPTED:** a run whose only violations are accepted risks exited `0` there
  (reported PASS). It will exit `4`, never `0`, so a wrapper that treats any
  non-zero code as a failure will stop on it. In 0.4.1 the same run already
  exits `3`. To let such runs through once ACCEPTED ships, treat `4` as
  success in the wrapper, or use the opt-in `--accepted-exit 0`, which makes
  ACCEPTED and PASS indistinguishable to the exit code. `--accepted-exit 1`
  will not exist, because 1 is FAIL's.

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
