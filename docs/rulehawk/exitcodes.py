"""RuleHawk's exit codes: one table for every command (design v4 section 7,
with the v4 errata).

README, docs/github-action.md and the `--help` text of `rulehawk`, `rulehawk
gate` and `rulehawk combine` are rendered from this module, and
tests/test_exitcodes_allclear.py checks that each matches it.

- 0 is an all-clear only as a certified PASS. The fail-closed stopgap (0.4.1)
  never emits one: `rulehawk.allclear` decides it, and it says no while its
  compiled-in RULEHAWK_CERT is 0. 0 is also the advisory code (`gate
  --fail-on none`, or a combine with no enforced check) and the --help code.
- 4 is reserved for ACCEPTED and is not emitted until ACCEPTED ships. No
  command uses 4 for anything else.
- combine reports UNKNOWN as 2 (unchanged from 0.4.1), not 3.
"""

from __future__ import annotations

from typing import List, Tuple

PASS = 0             # certified PASS; never emitted under the stopgap
ADVISORY = 0         # `gate --fail-on none`; combine with no enforced check
HELP = 0             # --help
FAIL = 1
INVALID = 2          # zero rules parsed, unreadable or invalid input, usage
UNKNOWN = 3          # `rulehawk FILE` and `rulehawk gate`
COMBINE_UNKNOWN = 2  # `rulehawk combine` (0.4.1 compatibility)
ACCEPTED = 4         # reserved: not emitted until ACCEPTED ships

ACCEPTED_EMITTED = False

_STOPGAP = "fail-closed stopgap pending soundness review"
_RESERVED = "reserved: not emitted until ACCEPTED ships"

# (outcome, rulehawk FILE, rulehawk gate, rulehawk combine, Actions)
_ROWS: List[Tuple[str, str, str, str, str]] = [
    ("PASS (certified). Not emitted by this release (fail-closed stopgap)",
     str(PASS), str(PASS), str(PASS),
     "not emitted; an enforced exit 0 fails the step closed"),
    ("FAIL", str(FAIL), str(FAIL), str(FAIL),
     "`verdict=FAIL`; the step fails"),
    ("config parsed to zero rules, unreadable or invalid input, usage",
     str(INVALID), str(INVALID), f"{INVALID} (usage only)",
     "the step fails (fail-closed)"),
    (f"UNKNOWN (reason `fail-closed-stopgap`: {_STOPGAP})",
     str(UNKNOWN), str(UNKNOWN), str(COMBINE_UNKNOWN),
     "`verdict=UNKNOWN`; the step fails"),
    (f"ACCEPTED ({_RESERVED})", str(ACCEPTED), str(ACCEPTED), str(ACCEPTED),
     "not emitted; any code but 0 fails the step"),
    ("advisory: `gate --fail-on none`, or combine with no enforced check",
     "n/a", f"{ADVISORY}, with the verdict (UNKNOWN or FAIL) reported",
     str(ADVISORY), "the step succeeds with a warning naming the verdict"),
    ("`--help`", str(HELP), str(HELP), str(HELP), "n/a"),
]

_HEADER = ("| outcome | `rulehawk FILE` | `rulehawk gate` | `rulehawk combine` "
           "| Actions (`action.yml`, `comment/action.yml`) |")

MARK_BEGIN = "<!-- rulehawk:exit-codes:begin (generated from rulehawk/exitcodes.py) -->"
MARK_END = "<!-- rulehawk:exit-codes:end -->"


def markdown_table() -> str:
    """The exit-code table as it appears in README and docs/github-action.md."""
    lines = [_HEADER, "|---|---|---|---|---|"]
    lines += ["| " + " | ".join(r) + " |" for r in _ROWS]
    lines.append("")
    lines.append(f"Precedence on `rulehawk FILE` and `rulehawk gate`: {INVALID}, "
                 f"then {FAIL}, then {UNKNOWN}, then {ACCEPTED}, then {PASS}. "
                 f"The Actions never report an exit code as a PASS, and "
                 f"`comment/action.yml` fails its step only with `fail: true`.")
    return "\n".join(lines)


def doc_block() -> str:
    """The generated block, with its markers, for the docs."""
    return f"{MARK_BEGIN}\n{markdown_table()}\n{MARK_END}"


# Per command: (code, meaning), in the order --help lists them.
_HELP = {
    "file": [
        (FAIL, "FAIL: at least one critical/high finding"),
        (INVALID, "parse failure (no rules parsed), unreadable input, or bad usage"),
        (UNKNOWN, "UNKNOWN: no critical/high finding, but not certified (reason\n"
                  f"     fail-closed-stopgap: {_STOPGAP})"),
        (ACCEPTED, _RESERVED),
        (HELP, "only for --help; an audited run never exits 0 (PASS is not\n"
               "     emitted by this release)"),
    ],
    "gate": [
        (FAIL, "FAIL: a finding at or above --fail-on"),
        (INVALID, "a file parsed to zero rules, or invalid input / usage"),
        (UNKNOWN, "UNKNOWN: nothing at or above --fail-on, but not certified\n"
                  f"     (fail-closed-stopgap: {_STOPGAP})"),
        (ACCEPTED, _RESERVED),
        (ADVISORY, "only with --fail-on none (advisory; the verdict still says\n"
                   "     UNKNOWN/FAIL), or --help. PASS is not emitted by this release"),
    ],
    "combine": [
        (FAIL, "FAIL: an enforced check failed"),
        (COMBINE_UNKNOWN, "UNKNOWN (or a usage error)"),
        (ACCEPTED, _RESERVED),
        (ADVISORY, "only when no enforced check exists (every check is\n"
                   "     `fail-on none`, shown with its verdict, not enforced), or --help"),
    ],
}

_HELP_TAIL = {
    "file": "",
    "gate": f"  Precedence: {INVALID}, then {FAIL}, then {UNKNOWN}, then {ACCEPTED}.\n",
    "combine": "",
}


def help_section(command: str) -> str:
    """The `exit codes` section of `--help` for "file", "gate" or "combine"."""
    scope = ", over the enforced checks" if command == "combine" else ""
    out = [f"exit codes{scope} (0.4.1, fail-closed stopgap: PASS is never "
           f"reported):"]
    out += [f"  {code}  {text}" for code, text in _HELP[command]]
    return "\n".join(out) + "\n" + _HELP_TAIL[command]


def codes(command: str) -> List[int]:
    """The codes a command's --help lists."""
    return [c for c, _ in _HELP[command]]
