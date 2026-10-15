"""rulehawk combine — one PR comment for every RuleHawk check in a run.

A PR is often checked more than once: hygiene plus segmentation over every
config, and a separate connectivity proof over the configs that own an egress
path. Each `rulehawk gate --result PATH` run leaves a result record; this
command reads them all and renders ONE sticky comment whose headline is the
worst verdict:

    FAIL     any check failed
    UNKNOWN  a check that was expected left no readable result (it crashed, was
             cancelled or skipped) — never read as a pass
    PASS     every expected check reported and passed

usage:
  rulehawk combine <result-file-or-dir>... [--expect N] [--comment PATH]
                   [--summary PATH] [-q]

Directories are searched recursively for *.json. Exit code: 0 PASS, 1 FAIL,
2 UNKNOWN (or a usage error).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .gate import FOOTER, RESULT_SCHEMA, _COMMENT_MARKER

# GitHub rejects a comment over 65,536 characters. A rejected update leaves the
# previous verdict standing on the PR, so the body is kept well under the limit
# by trimming detail — never the verdict or the per-check table.
MAX_COMMENT_CHARS = 60000

_RANK = {"PASS": 0, "UNKNOWN": 1, "FAIL": 2}
_ICON = {"PASS": "✅", "UNKNOWN": "❌", "FAIL": "❌"}
_EXIT = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}

_USAGE = __doc__.split("usage:", 1)[1].split("Directories", 1)[0]
_USAGE = "rulehawk combine — one PR comment for every check in a run\n\nusage:" + _USAGE


@dataclass
class Check:
    label: str
    verdict: str          # PASS | FAIL | UNKNOWN
    detail: str           # one line for the summary table
    markdown: str = ""    # the check's full report ('' when it has none)
    job: str = ""
    attempt: int = 1
    reported: bool = False   # a well-formed result record backs this check


def _result_files(paths: Sequence[str]) -> Tuple[List[str], List[Check]]:
    """Every *.json under the given paths (deduplicated, in a stable order),
    plus an UNKNOWN check for each path that does not exist."""
    files: List[str] = []
    seen = set()
    missing: List[Check] = []

    def add(p: str) -> None:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            files.append(p)

    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs.sort()
                for n in sorted(names):
                    if n.endswith(".json"):
                        add(os.path.join(root, n))
        elif os.path.isfile(p):
            add(p)
        else:
            missing.append(Check(label=p, verdict="UNKNOWN",
                                 detail="no results here (path does not exist)"))
    return files, missing


def _load(path: str) -> Check:
    name = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
    except (OSError, ValueError) as e:
        return Check(label=name, verdict="UNKNOWN",
                     detail=f"unreadable result file `{name}` ({type(e).__name__})")
    if not isinstance(rec, dict) or rec.get("schema") != RESULT_SCHEMA:
        return Check(label=name, verdict="UNKNOWN",
                     detail=f"`{name}` is not a RuleHawk result record")
    if rec.get("pending"):
        return Check(label=str(rec.get("label") or name), verdict="UNKNOWN",
                     detail="the check started but never reported a result")
    passed, code = rec.get("passed"), rec.get("exit_code")
    label, md = rec.get("label"), rec.get("markdown")
    attempt = rec.get("attempt", 1)
    if not (isinstance(passed, bool) and isinstance(code, int)
            and isinstance(label, str) and isinstance(md, str)
            and isinstance(attempt, int) and not isinstance(attempt, bool)):
        return Check(label=name, verdict="UNKNOWN",
                     detail=f"`{name}` is an incomplete result record")
    fail_on = str(rec.get("fail_on", ""))
    if passed and code == 0:
        verdict, detail = "PASS", f"no findings at or above `{fail_on}`"
    elif passed or code == 0:
        # The two fields disagree: trust neither.
        verdict, detail = "UNKNOWN", f"`{name}` reports an inconsistent verdict"
    else:
        verdict = "FAIL"
        n, pf = rec.get("violations", 0), rec.get("parse_failures", 0)
        if code == 2 and not n:
            detail = (f"fail-closed: {pf} file(s) parsed to zero rules" if pf
                      else "fail-closed: the gate could not audit its input")
        else:
            detail = f"{n} finding(s) at or above `{fail_on}`"
            if pf:
                detail += f", plus {pf} unparseable file(s)"
    return Check(label=label or name, verdict=verdict, detail=detail,
                 markdown=md, job=str(rec.get("job", "")), attempt=attempt,
                 reported=True)


def collect(paths: Sequence[str], expect: Optional[int] = None) -> List[Check]:
    """Load every result, keep only the newest run attempt of each check, and
    add an UNKNOWN entry for each expected check that never reported."""
    files, checks = _result_files(paths)
    loaded = [_load(f) for f in files]
    # A re-run attempt replaces that same check from an older attempt. Within
    # one attempt nothing is dropped: two results with the same label there are
    # different runs (a matrix), and neither may hide the other.
    newest: Dict[Tuple[str, str], int] = {}
    for c in loaded:
        if c.reported:
            key = (c.job, c.label)
            newest[key] = max(newest.get(key, c.attempt), c.attempt)
    for c in loaded:
        if c.reported and c.attempt < newest[(c.job, c.label)]:
            continue
        checks.append(c)
    reported = sum(1 for c in checks if c.reported)
    if expect is not None and reported < expect:
        checks.append(Check(
            label="(missing)", verdict="UNKNOWN",
            detail=(f"expected {expect} check(s), found {reported}: a job may "
                    f"have crashed, been cancelled or been skipped")))
    if not checks:
        checks.append(Check(label="(none)", verdict="UNKNOWN",
                            detail="no RuleHawk results were found"))
    return checks


def _cell(text: str) -> str:
    return " ".join(text.replace("|", "\\|").split())


def _section(c: Check) -> str:
    """The check's own report, retitled with its label and nested one level."""
    lines = c.markdown.rstrip("\n").splitlines()
    if lines and lines[-1] == FOOTER:
        lines = lines[:-1]
    if lines and lines[0].startswith("## "):
        lines[0] = f"### {_ICON[c.verdict]} {_cell(c.label)}"
        rest = lines[1:]
    else:
        rest, lines = lines, [f"### {_ICON[c.verdict]} {_cell(c.label)}"]
    rest = [("#" + l) if l.startswith("#") else l for l in rest]
    return "\n".join(lines[:1] + rest).rstrip()


def _render_many(checks: List[Check], worst: str, detail: str) -> str:
    total = len(checks)
    failed = sum(1 for c in checks if c.verdict == "FAIL")
    unknown = sum(1 for c in checks if c.verdict == "UNKNOWN")
    if worst == "PASS":
        summary = f"All {total} checks passed."
    else:
        parts = []
        if failed:
            parts.append(f"{failed} of {total} checks failed")
        if unknown:
            parts.append(f"{unknown} of {total} {'has' if unknown == 1 else 'have'} "
                         f"no verdict (UNKNOWN)")
        summary = "; ".join(parts) + "."
    head = [
        _COMMENT_MARKER,
        f"## {_ICON[worst]} RuleHawk firewall gate: {worst}",
        "",
        f"{summary} The headline is the worst verdict across every check in "
        f"this run.",
        "",
        "| Check | Verdict | Detail |",
        "|---|---|---|",
    ]
    rows = [f"| {_cell(c.label)} | {_ICON[c.verdict]} {c.verdict} | {_cell(c.detail)} |"
            for c in checks]
    tail = ["", FOOTER]

    def assemble(sections: List[str], note: str = "", shown=rows) -> str:
        body = head + shown
        if note:
            body += ["", note]
        for s in sections:
            body += ["", "---", "", s]
        return "\n".join(body + tail)

    if detail == "all":
        return assemble([_section(c) for c in checks if c.reported])
    if detail == "failing":
        return assemble([_section(c) for c in checks
                         if c.reported and c.verdict != "PASS"],
                        "<sub>Passing checks' reports are in each job's "
                        "summary; this comment shows the failing ones.</sub>")
    note = ("<sub>The full reports are too long for one comment; they are in "
            "each job's summary.</sub>")
    if detail == "table":
        return assemble([], note)
    # Even the table is too long: keep every non-passing row first.
    order = sorted(range(len(rows)), key=lambda i: -_RANK[checks[i].verdict])
    shown: List[str] = []
    for i in order:
        trial = assemble([], note, shown + [rows[i]])
        if len(trial) > MAX_COMMENT_CHARS - 200:
            break
        shown.append(rows[i])
    hidden = len(rows) - len(shown)
    return assemble([], note + f" <sub>{hidden} more check(s) are not listed.</sub>",
                    shown)


def render(paths: Sequence[str], expect: Optional[int] = None) -> Tuple[str, str]:
    """(comment body, worst verdict) for every result under `paths`."""
    return render_checks(collect(paths, expect))


def render_checks(checks: List[Check]) -> Tuple[str, str]:
    worst = max((c.verdict for c in checks), key=lambda v: _RANK[v])
    # A single reported check reads exactly as the single-gate comment always
    # has, so existing one-check workflows see no change.
    if len(checks) == 1 and checks[0].reported:
        return f"{_COMMENT_MARKER}\n{checks[0].markdown.rstrip(chr(10))}", worst
    for level in ("all", "failing", "table", "rows"):
        body = _render_many(checks, worst, level)
        if len(body) <= MAX_COMMENT_CHARS:
            return body, worst
    return body, worst


def _take(argv: List[str], flag: str) -> Optional[str]:
    if flag in argv:
        k = argv.index(flag)
        if k + 1 >= len(argv):
            raise ValueError(f"{flag} requires a value")
        val = argv[k + 1]
        del argv[k:k + 2]
        return val
    return None


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or "-h" in argv or "--help" in argv:
        print(_USAGE)
        return 0 if argv else 2
    quiet = False
    for q in ("-q", "--quiet"):
        while q in argv:
            quiet = True
            argv.remove(q)
    try:
        expect_s = _take(argv, "--expect")
        comment_path = _take(argv, "--comment")
        summary_path = _take(argv, "--summary")
    except ValueError as e:
        print(f"rulehawk combine: {e}", file=sys.stderr)
        return 2
    expect: Optional[int] = None
    if expect_s is not None:
        if not expect_s.isdigit():
            print(f"rulehawk combine: --expect needs a whole number, got "
                  f"{expect_s!r}", file=sys.stderr)
            return 2
        expect = int(expect_s)
    unknown = [a for a in argv if a.startswith("-")]
    if unknown:
        print(f"rulehawk combine: unknown option(s): {' '.join(unknown)}",
              file=sys.stderr)
        return 2
    if not argv:
        print("rulehawk combine: no result files or directories given",
              file=sys.stderr)
        return 2

    checks = collect(argv, expect)
    body, worst = render_checks(checks)
    if not quiet:
        for c in checks:
            print(f"  [{c.verdict:7}] {c.label}: {c.detail}")
        print(f"  VERDICT: {worst} ({len(checks)} check(s))")
    try:
        if comment_path:
            with open(comment_path, "w", encoding="utf-8") as fh:
                fh.write(body + "\n")
        summary_target = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_target:
            with open(summary_target, "a" if summary_path is None else "w",
                      encoding="utf-8") as fh:
                fh.write(body.split("\n", 1)[1] + "\n")
    except OSError as e:
        print(f"rulehawk combine: cannot write output: {e}", file=sys.stderr)
        return 2
    return _EXIT[worst]


if __name__ == "__main__":
    raise SystemExit(main())
