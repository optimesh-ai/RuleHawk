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
  rulehawk combine <result-file-or-dir>... [--expect N] [--needs JSON]
                   [--comment PATH] [--summary PATH] [-q]

--needs takes the combining job's `toJSON(needs)`: a gate job that did not
succeed, but whose results show no failure, is UNKNOWN. Directories are
searched recursively for *.json. Exit code: 0 PASS, 1 FAIL,
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
_FAIL_ON = ("critical", "high", "medium", "low", "none")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

_USAGE = """rulehawk combine — one PR comment for every check in a run

usage:
  rulehawk combine <result-file-or-dir>... [--expect N] [--needs JSON]
                   [--comment PATH] [--summary PATH] [-q]

  --expect N       N checks must report; fewer make the verdict UNKNOWN
  --needs JSON     the combining job's toJSON(needs): a gate job that did not
                   succeed, but whose results show no failure, is UNKNOWN
  --comment PATH   write the sticky PR-comment body
  --summary PATH   write the report (default: $GITHUB_STEP_SUMMARY when set)
  -q, --quiet      no console report

Directories are searched recursively for *.json.
Exit code: 0 PASS, 1 FAIL, 2 UNKNOWN (or a usage error).
"""


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
    attempt, fail_on = rec.get("attempt", 1), rec.get("fail_on")
    n, pf, job = rec.get("violations"), rec.get("parse_failures"), rec.get("job", "")
    if not (isinstance(passed, bool) and _is_int(code) and _is_int(attempt)
            and _is_int(n) and _is_int(pf) and isinstance(label, str)
            and isinstance(md, str) and isinstance(job, str)
            and fail_on in _FAIL_ON):
        return Check(label=name, verdict="UNKNOWN",
                     detail=f"`{name}` is an incomplete result record")
    if passed:
        # PASS only when every field agrees: exit 0, nothing at the threshold,
        # every file parsed (advisory `none` never blocks), a passing report.
        ok = (code == 0 and n == 0 and (pf == 0 or fail_on == "none")
              and md.startswith("## ✅ "))
        verdict, detail = "PASS", f"no findings at or above `{fail_on}`"
    else:
        ok = code in (1, 2) and md.startswith("## ❌ ")
        verdict = "FAIL"
        if code == 2 and not n:
            detail = (f"fail-closed: {pf} file(s) parsed to zero rules" if pf
                      else "fail-closed: the gate could not audit its input")
        else:
            detail = f"{n} finding(s) at or above `{fail_on}`"
            if pf:
                detail += f", plus {pf} unparseable file(s)"
    if not ok:
        # The fields disagree with each other or with the report: trust none.
        return Check(label=label or name, verdict="UNKNOWN",
                     detail=f"`{name}` reports an inconsistent verdict")
    return Check(label=label or name, verdict=verdict, detail=detail,
                 markdown=md, job=job, attempt=attempt, reported=True)


def collect(paths: Sequence[str], expect: Optional[int] = None,
            needs: Optional[Dict[str, dict]] = None) -> List[Check]:
    """Load every result, keep only the newest run attempt of each check, and
    add an UNKNOWN entry for each expected check that never reported.

    `needs` is the combining job's `needs` context (`toJSON(needs)`). A gate
    job that did not succeed but whose results show no failure is UNKNOWN:
    its newest attempt may not have reported (a re-run whose upload failed
    leaves the previous attempt's PASS behind), so its PASS is not proof."""
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
    for job, info in sorted((needs or {}).items()):
        result = info.get("result") if isinstance(info, dict) else None
        if result == "success":
            continue
        mine = [c for c in checks if c.reported and c.job == job]
        if mine and not any(c.verdict == "FAIL" for c in mine):
            checks.append(Check(
                label=f"job {job}", verdict="UNKNOWN",
                detail=(f"the job ended `{result}`, but its results show no "
                        f"failure: they may be from an earlier attempt")))
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


def render(paths: Sequence[str], expect: Optional[int] = None,
           needs: Optional[Dict[str, dict]] = None) -> Tuple[str, str]:
    """(comment body, worst verdict) for every result under `paths`."""
    return render_checks(collect(paths, expect, needs))


def render_checks(checks: List[Check]) -> Tuple[str, str]:
    worst = max((c.verdict for c in checks), key=lambda v: _RANK[v])
    # A single reported check reads exactly as the single-gate comment always
    # has, so existing one-check workflows see no change.
    if len(checks) == 1 and checks[0].reported:
        body = f"{_COMMENT_MARKER}\n{checks[0].markdown.rstrip(chr(10))}"
        if len(body) <= MAX_COMMENT_CHARS:
            return body, worst
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
        needs_s = _take(argv, "--needs")
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
    needs: Optional[Dict[str, dict]] = None
    if needs_s is not None and needs_s.strip():
        try:
            needs = json.loads(needs_s)
        except ValueError as e:
            print(f"rulehawk combine: --needs is not JSON: {e}", file=sys.stderr)
            return 2
        if not isinstance(needs, dict):
            print("rulehawk combine: --needs must be a JSON object (toJSON(needs))",
                  file=sys.stderr)
            return 2
    unknown = [a for a in argv if a.startswith("-")]
    if unknown:
        print(f"rulehawk combine: unknown option(s): {' '.join(unknown)}",
              file=sys.stderr)
        return 2
    if not argv:
        print("rulehawk combine: no result files or directories given",
              file=sys.stderr)
        return 2

    checks = collect(argv, expect, needs)
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
