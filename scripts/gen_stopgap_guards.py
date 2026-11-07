#!/usr/bin/env python3
"""Re-derive tests/fixtures/stopgap_guards_e04630e.json from git.

The fixture pins #44's fail-closed guard lines byte for byte: every contiguous
run of lines that `git diff -U0 v0.4.0 e04630e` adds to the Actions, the
hosted page and its glue, plus the whole enforce steps as they are at
e04630e. tests/test_exitcodes_allclear.py checks the tree against it, and
re-derives it with derive() when both commits are in the clone.

Usage: python scripts/gen_stopgap_guards.py [REPO]   (writes the fixture)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

BASE, HEAD = "v0.4.0", "e04630e"
FILES = ["action.yml", "comment/action.yml", "docs/index.html", "docs/worker.js"]
STEPS = {"action.yml": ["Enforce gate verdict"],
         "comment/action.yml": ["Combine every check", "Enforce the combined verdict"]}
FIXTURE = os.path.join("tests", "fixtures", "stopgap_guards_e04630e.json")


def _git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True,
                          text=True, check=True).stdout


def _added_runs(diff: str) -> list:
    runs, cur = [], []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            cur.append(line[1:])
        elif cur:
            runs.append("\n".join(cur) + "\n")
            cur = []
    if cur:
        runs.append("\n".join(cur) + "\n")
    return runs


def _step(lines: list, name: str) -> str:
    i = next(n for n, l in enumerate(lines) if l.strip() == f"- name: {name}")
    indent = len(lines[i]) - len(lines[i].lstrip())
    j = next((n for n in range(i + 1, len(lines))
              if lines[n].lstrip().startswith("- name: ")
              and len(lines[n]) - len(lines[n].lstrip()) == indent), len(lines))
    return "".join(lines[i:j]).rstrip("\n") + "\n"


def derive(repo: str) -> dict:
    out = {"_source": f"git diff -U0 {BASE} {HEAD} (contiguous added lines) "
                      f"and whole steps at {HEAD}"}
    for f in FILES:
        text = _git(repo, "show", f"{HEAD}:{f}")
        runs = _added_runs(_git(repo, "diff", "-U0", BASE, HEAD, "--", f))
        lines = text.splitlines(keepends=True)
        steps = [_step(lines, name) for name in STEPS.get(f, [])]
        for r in runs + steps:
            assert r in text, (f, r[:80])
        out[f] = {"runs": runs, "steps": steps}
    return out


def main(argv: list) -> int:
    repo = argv[1] if len(argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(repo, FIXTURE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(derive(repo), fh, indent=1, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
