#!/usr/bin/env python3
"""The #42 phase-2 harness (design v2 section 13, v4 section 11).

A developer script: it is not shipped (the wheel packages only
`rulehawk`) and no Action runs it. It runs each file through the gate
with RULEHAWK_SHADOW=1 set in this process only, and prints the shadow
per-file list for both placement modes:

- `default`: the shadow blocking reason with the default placement mode;
- `strict`: the blocking reason under strict placement;
- `would_pass`, the checker's agreement, and the checker's and the
  engine's answer per assertion.

Then, for each mode, the list of files that would pass and the count of
each blocking reason, so a reviewer sees the exact lists.

With no file named, it runs every row of the four EXPECTED tables under
tests/fixtures/fail_closed/variants/design (with the policy each row
names) and the three controls (with v4_ip). With files named, it runs
those, with `--policy` (default: v4_ip).

Usage: python scripts/shadow_harness.py [--policy POLICY.json] [FILE ...]
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_CONTROLS = ("controls/k00_base.conf", "controls/p00_base.set", "controls/i00_base.sh")
COLUMNS = ("file", "policy", "dialects", "grammar", "default", "strict", "would_pass",
           "checker_agrees", "checker", "engine")


def _cases():
    out = []
    for name in sorted(os.listdir(_D)):
        if name.startswith("EXPECTED") and name.endswith(".tsv"):
            with open(os.path.join(_D, name), encoding="utf-8") as fh:
                out += [(r["file"], r["policy"]) for r in csv.DictReader(fh, delimiter="\t")]
    out += [(c, "v4_ip") for c in _CONTROLS]
    return [(os.path.join(_D, f), f, os.path.join(_D, "pol", p + ".json"), p)
            for f, p in out]


def _shadow(path, policy_path):
    from rulehawk import gate as g
    with open(policy_path, encoding="utf-8") as fh:
        pol = json.load(fh)
    d = json.loads(g.to_json(g.run_gate([path], pol, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    return f.get("shadow") or {}


def _row(label, policy, sh):
    b = sh.get("boundary") or {}
    gm = sh.get("grammar")
    cv = sh.get("checker_verdict") or {}
    answers = cv.get("assertions") or []
    reason = sh.get("blocking_reason", "-")
    return {
        "file": label,
        "policy": policy,
        "dialects": ",".join(b.get("dialects") or []) or "-",
        "grammar": (gm["reason"] or "parses") if gm else
                   ("unavailable" if "grammar_unavailable" in sh else "-"),
        "default": reason,
        "strict": sh.get("blocking_reason_strict", reason),
        "would_pass": "true" if sh.get("would_pass") else "false",
        "checker_agrees": ("true" if cv.get("agrees") else "false") if cv else "-",
        "checker": ",".join(a["checker"] for a in answers) or "-",
        "engine": ",".join(a["engine"] for a in answers) or "-",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--policy", default=os.path.join(_D, "pol", "v4_ip.json"))
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv)
    sys.path.insert(0, _ROOT)
    os.environ["RULEHAWK_SHADOW"] = "1"          # this process only
    if args.files:
        cases = [(f, os.path.relpath(f, _D) if f.startswith(_D) else f, args.policy,
                  os.path.splitext(os.path.basename(args.policy))[0]) for f in args.files]
    else:
        cases = _cases()
    rows = [_row(label, pname, _shadow(path, ppath)) for path, label, ppath, pname in cases]
    print("\t".join(COLUMNS))
    for r in rows:
        print("\t".join(r[c] for c in COLUMNS))
    print()
    for mode in ("default", "strict"):
        # would_pass is one field today; it is listed under both modes so
        # the lists stay comparable when the strict mode gets its own.
        passing = [r["file"] for r in rows if r["would_pass"] == "true"]
        print(f"would pass ({mode} placement): {len(passing)}")
        for f in passing:
            print("  " + f)
        print(f"blocking reasons ({mode} placement):")
        for reason, n in sorted(collections.Counter(r[mode] for r in rows).items()):
            print(f"  {reason}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
