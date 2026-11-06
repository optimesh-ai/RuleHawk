"""FAIL-unchanged baseline for the fail-closed stopgap (0.3.2).

The stopgap turns every pass into UNKNOWN. It must not change a single FAIL:
the same findings, severities, messages and witness packets, the same SARIF
results, and the same exit 1 / exit 2.

`collect()` audits every sample config, every corpus fixture and every config
the hosted page ships (docs/index.html SAMPLE_*), each with no policy and with
each policy below, and returns everything a FAIL is made of. The assertion
pass kinds (`segmentation-ok`, `connectivity-ok`) and the stopgap's UNKNOWN
kinds that replace them are left out: they are not FAIL findings, and they are
exactly what the stopgap changes.

`tests/stopgap_fail_golden.json` was written by running this module on the
tree before the stopgap (`python tests/stopgap_fail_baseline.py`).
tests/test_stopgap.py compares the current tree against it.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rulehawk import cli  # noqa: E402
from rulehawk import gate  # noqa: E402

GOLDEN = os.path.join(ROOT, "tests", "stopgap_fail_golden.json")

# What the stopgap changes; everything else must be identical.
CHANGED_KINDS = frozenset({"segmentation-ok", "connectivity-ok",
                           "segmentation-unknown", "connectivity-unknown"})

# A must_reach assertion so connectivity FAILs (connectivity-broken) are pinned
# too, beside the shipped must_not_reach policies.
MUST_REACH_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"],
              "DMZ": ["203.0.113.0/24"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                        "ports": [445, 3389, 22]}],
    "must_reach": [{"src": "CORP", "dst": "DMZ", "proto": "tcp",
                    "ports": [443]},
                   {"src": "DMZ", "dst": "PCI", "proto": "tcp",
                    "ports": [1433]}],
}


def _configs():
    out = []
    sdir = os.path.join(ROOT, "samples")
    for n in sorted(os.listdir(sdir)):
        if n != "policy.json":
            out.append((f"samples/{n}", os.path.join(sdir, n)))
    cdir = os.path.join(ROOT, "scripts", "corpus", "ten_router_acl")
    if os.path.isdir(cdir):
        for n in sorted(os.listdir(cdir)):
            out.append((f"scripts/corpus/ten_router_acl/{n}", os.path.join(cdir, n)))
    return out


def _web_samples():
    path = os.path.join(ROOT, "docs", "index.html")
    html = open(path, encoding="utf-8").read()
    out = []
    for m in re.finditer(r"const\s+(SAMPLE_[A-Z_]+)\s*=\s*`([^`]*)`", html):
        if m.group(1) != "SAMPLE_POLICY":
            out.append((f"docs/index.html:{m.group(1)}", m.group(2)))
    return out


def _policies(tmp):
    pols = [("none", None)]
    for rel in ("samples/policy.json", "scripts/corpus/policy_corp_pci.json"):
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            pols.append((rel, p))
    p = os.path.join(tmp, "must_reach.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(MUST_REACH_POLICY, fh)
    pols.append(("must_reach", p))
    return pols


def _finding(f) -> dict:
    return {"rule_id": f.get("rule_id"), "kind": f.get("kind"),
            "severity": f.get("severity"), "message": f.get("message"),
            "rule": f.get("rule"), "cited": f.get("cited"), "fix": f.get("fix"),
            "witness": f.get("witness"), "line": f.get("line")}


def _cli(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc = cli.main(args)
    return rc, buf.getvalue()


def _one(label, path, pol_label, pol_path):
    pargs = ["--policy", pol_path] if pol_path else []
    rc, out = _cli([path, "--json"] + pargs)
    rep = json.loads(out)
    findings = sorted((_finding(f) for f in rep["findings"]
                       if f["kind"] not in CHANGED_KINDS),
                      key=lambda d: json.dumps(d, sort_keys=True))
    policy = None
    if pol_path:
        with open(pol_path, encoding="utf-8") as fh:
            policy = json.load(fh)
    g = gate.run_gate([path], policy, "high")
    sarif = json.loads(gate.to_sarif(g, version="x"))
    results = [{"ruleId": r["ruleId"], "level": r["level"],
                "message": r["message"]["text"],
                "line": r["locations"][0]["physicalLocation"]["region"]["startLine"],
                "fp": r["partialFingerprints"]["ruleHawk/v2"]}
               for r in sarif["runs"][0]["results"]]
    return {
        "config": label, "policy": pol_label,
        "cli_exit": rc, "gate_exit_high": g.exit_code(),
        "findings": findings,
        "sarif_results": results,
        "gate_violations": sorted(
            json.dumps(_finding({"rule_id": f.rule_id, "kind": f.kind,
                                 "severity": f.severity, "message": f.message,
                                 "rule": f.rule, "cited": f.cited, "fix": f.fix,
                                 "witness": f.witness, "line": f.line}),
                       sort_keys=True)
            for _, f in g.violations),
    }


def collect() -> list:
    rows = []
    cwd = os.getcwd()
    os.chdir(ROOT)      # SARIF uris (and so fingerprints) are cwd-relative
    try:
        return _collect(rows)
    finally:
        os.chdir(cwd)


def _collect(rows) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        pols = _policies(tmp)
        cfgs = list(_configs())
        for name, text in _web_samples():
            p = os.path.join(tmp, re.sub(r"[^A-Za-z0-9_]", "_", name) + ".txt")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
            cfgs.append((name, p))
        for label, path in cfgs:
            for pol_label, pol_path in pols:
                row = _one(label, path, pol_label, pol_path)
                # Paths under tmp differ per run; SARIF uris carry them only for
                # the hosted samples, so key those on the label instead.
                for r in row["sarif_results"]:
                    r["fp"] = r["fp"] if not path.startswith(tmp) else "<tmp>"
                rows.append(row)
    return rows


if __name__ == "__main__":
    with open(GOLDEN, "w", encoding="utf-8") as fh:
        json.dump(collect(), fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"wrote {GOLDEN}")
