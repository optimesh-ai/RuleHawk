"""RuleHawk CLI:  rulehawk <config-file> [--json]

Day-1 value: point it at a firewall/ACL config file (Cisco IOS extended ACL or
Cisco ASA) and get a ranked hygiene report in seconds. Reads stdin if no file.
"""

from __future__ import annotations

import json
import sys

from .analyze import analyze, score
from .parse import parse_acls
from .report import to_json, to_text
from .segcheck import check_segmentation


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    policy_path = None
    if "--policy" in argv:
        k = argv.index("--policy")
        if k + 1 >= len(argv):
            print("rulehawk: --policy requires a file", file=sys.stderr)
            return 2
        policy_path = argv[k + 1]
        del argv[k:k + 2]
    if argv and argv[0] != "-":
        try:
            text = open(argv[0], encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"rulehawk: cannot read {argv[0]!r}: {e}", file=sys.stderr)
            return 2
    else:
        text = sys.stdin.read()  # no file, or explicit "-"

    aces, notes = parse_acls(text)
    findings = analyze(aces)
    if policy_path:
        try:
            policy = json.load(open(policy_path, encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"rulehawk: cannot read policy {policy_path!r}: {e}", file=sys.stderr)
            return 2
        findings += check_segmentation(aces, policy)
    if as_json:
        print(to_json(findings, notes, len(aces)))
    else:
        print(to_text(findings, notes, len(aces)))
    # Non-zero exit when a critical/high issue is present, so it's CI-usable.
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
