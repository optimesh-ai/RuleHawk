"""RuleHawk CLI:  rulehawk <config-file> [--json] [--junos] [--panos] [--iptables]

Day-1 value: point it at a firewall/ACL config file (Cisco IOS extended ACL,
Cisco ASA, NX-OS, Arista EOS, Juniper Junos firewall filter, Palo Alto PAN-OS
security policy, or Linux iptables/ip6tables filter rules) and get a ranked
hygiene report in seconds. The vendor is auto-detected; force Junos with
--junos, PAN-OS with --panos, or iptables with --iptables. Reads stdin if no file.

Subcommand:  rulehawk gate <file-or-glob>... [--policy P] [--fail-on LEVEL] ...
audits many configs at once and emits SARIF + a PR-comment + a step summary for
the GitHub Action gate (see rulehawk/gate.py). `rulehawk gate --help` for detail.

Optional PATH-GROUNDING: with `--policy P --hh-snapshot DIR --hh-from DEVICE`,
each segmentation-violation witness is routed through Hammerhead's forwarding
model (`hammerhead reachability`) so violations on infeasible routing paths are
suppressed to informational while confirmed leaks are stamped path-confirmed.
Soundness: only a deterministic, NAT-free "not delivered" verdict ever downgrades
a finding — NAT/error/unknown-device fail closed and keep it. See pathground.py.
"""

from __future__ import annotations

import json
import sys

from .analyze import analyze, score
from .parse import parse_acls
from .parse_awssg import detect as detect_awssg, parse_awssg
from .parse_eos import detect as detect_eos, parse_eos
from .parse_fortinet import detect as detect_fortinet, parse_fortinet
from .parse_infoblox import detect as detect_infoblox, parse_infoblox
from .parse_iptables import detect as detect_iptables, parse_iptables
from .parse_junos import detect as detect_junos, parse_junos
from .parse_msdns import detect as detect_msdns, parse_msdns
from .parse_nxos import detect as detect_nxos, parse_nxos
from .parse_panos import detect as detect_panos, parse_panos
from .parse_umbrella import detect as detect_umbrella, parse_umbrella
from .parse_winfw import detect as detect_winfw, parse_winfw
from .pathground import HammerheadReachOracle, path_ground
from .report import to_json, to_text
from .segcheck import check_segmentation


_USAGE = """rulehawk — firewall/ACL hygiene auditor (single-file report)

usage:
  rulehawk <config-file> [options]         audit ONE config file (exactly one)
  rulehawk - [options]                     read the config from stdin
  cat config | rulehawk [options]          piped stdin also works
  rulehawk gate <file-or-glob>... [...]    multi-file CI gate (`rulehawk gate --help`)

options:
  --json               emit the machine-readable JSON report instead of text
  --junos              force the Juniper Junos parser (skip auto-detection)
  --panos              force the Palo Alto PAN-OS parser (skip auto-detection)
  --iptables           force the Linux iptables parser (skip auto-detection)
  --policy PATH        segmentation policy JSON (zones + must_not_reach)
  --hh-snapshot DIR    Hammerhead snapshot dir for path-grounding (needs --hh-from)
  --hh-from DEVICE     source device for path-grounding (needs --hh-snapshot)
  -h, --help           show this help

Vendor is auto-detected: Cisco IOS/ASA/NX-OS/Umbrella, Arista EOS, Juniper Junos,
Palo Alto PAN-OS, Fortinet FortiGate, Linux iptables, Windows Firewall, AWS
Security Groups, Infoblox/BIND DNS ACLs, Microsoft DNS.

Single-file mode takes exactly one config file. To audit several at once (e.g.
a shell glob like `rulehawk configs/*.txt`), use `rulehawk gate <files...>` —
passing extra files here is an error (exit 2), never a partial audit.

exit codes:
  0  config parsed; no critical/high findings
  1  at least one critical/high finding
  2  parse failure (no rules parsed), unreadable input, or bad usage
"""


def _take_opt(argv: list[str], name: str) -> str | None:
    """Pop `--name VALUE` from argv in place; return VALUE, or None if absent.
    Returns the sentinel '' when the flag is present but missing its value so the
    caller can emit a usage error."""
    if name not in argv:
        return None
    k = argv.index(name)
    if k + 1 >= len(argv):
        return ""  # present-but-empty -> caller reports the usage error
    val = argv[k + 1]
    del argv[k:k + 2]
    return val


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Subcommand: `rulehawk gate ...` runs the multi-file CI gate (SARIF, PR
    # comment, severity threshold). Everything else is the single-file report.
    if argv and argv[0] == "gate":
        from .gate import main as gate_main
        return gate_main(argv[1:])
    # Help first: `rulehawk --help` / `-h` must print usage and exit 0, never
    # be mistaken for a config-file path (mirrors gate.py's pattern).
    if "-h" in argv or "--help" in argv:
        print(_USAGE)
        return 0
    as_json = "--json" in argv
    force_junos = "--junos" in argv
    force_panos = "--panos" in argv
    force_iptables = "--iptables" in argv
    argv = [a for a in argv
            if a not in ("--json", "--junos", "--panos", "--iptables")]
    hh_snapshot = _take_opt(argv, "--hh-snapshot")
    hh_from = _take_opt(argv, "--hh-from")
    if hh_snapshot == "" or hh_from == "":
        print("rulehawk: --hh-snapshot and --hh-from each require a value",
              file=sys.stderr)
        return 2
    if bool(hh_snapshot) != bool(hh_from):
        print("rulehawk: path-grounding needs BOTH --hh-snapshot and --hh-from",
              file=sys.stderr)
        return 2
    policy_path = None
    if "--policy" in argv:
        k = argv.index("--policy")
        if k + 1 >= len(argv):
            print("rulehawk: --policy requires a file", file=sys.stderr)
            return 2
        policy_path = argv[k + 1]
        del argv[k:k + 2]
    # Anything left that looks like a flag is an unknown option (bare "-" means
    # stdin). Reject it explicitly instead of trying to open() it as a file —
    # a typo like --jsn must say "unknown option", not "cannot read file".
    for a in argv:
        if a.startswith("-") and a != "-":
            print(f"rulehawk: unknown option {a!r} (see `rulehawk --help`)",
                  file=sys.stderr)
            return 2
    # Exactly one positional: silently auditing only argv[0] of a shell glob
    # (`rulehawk configs/*.txt`) would hand the user a verdict for one file
    # while they believe all were audited — the false bill of health this tool
    # exists to prevent. Fail closed with bad-usage (exit 2) and point at the
    # multi-file gate instead.
    if len(argv) > 1:
        print(f"rulehawk: got {len(argv)} config files; single-file mode "
              "audits exactly one — use `rulehawk gate <files...>` for "
              "multi-file audits", file=sys.stderr)
        return 2
    # Bare `rulehawk` on an interactive terminal would silently block on
    # sys.stdin.read(); print usage instead. Piped/redirected stdin still works.
    if not argv and sys.stdin.isatty():
        print(_USAGE, file=sys.stderr)
        return 2
    if argv and argv[0] != "-":
        try:
            text = open(argv[0], encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"rulehawk: cannot read {argv[0]!r}: {e}", file=sys.stderr)
            return 2
    else:
        # Read stdin as bytes and decode leniently: a non-UTF-8 config (a
        # latin-1 export, a stray BOM/binary) must degrade like the file path
        # does (errors="replace"), never crash with an uncaught
        # UnicodeDecodeError and exit 1 (the "finding found" code).
        try:
            raw = sys.stdin.buffer.read()
        except (AttributeError, OSError):
            raw = sys.stdin.read().encode("utf-8", "replace")
        text = raw.decode("utf-8", "replace")  # no file, or explicit "-"

    # Auto-detect vendor (same precedence order as gate.py _pick_parser).
    # "ios-asa" is the fallback: no positive signal was found.
    forced = force_junos or force_panos or force_iptables
    if force_junos or (not forced and detect_junos(text)):
        aces, notes = parse_junos(text)
        vendor = "junos"
    elif force_panos or (not forced and detect_panos(text)):
        aces, notes = parse_panos(text)
        vendor = "panos"
    elif force_iptables or (not forced and detect_iptables(text)):
        aces, notes = parse_iptables(text)
        vendor = "iptables"
    elif not forced and detect_nxos(text):
        aces, notes = parse_nxos(text)
        vendor = "nxos"
    elif not forced and detect_eos(text):
        aces, notes = parse_eos(text)
        vendor = "eos"
    elif not forced and detect_fortinet(text):
        aces, notes = parse_fortinet(text)
        vendor = "fortinet"
    elif not forced and detect_awssg(text):
        aces, notes = parse_awssg(text)
        vendor = "aws-sg"
    elif not forced and detect_umbrella(text):
        aces, notes = parse_umbrella(text)
        vendor = "umbrella"
    elif not forced and detect_winfw(text):
        aces, notes = parse_winfw(text)
        vendor = "winfw"
    elif not forced and detect_msdns(text):
        aces, notes = parse_msdns(text)
        vendor = "msdns"
    elif not forced and detect_infoblox(text):
        aces, notes = parse_infoblox(text)
        vendor = "infoblox"
    else:
        aces, notes = parse_acls(text)
        vendor = "ios-asa"
    findings = analyze(aces)
    if policy_path:
        try:
            policy = json.load(open(policy_path, encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"rulehawk: cannot read policy {policy_path!r}: {e}", file=sys.stderr)
            return 2
        seg = check_segmentation(aces, policy)
        if hh_snapshot and hh_from:
            oracle = HammerheadReachOracle(hh_snapshot, hh_from)
            seg = path_ground(seg, oracle)
        findings += seg
    n_rules = len(aces)
    if as_json:
        print(to_json(findings, notes, n_rules, vendor))
    else:
        print(to_text(findings, notes, n_rules, vendor))
    # Distinct exit codes: 0 clean · 1 finding at critical/high · 2 parse failure.
    # Exit 2 (fail-closed) when NOTHING was parsed: absence of findings must NOT
    # imply a clean audit when the input was never read as a firewall config.
    if not n_rules:
        return 2
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
