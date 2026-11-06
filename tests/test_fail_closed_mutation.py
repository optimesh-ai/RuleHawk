"""Mutation self-check (review of #42, round 5).

Every counterexample and every reviewer variant (rounds 2-4) whose answer
is UNKNOWN or FAIL today is mutated in ways a device does not care about,
or that make the input invalid, and no mutant may come back PASS:

- remove the indentation of one line;
- insert a junk line, or a line that is only a no-break space, before one line;
- put \\v, \\x85 or \\x0c inside a `description`;
- put a space into an interface name (`Gi0/1` -> `Gi 0/1`);
- upper-case the first word of one line;
- CRLF line ends;
- tabs for the leading spaces.

A PASS from any of these means some check reads lines or stanzas
differently from the device, which is the class of bug review-rh42-r4 found.
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
from typing import Iterator, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import cli  # noqa: E402
from rulehawk.failclosed import assertion_verdict, build_context  # noqa: E402
from rulehawk.model import strip_pager  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FX = os.path.join(_ROOT, "tests", "fixtures", "fail_closed")

# The counterexamples' own policies (wedge-check audit/cases.txt).
_CX_POL = {
    "01_ipt_input_only.sh": "v4_host22.json", "02_ipt_no_policy.sh": "v4_tcp445.json",
    "03_ipt_proto0.sh": "v4_tcp445.json", "04_ip6t_save.rules": "v6_tcp445.json",
    "05_ipt_delete.sh": "v4_ip.json", "06_panos_default.set": "v4_tcp445.json",
    "07_panos_user.set": "v4_tcp445.json", "08_junos_ls.conf": "v4_ip.json",
    "09_junos_srx.conf": "v4_tcp445.json", "10_ios_vty_acl.cfg": "v4_tcp445.json",
    "11_asa_seclevel.cfg": "v4_ip.json", "12_ios_v6_icmp.cfg": "v6_icmpv6.json",
    "12b_ios_v6_nd.cfg": "v6_icmpv6.json", "13_asa_icmp6.cfg": "v6_icmpv6.json",
    "14_ios_mask.cfg": "v4_tcp445.json", "15_ios_dynamic.cfg": "v4_ip.json",
    "16_ios_established.cfg": "v4_tcp445.json", "17_ios_fragments.cfg": "v4_tcp445.json",
    "18_nft.conf": "v4_ip.json", "19_nxos_v6_nd.cfg": "v6_icmpv6.json",
}


def _policy(name: str) -> dict:
    with open(os.path.join(_FX, "pol", name), encoding="utf-8") as fh:
        return json.load(fh)


def _corpus() -> List[Tuple[str, str]]:
    out = [(os.path.join(_FX, "cfg", f), p) for f, p in sorted(_CX_POL.items())]
    for r in ("r2", "r3", "r4"):
        for path in sorted(glob.glob(os.path.join(_FX, "variants", r, "*"))):
            pol = "v4_reach_ip.json" if "reach" in os.path.basename(path) else "v4_ip.json"
            out.append((path, pol))
    return out


def verdict(text: str, policy: dict) -> str:
    """The CLI's path (cli.main): vendor detection, parse, fail-closed
    context, search. `test_verdict_matches_the_cli` pins the two together."""
    if cli.detect_junos(text):
        aces, notes, v = *cli.parse_junos(text), "junos"
    elif cli.detect_panos(text):
        aces, notes, v = *cli.parse_panos(text), "panos"
    elif cli.detect_iptables(text):
        aces, notes, v = *cli.parse_iptables(text), "iptables"
    elif cli.detect_awssg(text):
        aces, notes, v = *cli.parse_awssg(text), "aws-sg"
    elif cli.detect_nxos(text):
        aces, notes, v = *cli.parse_nxos(text), "nxos"
    elif cli.detect_eos(text):
        aces, notes, v = *cli.parse_eos(text), "eos"
    else:
        aces, notes, v = *cli.parse_acls(text), "ios-asa"
    ctx = build_context(text, aces, notes, v)
    return assertion_verdict(check_segmentation(aces, policy, context=ctx)) or "NONE"


def _read(path: str) -> str:
    with open(path, "rb") as fh:
        return strip_pager(fh.read().decode("utf-8", "replace"))


_IFNAME = re.compile(r"(?i)^(\s*interface\s+[A-Za-z-]+)(\d)")


def mutants(text: str) -> Iterator[Tuple[str, str]]:
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if ln[:1] in (" ", "\t"):
            yield f"dedent:{i + 1}", "\n".join(lines[:i] + [ln.lstrip(" \t")] + lines[i + 1:])
        for tag, junk in (("junk", "xyzzy"), ("nbsp", " ")):
            yield f"{tag}-before:{i + 1}", "\n".join(lines[:i] + [junk] + lines[i:])
        if "description" in ln:
            k = ln.index("description") + len("description ")
            for ch in ("\v", "\x85", "\x0c"):
                yield (f"ctl-{ord(ch):02x}-in-description:{i + 1}",
                       "\n".join(lines[:i] + [ln[:k] + "a" + ch + ln[k:]] + lines[i + 1:]))
        m = _IFNAME.match(ln)
        if m:
            spaced = _IFNAME.sub(r"\1 \2", ln, count=1)
            yield f"ifname-space:{i + 1}", "\n".join(lines[:i] + [spaced] + lines[i + 1:])
        words = ln.split(" ")
        lead = next((j for j, w in enumerate(words) if w), None)
        if lead is not None and words[lead].upper() != words[lead]:
            up = words[:lead] + [words[lead].upper()] + words[lead + 1:]
            yield f"upper-first-word:{i + 1}", "\n".join(lines[:i] + [" ".join(up)] + lines[i + 1:])
    yield "crlf", "\r\n".join(lines)
    yield "tabs", "\n".join(re.sub(r"^ +", "\t", ln) for ln in lines)


def _run_all():
    checked, n_mutants, bad = 0, 0, []
    for path, pol in _corpus():
        policy = _policy(pol)
        text = _read(path)
        base = verdict(text, policy)
        if base == "PASS":
            continue
        checked += 1
        for tag, mutant in mutants(text):
            n_mutants += 1
            if verdict(mutant, policy) == "PASS":
                bad.append(f"{os.path.relpath(path, _FX)} [{base}] {tag}")
    return checked, n_mutants, bad


def test_no_mutant_of_a_non_pass_answer_is_a_pass():
    checked, n_mutants, bad = _run_all()
    print(f"\nmutation self-check: {checked} configs, {n_mutants} mutants, "
          f"{len(bad)} PASS")
    assert checked >= 150 and n_mutants >= 5000, (checked, n_mutants)
    assert not bad, f"{len(bad)} mutant(s) PASS:\n" + "\n".join(bad[:60])


def test_verdict_matches_the_cli():
    for path, pol in _corpus():
        _, out = cli_json(path, pol)
        assert verdict(_read(path), _policy(pol)) == (out["assertion_verdict"] or "NONE"), path


def cli_json(path: str, pol: str):
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.main([path, "--json", "--policy", os.path.join(_FX, "pol", pol)])
    return rc, json.loads(buf.getvalue())
