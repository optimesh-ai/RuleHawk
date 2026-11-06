"""Mutation self-check over every frontend (review of #42, round 6, N5).

Seeds: every config fixture under tests/fixtures/fail_closed (counterexamples,
controls, reviewer configs and variants r1-r5) and samples/, PASS seeds
included: adding a hidden line to a genuine PASS is where a false PASS comes
from.

Each mutant carries what the device makes of it:

- ``preserve``: the device reads it as the seed (a re-indented Cisco line, a
  rejected junk line, a bash comment). It may PASS only if the seed does.
- ``ref``: the device reads it as another config we can write down (a line a
  comment hides is a deleted line; ACL entries after a mode change are
  rejected). It may PASS only if that reference config does.
- ``never``: the device result is unknown or the config is invalid (a
  separator or control character, CRLF in a bash script, an upper-case Junos
  keyword, comment markers in a Junos string). It must never PASS.

Every mutant runs through `cli.main --json` and `gate.run_gate` (the Action's
engine); a fixed sample of 240 also runs through MCP `rulehawk_audit` and the
hosted page's own entry point. A PASS on any of them that the rule above
does not allow fails the test.
"""

from __future__ import annotations

import glob
import io
import json
import os
import random
import re
import sys
from collections import Counter, defaultdict
from contextlib import redirect_stdout
from typing import Dict, Iterator, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import cli  # noqa: E402
from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FX = os.path.join(_ROOT, "tests", "fixtures", "fail_closed")
_POL = os.path.join(_FX, "pol")

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


def _corpus() -> List[Tuple[str, str]]:
    out = []
    for f, p in sorted(_CX_POL.items()):
        out.append((os.path.join(_FX, "cfg", f), os.path.join(_POL, p)))
    for path in sorted(glob.glob(os.path.join(_FX, "cfg", "ok", "*"))):
        out.append((path, os.path.join(_POL, "v4_tcp445.json")))
    for d in ("rev42", "rev42r2", "rev42r3", "variants"):
        for path in sorted(glob.glob(os.path.join(_FX, d, "**", "*"), recursive=True)):
            if os.path.isfile(path):
                pol = "v4_reach_ip.json" if "reach" in os.path.basename(path) else "v4_ip.json"
                out.append((path, os.path.join(_POL, pol)))
    for path in sorted(glob.glob(os.path.join(_ROOT, "samples", "*"))):
        if not path.endswith("policy.json"):
            out.append((path, os.path.join(_ROOT, "samples", "policy.json")))
    return out


def _vendor(text: str) -> str:
    for name, det in (("junos", cli.detect_junos), ("panos", cli.detect_panos),
                      ("iptables", cli.detect_iptables), ("aws-sg", cli.detect_awssg),
                      ("nxos", cli.detect_nxos), ("eos", cli.detect_eos)):
        if det(text):
            return name
    return "ios-asa"


# --------------------------------------------------------------------------- #
# Mutation families
# --------------------------------------------------------------------------- #
_SEPS = [" ", " ", "\x85", "\x0c", "\x0b", "\x1c"]
_CISCO = ("ios-asa", "nxos", "eos")
_ACL_HDR = re.compile(r"(?i)^\s*(?:ip|ipv6) access-list\s")
_OG_HDR = re.compile(r"(?i)^\s*object-group\s")
_ENTRY = re.compile(r"(?i)^\s*(?:(?:sequence\s+)?\d+\s+)?(?:permit|deny|remark)\b")
_BREAKS = ["exit", " exit", "end", " hostname R1", "router ospf 1",
           " line vty 0 4", "interface Loopback0", " banner motd ^C x ^C",
           " ip routing", "control-plane"]
_NEUTRAL_BREAKS = {" hostname R1", "router ospf 1", " line vty 0 4",
                   "interface Loopback0", " banner motd ^C x ^C", " ip routing",
                   "control-plane"}
# Mode breaks written independently of the lexer (review of #42, round 7,
# R6-1): global commands that are on neither `_TOP_LEVEL` nor the interface
# allowlist, abbreviations of `exit` / `end` / `hostname`, and tab or Unicode
# indentation. On IOS a command the sub-mode lacks is run in global mode, so
# the ACL entries after it are rejected: the reference drops them.
_INDEPENDENT_BREAKS = [" ntp server 203.0.113.1", " ex", " exi", " EX", "\tex", " hostn R1",
                       "\tlogging host 203.0.113.9", " no ip domain-lookup",
                       " aaa new-model", " username u secret x", " service timestamps",
                       " ip ssh version 2", " en", "\u00a0ntp server 203.0.113.1",
                       "\u2003exit"]

Mutant = Tuple[str, str, str, str, Optional[str]]   # family, tag, text, kind, ref


def _j(ls: List[str]) -> str:
    return "\n".join(ls)


def _bodies(lines: List[str], hdr) -> List[Tuple[int, int]]:
    """(first body line, end) for every stanza opened by `hdr`. The body runs
    over indented, entry-like and `!` lines; this is the test's own reading,
    independent of rulehawk's lexer."""
    out = []
    for i, ln in enumerate(lines):
        if not hdr.match(ln):
            continue
        j = i + 1
        while j < len(lines) and lines[j].strip() and (
                lines[j][:1] in (" ", "\t") or _ENTRY.match(lines[j])
                or lines[j].lstrip().startswith("!")):
            j += 1
        if j > i + 1:
            out.append((i + 1, j))
    return out


def _cisco(lines: List[str]) -> Iterator[Mutant]:
    for i, ln in enumerate(lines):
        if ln[:1] in (" ", "\t"):
            yield ("cisco-dedent", f"{i + 1}", _j(lines[:i] + [ln.lstrip(" \t")] + lines[i + 1:]),
                   "preserve", None)
        yield ("cisco-junk-line", f"{i + 1}", _j(lines[:i] + ["xyzzy"] + lines[i:]),
               "preserve", None)
        yield ("cisco-nbsp-line", f"{i + 1}", _j(lines[:i] + [" "] + lines[i:]),
               "never", None)
        if "description" in ln:
            k = ln.index("description") + len("description ")
            for ch in ("\v", "\x85", "\x0c"):
                yield ("cisco-ctl-in-description", f"{i + 1}:{ord(ch):02x}",
                       _j(lines[:i] + [ln[:k] + "a" + ch + ln[k:]] + lines[i + 1:]),
                       "never", None)
        m = re.match(r"(?i)^(\s*interface\s+[A-Za-z-]+)(\d)", ln)
        if m:
            sp = re.sub(r"(?i)^(\s*interface\s+[A-Za-z-]+)(\d)", r"\1 \2", ln, count=1)
            yield ("cisco-ifname-space", f"{i + 1}", _j(lines[:i] + [sp] + lines[i + 1:]),
                   "preserve", None)
        words = ln.split(" ")
        lead = next((w for w, x in enumerate(words) if x), None)
        if lead is not None and words[lead].upper() != words[lead]:
            up = words[:lead] + [words[lead].upper()] + words[lead + 1:]
            yield ("cisco-keyword-case", f"{i + 1}", _j(lines[:i] + [" ".join(up)] + lines[i + 1:]),
                   "preserve", None)
        if i and ln.strip() and not ln.strip().startswith("!"):
            yield ("cisco-post-end", f"{i + 1}", _j(lines[:i] + ["end"] + lines[i:]),
                   "ref", _j(lines[:i]))
    for hdr, fam in ((_ACL_HDR, "cisco-acl-mode-break"), (_OG_HDR, "cisco-objgroup-mode-break")):
        for s, e in _bodies(lines, hdr):
            for i in range(s, e):
                if not lines[i].strip() or lines[i].lstrip().startswith("!"):
                    continue
                for b in _BREAKS:
                    mutant = _j(lines[:i] + [b] + lines[i:])
                    if b.strip() == "end":
                        ref = _j(lines[:i])
                    elif b in _NEUTRAL_BREAKS:
                        ref = _j(lines[:i] + [b] + lines[e:])
                    else:
                        ref = _j(lines[:i] + lines[e:])
                    yield (fam, f"{i + 1}:{b.strip()}", mutant, "ref", ref)
        for s, e in _bodies(lines, hdr):
            for i in range(s, e):
                if not lines[i].strip() or lines[i].lstrip().startswith("!"):
                    continue
                for b in _INDEPENDENT_BREAKS:
                    mutant = _j(lines[:i] + [b] + lines[i:])
                    if b[:1] not in (" ", "\t"):
                        kind, ref = "never", None        # a Unicode space
                    elif b.strip().lower() == "en":
                        kind, ref = "ref", _j(lines[:i])
                    else:
                        kind, ref = "ref", _j(lines[:i] + lines[e:])
                    yield (fam + "-unlisted", f"{i + 1}:{b.strip()}", mutant, kind, ref)
    # R6-2: `exit` after a one-line global command leaves configuration mode;
    # after the body of a mode RuleHawk does not model, it may.
    for i in range(1, len(lines)):
        if lines[i][:1] in (" ", "\t") or not lines[i].strip():
            continue
        yield ("cisco-global-exit", f"{i + 1}",
               _j(lines[:i] + ["hostname R9", "exit"] + lines[i:]), "ref",
               _j(lines[:i] + ["hostname R9"]))
        yield ("cisco-submode-body-exit", f"{i + 1}",
               _j(lines[:i] + ["router ospf 9", " ntp server 203.0.113.1", "exit"] + lines[i:]),
               "ref", _j(lines[:i] + ["router ospf 9"]))
    yield ("crlf", "", "\r\n".join(lines), "preserve", None)
    yield ("tabs", "", _j(re.sub(r"^ +", "\t", ln) for ln in lines), "preserve", None)


def _iptables(lines: List[str]) -> Iterator[Mutant]:
    save = any(ln.startswith("*") for ln in lines)
    for i, ln in enumerate(lines):
        s = ln.strip()
        yield ("ipt-comment-line", f"{i + 1}", _j(lines[:i] + ["# x"] + lines[i:]),
               "preserve", None)
        if not s or s.startswith("#"):
            continue
        dropped = _j(lines[:i] + lines[i + 1:])
        yield ("ipt-comment-out", f"{i + 1}", _j(lines[:i] + ["# " + ln] + lines[i + 1:]),
               "ref", dropped)
        # A trailing comment on a continued line (`... \\`) changes what the
        # continuation joins (round 7, R6-4): never.
        yield ("ipt-trailing-comment", f"{i + 1}", _j(lines[:i] + [ln + " # x"] + lines[i + 1:]),
               "never" if save or ln.rstrip().endswith("\\") else "preserve", None)
        yield ("ipt-glued-hash", f"{i + 1}", _j(lines[:i] + [ln + "#x"] + lines[i + 1:]),
               "never" if save else "ref", None if save else dropped)
        if i and lines[i - 1].strip() and not lines[i - 1].strip().startswith("#"):
            both = _j(lines[:i - 1] + lines[i + 1:])
            yield ("ipt-continuation", f"{i + 1}",
                   _j(lines[:i - 1] + [lines[i - 1] + " \\"] + lines[i:]),
                   "never" if save else "ref", None if save else both)
        if not save and re.match(r"^\s*ip6?tables\b", ln):
            up = re.sub(r"^(\s*)(ip6?tables)", lambda m: m.group(1) + m.group(2).upper(), ln)
            yield ("ipt-command-case", f"{i + 1}", _j(lines[:i] + [up] + lines[i + 1:]),
                   "ref", dropped)
    yield ("crlf", "", "\r\n".join(lines), "never", None)
    yield ("tabs", "", _j(ln.replace(" ", "\t") for ln in lines),
           "never" if save else "preserve", None)


def _panos(lines: List[str]) -> Iterator[Mutant]:
    for i, ln in enumerate(lines):
        yield ("panos-junk-line", f"{i + 1}", _j(lines[:i] + ["xyzzy"] + lines[i:]),
               "preserve", None)
        if ln.startswith("set "):
            yield ("panos-command-case", f"{i + 1}", _j(lines[:i] + ["SET" + ln[3:]] + lines[i + 1:]),
                   "never", None)
        m = re.match(r"^(set .*?\brules )([A-Za-z0-9_.-]+)( .*)?$", ln)
        if m:
            # R6-5: whether PAN-OS trims a quoted name is not known.
            for q in (f'"{m.group(2)} "', f'" {m.group(2)}"'):
                yield ("panos-quoted-name-space", f"{i + 1}:{q}",
                       _j(lines[:i] + [m.group(1) + q + (m.group(3) or "")] + lines[i + 1:]),
                       "never", None)
    yield ("crlf", "", "\r\n".join(lines), "never", None)


def _junos_comments(text: str) -> List[bool]:
    """Per character: inside a `#` or `/* */` comment (the test's own scan;
    quoted strings are skipped). A mutation inside a comment changes nothing
    on the device, so none is made there (round 7)."""
    out = [False] * (len(text) + 1)
    state, i = "code", 0
    while i < len(text):
        c, two = text[i], text[i:i + 2]
        if state == "code":
            if c == '"':
                state = "string"
            elif c == "#":
                state = "hash"
            elif two == "/*":
                state = "block"
                out[i] = out[i + 1] = True
                i += 2
                continue
        elif state == "string":
            if c == "\\":
                i += 1
            elif c == '"' or c == "\n":
                state = "code"
        elif state == "hash":
            if c == "\n":
                state = "code"
        elif state == "block" and two == "*/":
            out[i] = out[i + 1] = True
            state = "code"
            i += 2
            continue
        out[i] = state in ("hash", "block")
        i += 1
    out[len(text)] = state == "block"
    return out


def _junos(lines: List[str]) -> Iterator[Mutant]:
    text = _j(lines)
    cmt = _junos_comments(text)
    starts, heads, off = [], [], 0
    for ln in lines:
        heads.append(off)
        starts.append(off + len(ln) - len(ln.lstrip()))
        off += len(ln) + 1

    def in_comment(i: int) -> bool:
        # the first word of line i is inside a comment
        return cmt[min(starts[i], len(text))]

    def in_block(i: int) -> bool:
        # the newline before line i is inside a /* */ block
        return 0 < i < len(heads) and cmt[heads[i] - 1]
    terms = [m.end() for m in re.finditer(r"\bterm\s+\S+\s*\{", text) if not cmt[m.start()]]
    for k, pos in enumerate(terms):
        for d1, d2 in (('description "/*"; ', 'description "*/"; '),
                       ('description "#"; ', None), ('description "{"; ', None),
                       ('description "}"; ', None)):
            t = text[:pos] + " " + d1 + text[pos:]
            if d2 and k + 1 < len(terms):
                p2 = terms[k + 1] + len(d1) + 1
                t = t[:p2] + " " + d2 + t[p2:]
            yield ("junos-quoted-markers", f"term{k}:{d1.strip()}", t, "never", None)
        # R6-3: a `#` inside a word; the device reading is not known.
        t = text[:pos] + " description x#y; " + text[pos:]
        yield ("junos-hash-in-word", f"term{k}", t, "never", None)
    # R6-3: one brace too few or too many; the device does not load the file.
    closes = [m.start() for m in re.finditer(r"\}", text) if not cmt[m.start()]
              and text.count('"', text.rfind("\n", 0, m.start()) + 1, m.start()) % 2 == 0]
    for c in closes[:12] + closes[-3:]:
        yield ("junos-brace", f"drop:{c}", text[:c] + text[c + 1:], "never", None)
    yield ("junos-brace", "add", text.rstrip("\n") + " }\n", "never", None)
    for i, ln in enumerate(lines):
        if i + 2 < len(lines) and not in_block(i) and not in_block(i + 2):
            m = lines[:i] + ["# a /*"] + lines[i:i + 2] + ["# b */"] + lines[i + 2:]
            yield ("junos-hash-block", f"{i + 1}", _j(m), "never", None)
        # Junos comments do not nest (R6-4): no annotation inside a block.
        if not in_block(i):
            yield ("junos-annotation", f"{i + 1}", _j(lines[:i] + ["/* x */"] + lines[i:]),
                   "preserve", None)
        words = ln.split(" ")
        lead = next((w for w, x in enumerate(words) if x and x[0].isalpha()), None)
        if lead is not None and words[lead].upper() != words[lead] and not in_comment(i):
            up = words[:lead] + [words[lead].upper()] + words[lead + 1:]
            yield ("junos-keyword-case", f"{i + 1}", _j(lines[:i] + [" ".join(up)] + lines[i + 1:]),
                   "never", None)
    yield ("crlf", "", "\r\n".join(lines), "never", None)
    yield ("tabs", "", _j(re.sub(r"^ +", "\t", ln) for ln in lines), "preserve", None)


def _aws(lines: List[str]) -> Iterator[Mutant]:
    text = _j(lines)
    for k, m in enumerate(re.finditer(r'":\s*"', text)):
        ch = _SEPS[k % len(_SEPS)]
        yield ("aws-char-in-string", f"{k}:{ord(ch):x}", text[:m.end()] + ch + text[m.end():],
               "never", None)
    yield ("crlf", "", "\r\n".join(lines), "preserve", None)
    yield ("tabs", "", _j(re.sub(r"^ +", "\t", ln) for ln in lines), "preserve", None)


def _separators(lines: List[str]) -> Iterator[Mutant]:
    """Every frontend: a separator joining two lines, or inside a line."""
    for i, ln in enumerate(lines):
        if i:
            ch = _SEPS[i % len(_SEPS)]
            yield ("sep-joins-lines", f"{i + 1}:{ord(ch):x}",
                   _j(lines[:i - 1] + [lines[i - 1] + ch + ln] + lines[i + 1:]), "never", None)
        if len(ln.strip()) > 2:
            ch = _SEPS[(i + 3) % len(_SEPS)]
            k = len(ln) // 2
            yield ("sep-inside-line", f"{i + 1}:{ord(ch):x}",
                   _j(lines[:i] + [ln[:k] + ch + ln[k:]] + lines[i + 1:]), "never", None)


def mutants(text: str, vendor: str) -> Iterator[Mutant]:
    lines = text.split("\n")
    fam = (_cisco if vendor in _CISCO else _iptables if vendor == "iptables" else
           _panos if vendor == "panos" else _junos if vendor == "junos" else
           _aws if vendor == "aws-sg" else None)
    if fam:
        yield from fam(lines)
    yield from _separators(lines)


# --------------------------------------------------------------------------- #
# Running the surfaces
# --------------------------------------------------------------------------- #
class _Runner:
    def __init__(self, tmpdir: str):
        self.tmp = tmpdir
        self.n = 0
        self.cache: Dict[Tuple[str, str], Tuple[str, str]] = {}
        self.policies: Dict[str, dict] = {}

    def path_for(self, text: str, ext: str) -> str:
        self.n += 1
        p = os.path.join(self.tmp, f"m{self.n}{ext}")
        with open(p, "wb") as fh:
            fh.write(text.encode("utf-8"))
        return p

    def cli_and_gate(self, text: str, pol: str, ext: str) -> Tuple[str, str]:
        key = (text, pol)
        if key not in self.cache:
            p = self.path_for(text, ext)
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.main([p, "--json", "--policy", pol])
            v_cli = json.loads(buf.getvalue())["assertion_verdict"] or "NONE"
            if pol not in self.policies:
                with open(pol, encoding="utf-8") as fh:
                    self.policies[pol] = json.load(fh)
            v_gate = g.run_gate([p], self.policies[pol]).verdict
            self.cache[key] = (v_cli, v_gate)
            os.unlink(p)
        return self.cache[key]


def _allowed(kind: str, seed_pass: bool, ref_pass: Optional[bool]) -> bool:
    return (kind == "preserve" and seed_pass) or (kind == "ref" and bool(ref_pass))


def _run(tmpdir: str):
    run = _Runner(tmpdir)
    stats: Dict[str, Counter] = defaultdict(Counter)
    bad: List[str] = []
    sample_pool = []
    seeds = Counter()
    for path, pol in _corpus():
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        ext = os.path.splitext(path)[1] or ".txt"
        vendor = _vendor(text)
        base = run.cli_and_gate(text, pol, ext)
        seed_pass = "PASS" in base
        seeds["PASS" if seed_pass else "other"] += 1
        for fam, tag, mutant, kind, ref in mutants(text, vendor):
            st = stats[fam]
            st["mutants"] += 1
            v = run.cli_and_gate(mutant, pol, ext)
            ref_pass = None
            if kind == "ref":
                ref_pass = "PASS" in run.cli_and_gate(ref, pol, ext)
            if "PASS" in v:
                st["pass"] += 1
                if not _allowed(kind, seed_pass, ref_pass):
                    st["violations"] += 1
                    bad.append(f"{os.path.relpath(path, _ROOT)} [{fam} {tag} {kind}] "
                               f"cli/gate={v} seed={base} ref_pass={ref_pass}")
            if "\r" not in mutant:
                sample_pool.append((path, pol, ext, fam, tag, mutant, kind, seed_pass, ref_pass))
    return run, stats, bad, sample_pool, seeds


def _table(stats, seeds) -> str:
    rows = [f"seeds: {sum(seeds.values())} ({seeds['PASS']} PASS)",
            f"{'family':28s} {'mutants':>8s} {'PASS':>6s} {'bad':>5s}"]
    for fam in sorted(stats):
        s = stats[fam]
        rows.append(f"{fam:28s} {s['mutants']:8d} {s['pass']:6d} {s['violations']:5d}")
    tot = Counter()
    for s in stats.values():
        tot.update(s)
    rows.append(f"{'total':28s} {tot['mutants']:8d} {tot['pass']:6d} {tot['violations']:5d}")
    return "\n".join(rows)


_RESULT = {}


def _result(tmp_path_factory):
    if not _RESULT:
        _RESULT["r"] = _run(str(tmp_path_factory.mktemp("mut")))
    return _RESULT["r"]


def test_no_mutant_passes_where_the_device_would_not(tmp_path_factory):
    run, stats, bad, _, seeds = _result(tmp_path_factory)
    table = _table(stats, seeds)
    print("\n" + table)
    out = os.environ.get("RULEHAWK_MUTATION_REPORT")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(table + "\n" + "\n".join(bad) + "\n")
    total = sum(s["mutants"] for s in stats.values())
    assert seeds["PASS"] >= 60 and total >= 20000, (dict(seeds), total)
    for fam in ("cisco-acl-mode-break", "cisco-acl-mode-break-unlisted",
                "cisco-global-exit", "cisco-submode-body-exit", "junos-brace",
                "junos-hash-in-word", "panos-quoted-name-space",
                "cisco-post-end", "ipt-comment-out",
                "ipt-continuation", "panos-command-case", "junos-quoted-markers",
                "junos-hash-block", "aws-char-in-string", "sep-joins-lines"):
        assert stats[fam]["mutants"] > 0, fam
    assert not bad, f"{len(bad)} mutant(s) PASS where the device would not:\n" + \
        "\n".join(bad[:80]) + "\n" + table


def test_a_sample_on_mcp_and_the_hosted_page(tmp_path_factory):
    """240 mutants, a fixed sample, through MCP rulehawk_audit and the hosted
    entry point. Mutants holding a CR are left out: the hosted page reads a
    browser textarea, which has none."""
    from rulehawk import mcp_server as m
    from tests.test_hosted_parity import _WORKER, _analyze_py, _read, _run_hosted
    run, _, _, pool, _ = _result(tmp_path_factory)
    analyze = _analyze_py(_read(_WORKER))
    sample = random.Random(20261106).sample(pool, min(240, len(pool)))
    assert len(sample) >= 200
    bad = []
    for path, pol, ext, fam, tag, mutant, kind, seed_pass, ref_pass in sample:
        p = run.path_for(mutant, ext)
        v_mcp = m.audit(p, pol)["verdict"]
        with open(pol, encoding="utf-8") as fh:
            env = _run_hosted(analyze, mutant, fh.read())
        v_host = env["report_json"]["assertion_verdict"]
        os.unlink(p)
        if "PASS" in (v_mcp, v_host) and not _allowed(kind, seed_pass, ref_pass):
            bad.append(f"{os.path.relpath(path, _ROOT)} [{fam} {tag}] mcp={v_mcp} hosted={v_host}")
    assert not bad, "\n".join(bad)
