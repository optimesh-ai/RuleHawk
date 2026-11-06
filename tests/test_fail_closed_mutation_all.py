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
from test_fail_closed_review10 import _T_MARK  # noqa: E402

try:
    from rulehawk.failclosed import collect_ledgers  # noqa: E402
except ImportError:                      # before round 8: no ledger
    collect_ledgers = None

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
                base = os.path.basename(path)
                pol = "v4_reach_ip.json" if "reach" in base else "v4_ip.json"
                if os.sep + "r7" + os.sep in path or os.sep + "r8" + os.sep in path:
                    # the reviewer's round-8 and round-9 drivers
                    pol = ("v6_ip.json" if base.startswith("v6") else
                           "v4_tcp445.json" if "tcp445" in base else pol)
                if os.sep + "r9" + os.sep in path:
                    # the reviewer's round-10 driver (rev42-r9/pol.sh)
                    m = re.search(r"_(reach)?(tcp|udp)(\d+)", base)
                    pol = (("must_reach" if m.group(1) else "must_not_reach")
                           + f"_{m.group(2)}{m.group(3)}.json" if m else
                           "v6_ip.json" if base.startswith("v6") else pol)
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
_INDEPENDENT_BREAKS = [" ntp server 203.0.113.1", " hostn R1",
                       "\tlogging host 203.0.113.9", " no ip domain-lookup",
                       " aaa new-model", " username u secret x", " service timestamps",
                       " ip ssh version 2", "\u00a0ntp server 203.0.113.1",
                       " ip name-server 203.0.113.53", " clock timezone UTC 0",
                       " ip domain name example.net"]
# Abbreviations of `exit` / `end`: they are on the lexer's own `_EXIT_END`
# list, so they are a known-breaks family of their own, not independent ones
# (round 8, R7-8).
_ABBREV_BREAKS = [" ex", " exi", " EX", "\tex", " en", "\u2003exit"]

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


def _cisco(lines: List[str], vendor: str = "ios-asa") -> Iterator[Mutant]:
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
                for sfx, brks in (("-unlisted", _INDEPENDENT_BREAKS),
                                  ("-abbrev", _ABBREV_BREAKS)):
                    for b in brks:
                        mutant = _j(lines[:i] + [b] + lines[i:])
                        if b[:1] not in (" ", "\t"):
                            kind, ref = "never", None        # a Unicode space
                        elif b.strip().lower() == "en":
                            kind, ref = "ref", _j(lines[:i])
                        else:
                            kind, ref = "ref", _j(lines[:i] + lines[e:])
                        yield (fam + sfx, f"{i + 1}:{b.strip()}", mutant, kind, ref)
    yield from _cisco_acl_meaning(lines)
    yield from _cisco_grammar(lines, vendor)
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


_NUM = re.compile(r"^\s*(sequence\s+)?(\d+)\s")
_PD = re.compile(r"(?i)\b(?:permit|deny)\b")


# Trailing tokens (round 9, R8-8): real keywords from other vendors and
# contexts, not only a word no grammar accepts. A word the entry grammar does
# not have is rejected (`% Invalid input`): ref = the line dropped. A cited
# qualifier that narrows the match (`fragments`, `established` on a non-TCP
# entry is rejected, on TCP narrows) has no reference config: never.
_TRAILING = [("xyzzy", "ref"), ("accept", "ref"), ("count", "ref"), ("interval", "ref"),
             ("then", "ref"), ("-j", "ref"), ("any4", "ref"), ("fragments", "never"),
             ("established", "never")]
# The largest sequence number the device takes, per dialect (round 9, R8-2):
# IOS XE 17 IPv4 2147483647; IOS IPv6 and NX-OS 4294967295. EOS is not cited.
_SEQ_MAX = {("ios-asa", False): 2147483647, ("ios-asa", True): 4294967295,
            ("nxos", False): 4294967295, ("nxos", True): 4294967295,
            ("eos", False): 4294967295, ("eos", True): 4294967295}
_WC = re.compile(r"\b(\d+\.\d+\.\d+\.\d+) (0\.\d+\.\d+\.\d+)\b")


def _cisco_grammar(lines: List[str], vendor: str) -> Iterator[Mutant]:
    """Forms the ACL grammar of another dialect, or of no dialect, accepts
    with a meaning the seed does not have (round 9, R8-8). Each one is
    `never`: the device rejects the line or reads it differently, and the
    answer must not rest on it.

    - an entry numbered 0 or one past the dialect's maximum;
    - a `resequence` line naming the ACL;
    - on IOS IPv4: a prefix operand (`A/len`) for a wildcard pair, and ASA
      `log` arguments (`log 5`, `log interval 5`, `log disable`);
    - on NX-OS and EOS: an upper-case keyword (IOS: preserve, cited)."""
    for s, e in _bodies(lines, _ACL_HDR):
        hdr = lines[s - 1]
        v6 = "ipv6" in hdr.lower()
        name = hdr.split()[-1]
        ents = [i for i in range(s, e) if _ENTRY.match(lines[i]) and _PD.search(lines[i])]
        if not ents:
            continue
        ind = re.match(r"^[ \t]*", lines[ents[0]]).group(0) or " "
        top = _SEQ_MAX[(vendor, v6)]
        for i in ents:
            ln = lines[i]
            mm = _NUM.match(ln)
            body = ln[mm.end():] if mm else ln.lstrip()
            remark = body.split()[:1] and body.split()[0].lower() == "remark"
            kw = "sequence " if (vendor == "ios-asa" and v6) else ""
            for n in ("0", str(top + 1)):
                yield ("cisco-acl-seq-range", f"{i + 1}:{n}",
                       _j(lines[:i] + [ind + kw + n + " " + body] + lines[i + 1:]),
                       "never", None)
            low = body.split()
            if low and low[0].lower() in ("permit", "deny"):
                up = ind + (mm.group(0).strip() + " " if mm else "") + low[0].upper() + \
                    body[len(low[0]):]
                yield ("cisco-acl-keyword-case", f"{i + 1}",
                       _j(lines[:i] + [up] + lines[i + 1:]),
                       "preserve" if vendor == "ios-asa" else "never", None)
            if vendor == "ios-asa" and not v6 and not remark:   # a remark is free text
                w = _WC.search(ln)
                if w:
                    plen = 32 - sum(bin(int(o)).count("1") for o in w.group(2).split("."))
                    yield ("cisco-acl-cidr-operand", f"{i + 1}",
                           _j(lines[:i] + [ln[:w.start()] + f"{w.group(1)}/{plen}"
                                           + ln[w.end():]] + lines[i + 1:]), "never", None)
                if "log" not in ln.lower().split():
                    for a in ("log 5", "log interval 5", "log disable"):
                        yield ("cisco-acl-log-args", f"{i + 1}:{a}",
                               _j(lines[:i] + [ln.rstrip() + " " + a] + lines[i + 1:]),
                               "never", None)
        fam = "ipv6" if v6 else "ip"
        for rs in (f"resequence {fam} access-list {name} 100 10",
                   f"{fam} access-list resequence {name} 100 10"):
            yield ("cisco-acl-resequence", rs.split()[0],
                   _j(lines[:e] + ["hostname R1", rs] + lines[e:]), "never", None)
        yield ("cisco-acl-resequence", "in-acl",
               _j(lines[:e] + [ind + "resequence 100 10"] + lines[e:]), "never", None)


def _cisco_acl_meaning(lines: List[str]) -> Iterator[Mutant]:
    """Lines the ACL grammar admits whose meaning must be modelled (round 8,
    R7-8): a deletion, a `default` line, a numbered entry among unnumbered
    ones, a trailing token. The test's own reading of the device:

    - `no N` deletes entry N of a fully numbered body (IOS XE 17 "IP Access
      List Entry Sequence Numbering": "Use the no sequence-number command to
      delete an entry."): ref = the body without it.
    - `default N`, `default sequence N`, `no sequence N`, `default remark`:
      what the device does is not cited here: never.
    - `1 permit ... any any` at the end of an unnumbered body runs first on
      the device ("the first entry is assigned a sequence number of 10, and
      successive entries are incremented by 10"): ref = the permit first.
    - an entry with an unknown trailing word is rejected (`% Invalid input`):
      ref = the line dropped."""
    for s, e in _bodies(lines, _ACL_HDR):
        body = [(i, lines[i]) for i in range(s, e)
                if lines[i].strip() and not lines[i].lstrip().startswith("!")]
        ents = [(i, ln) for i, ln in body if _ENTRY.match(ln) and _PD.search(ln)]
        if not ents:
            continue
        ind = re.match(r"^[ \t]*", ents[0][1]).group(0) or " "
        nums = [_NUM.match(ln) for _, ln in body]
        v6 = "ipv6" in lines[s - 1].lower()
        ins = lambda extra: _j(lines[:e] + [ind + extra] + lines[e:])  # noqa: E731
        for i, ln in ents:
            mm = _NUM.match(ln)
            if mm and all(nums):
                n = mm.group(2)
                yield ("cisco-acl-entry-delete", f"{i + 1}:no {n}", ins("no " + n), "ref",
                       _j(lines[:i] + lines[i + 1:]))
                yield ("cisco-acl-entry-delete", f"{i + 1}:no sequence {n}",
                       ins("no sequence " + n), "never", None)
                yield ("cisco-acl-default", f"{i + 1}:default {n}", ins("default " + n),
                       "never", None)
                yield ("cisco-acl-default", f"{i + 1}:default sequence {n}",
                       ins("default sequence " + n), "never", None)
            remark = bool(re.match(r"(?i)^\s*(?:(?:sequence\s+)?\d+\s+)?remark\b", ln))
            for tok, kind in _TRAILING if "log" not in ln.lower().split() else _TRAILING[:1]:
                if remark and kind == "never":
                    kind = "preserve"            # free text: a remark stays a remark
                yield ("cisco-acl-trailing-token", f"{i + 1}:{tok}",
                       _j(lines[:i] + [ln.rstrip() + " " + tok] + lines[i + 1:]), kind,
                       _j(lines[:i] + lines[i + 1:]) if kind == "ref" else None)
        yield ("cisco-acl-default", f"{s + 1}:default remark", ins("default remark"),
               "never", None)
        if not any(nums):
            anyany = "permit ipv6 any any" if v6 else "permit ip any any"
            yield ("cisco-acl-seq-mix", f"{s + 1}", ins("1 " + anyany), "ref",
                   _j(lines[:s] + [ind + anyany] + lines[s:]))


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
    # Round 9 (R8-3, R8-4, R8-8): iptables-restore commits only on the exact
    # line `COMMIT` (iptables-restore.c: `strcmp(buffer, "COMMIT\n")`), and
    # iptables rejects a command with arguments left over (xtables.c:
    # "unknown arguments found on commandline"). Both: never.
    for i, ln in enumerate(lines):
        if ln == "COMMIT":
            for c in ("commit", "COMMIT ", "Commit", " COMMIT"):
                yield ("ipt-commit-spelling", f"{i + 1}:{c!r}",
                       _j(lines[:i] + [c] + lines[i + 1:]), "never", None)
        if re.match(r"^\s*(?:ip6?tables\s+)?-(?:P|N|F|X)\s+\S+", ln):
            for extra in (" extra", " INPUT", " -w"):
                yield ("ipt-policy-extra-arg", f"{i + 1}:{extra.strip()}",
                       _j(lines[:i] + [ln.rstrip() + extra] + lines[i + 1:]), "never", None)
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
        # Round 9 (R8-9): an address object with a token past its value is
        # rejected by PAN-OS: never.
        if re.match(r"^set (?:.* )?address \S+ (?:ip-netmask|ip-range) \S+$", ln):
            yield ("panos-object-extra-token", f"{i + 1}",
                   _j(lines[:i] + [ln + " extra"] + lines[i + 1:]), "never", None)
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
    # Only from a balanced seed: on an unbalanced one the edit can restore
    # the balance.
    def live(ch: str) -> List[int]:
        return [m.start() for m in re.finditer(re.escape(ch), text) if not cmt[m.start()]
                and text.count('"', text.rfind("\n", 0, m.start()) + 1, m.start()) % 2 == 0]
    closes = live("}")
    if len(closes) == len(live("{")):
        for c in closes[:12] + closes[-3:]:
            yield ("junos-brace", f"drop:{c}", text[:c] + text[c + 1:], "never", None)
        yield ("junos-brace", "add", text.rstrip("\n") + " }\n", "never", None)
    for i, ln in enumerate(lines):
        if i + 2 < len(lines) and not in_block(i) and not in_block(i + 2):
            m = lines[:i] + ["# a /*"] + lines[i:i + 2] + ["# b */"] + lines[i + 2:]
            yield ("junos-hash-block", f"{i + 1}", _j(m), "never", None)
        # Junos comments do not nest (R6-4): inside a block, the annotation's
        # `*/` ends the block early, so the rest of it is read as statements
        # (round 8: restored, labelled never).
        yield ("junos-annotation", f"{i + 1}", _j(lines[:i] + ["/* x */"] + lines[i:]),
               "never" if in_block(i) else "preserve", None)
        words = ln.split(" ")
        lead = next((w for w, x in enumerate(words) if x and x[0].isalpha()), None)
        if lead is not None and words[lead].upper() != words[lead]:
            up = words[:lead] + [words[lead].upper()] + words[lead + 1:]
            # A word inside a comment changes nothing on the device (round 8:
            # restored, labelled preserve); anywhere else the upper-case
            # keyword is rejected.
            at = heads[i] + len(" ".join(words[:lead])) + (1 if lead else 0)
            yield ("junos-keyword-case", f"{i + 1}", _j(lines[:i] + [" ".join(up)] + lines[i + 1:]),
                   "preserve" if cmt[min(at, len(text))] else "never", None)
    # Round 9 (R8-1, R8-10, R8-8): a second terminating action after the
    # first (Juniper: "the latest terminating action will replace the
    # existing terminating action"), a term name used twice in one filter
    # (Juniper: "You must specify a unique name for each term"), and a
    # statement the term grammar does not have. All never.
    opp = {"accept": "discard", "discard": "accept", "reject": "accept"}
    for k, m in enumerate(re.finditer(r"\bthen\s+(accept|discard|reject)\s*;", text)):
        if cmt[m.start()]:
            continue
        t = text[:m.end()] + f" then {opp[m.group(1)]};" + text[m.end():]
        yield ("junos-two-terminating", f"{k}", t, "never", None)
    for k, m in enumerate(re.finditer(r"\bterm\s+(\S+)\s*\{", text)):
        if cmt[m.start()]:
            continue
        t = text[:m.end()] + " bogus-stmt;" + text[m.end():]
        yield ("junos-term-unknown-stmt", f"{k}", t, "never", None)
        t = text[:m.start()] + f"term {m.group(1)} {{ then accept; }} " + text[m.start():]
        yield ("junos-duplicate-term", f"{k}", t, "never", None)
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


# --------------------------------------------------------------------------- #
# Round 10 families (review-rh42-r9.md). None comes from rulehawk's grammars:
# the labels come from the other dialect's cited grammar, or from "the file
# no longer says which device reads it".
# --------------------------------------------------------------------------- #
# Lines that say which Cisco dialect wrote the file (the test's own list, the
# citations are in test_fail_closed_review10.py).
_MARKER_LINE = re.compile(
    r"(?i)^\s*(?:!\s*command:|!\s*device:|!\s*time:|!\s*running configuration|"
    r"building configuration|current configuration\s*:|version\s|"
    r"boot-start-marker|boot-end-marker|boot system|asa version|pix version|"
    r":\s*saved|:\s*hardware|feature\s|vlan configuration\b|"
    r"management api http-commands)")
_TYPED_HDR = re.compile(r"(?im)^(\s*ip access-list) (?:extended|standard) ")
_UNTYPED_HDR = re.compile(r"(?m)^ip access-list (?!extended\b|standard\b|resequence\b|"
                          r"logging\b|persistent\b|role-based\b|helper\b)\S+\s*$")
_FLAT_OR_SHOW = re.compile(r"(?im)^(?:access-list\s|(?:ip|ipv6) access list\s)")
_BANNER_IOS = "Building configuration...\n\nCurrent configuration : 900 bytes\n!\nversion 15.2\n!"
_BANNER_EOS = "! Command: show running-config\n! device: r1 (vEOS, EOS-4.30.0F)\n!"
_BANNER_NX = ("!Command: show running-config\n\nversion 9.3(10) Bios:version 05.45\n"
              "feature interface-vlan")


def _strip_markers(lines: List[str]) -> List[str]:
    return [_TYPED_HDR.sub(r"\1 ", ln) for ln in lines if not _MARKER_LINE.match(ln)]


def _cisco_dialect(lines: List[str], vendor: str) -> Iterator[Mutant]:
    """R9-1, R9-3. A PASS needs the dialect to be positively identified."""
    text = _j(lines)
    if not _FLAT_OR_SHOW.search(text):
        # Banners, version, feature and boot lines removed and headers
        # untyped: no line says which device reads the file. Never.
        stripped = _strip_markers(lines)
        if stripped != lines:
            yield ("cisco-marker-strip", vendor, _j(stripped), "never", None)
    if vendor == "ios-asa":
        # IOS: `ip access-list {standard | extended} NAME` (Catalyst 9400
        # IOS XE 16.10 command reference); a bound named ACL that does not
        # exist passes every packet (IOS XE 16.11 ACL guide). An untyped
        # header in an IOS file: never.
        for i, ln in enumerate(lines):
            if _TYPED_HDR.match(ln):
                yield ("cisco-untyped-header", f"{i + 1}",
                       _j(lines[:i] + [_TYPED_HDR.sub(r"\1 ", ln)] + lines[i + 1:]), "never", None)
        if _TYPED_HDR.search(text) or re.search(r"(?m)^access-list\s", text):
            # An IOS body under an EOS banner (EOS grammar: not cited) or an
            # NX-OS banner (NX-OS: `ip access-list access-list-name`, no
            # type, no numbered lists). Never.
            yield ("cisco-dialect-transplant", "ios-body+eos-banner",
                   _BANNER_EOS + "\n" + text, "never", None)
            yield ("cisco-dialect-transplant", "ios-body+nxos-banner",
                   _BANNER_NX + "\n" + text, "never", None)
    elif _UNTYPED_HDR.search(text) and not _FLAT_OR_SHOW.search(text):
        # An NX-OS / EOS body, its markers gone, under an IOS banner: the
        # untyped header is not in the IOS grammar. Never.
        yield ("cisco-dialect-transplant", f"{vendor}-body+ios-banner",
               _BANNER_IOS + "\n" + _j(_strip_markers(lines)), "never", None)


_PA_RULE = re.compile(r'^(set (?:.*? )?rules (?:"[^"]*"|\S+))(?: (.*))?$')
_PA_OPP = {"allow": "deny", "deny": "allow", "drop": "allow", "reset-client": "allow",
           "reset-server": "allow", "reset-both": "allow", "yes": "no", "no": "yes"}


def _panos_leaf(lines: List[str]) -> Iterator[Mutant]:
    """R9-2, R9-5. A field that holds one value, set a second time with a
    different value, and `any` with a member added. The replace / merge
    semantics are not cited: never."""
    text = _j(lines)
    svcs = re.findall(r"(?m)^set (?:.*? )?service (\S+) protocol ", text)

    def after(i: int, extra: str) -> str:
        return _j(lines[:i + 1] + [extra] + lines[i + 1:])

    for i, ln in enumerate(lines):
        m = re.match(r"^(set (?:.*? )?service \S+ protocol )(tcp|udp)( .*)$", ln)
        if m:
            other = "udp" if m.group(2) == "tcp" else "tcp"
            yield ("panos-leaf-dup", f"{i + 1}:protocol",
                   after(i, m.group(1) + other + m.group(3)), "never", None)
            for leaf in ("port", "source-port"):
                pm = re.search(rf"\b{leaf} (\S+)", m.group(3))
                if pm:
                    new = "1" if pm.group(1) != "1" else "2"
                    yield ("panos-leaf-dup", f"{i + 1}:{leaf}",
                           after(i, f"{m.group(1)}{m.group(2)} {leaf} {new}"), "never", None)
        m = re.match(r"^(set (?:.*? )?address \S+) (ip-netmask|ip-range|fqdn) (\S+)$", ln)
        if m:
            new = "203.0.113.0/24" if m.group(3) != "203.0.113.0/24" else "203.0.113.128/25"
            yield ("panos-leaf-dup", f"{i + 1}:address",
                   after(i, f"{m.group(1)} ip-netmask {new}"), "never", None)
        m = _PA_RULE.match(ln)
        if m and m.group(2):
            rest = " " + m.group(2)
            for leaf in ("action", "disabled", "negate-source", "negate-destination"):
                lm = re.search(rf" {leaf} (\S+)", rest)
                if lm and lm.group(1) in _PA_OPP:
                    yield ("panos-leaf-dup", f"{i + 1}:{leaf}",
                           after(i, f"{m.group(1)} {leaf} {_PA_OPP[lm.group(1)]}"), "never", None)
            for leaf in ("source", "destination"):
                if re.search(rf" {leaf} any\b", rest):
                    yield ("panos-any-plus-member", f"{i + 1}:{leaf}",
                           after(i, f"{m.group(1)} {leaf} 203.0.113.0/24"), "never", None)
                    yield ("panos-any-plus-member", f"{i + 1}:{leaf}-bracket",
                           _j(lines[:i] + [m.group(1) + re.sub(
                               rf" {leaf} any\b", f" {leaf} [ any 203.0.113.0/24 ]", rest, count=1)]
                              + lines[i + 1:]), "never", None)
            if re.search(r" service any\b", rest) and svcs:
                yield ("panos-any-plus-member", f"{i + 1}:service",
                       after(i, f"{m.group(1)} service {svcs[0]}"), "never", None)


def _junos_leaf(lines: List[str]) -> Iterator[Mutant]:
    """R9-2 for Junos. Juniper, "filter (Applying to a Logical Interface)":
    `input filter-name`, "Name of one filter to evaluate when packets are
    received on the interface". A second `input` / `output` on the same
    unit and family, naming another filter: never."""
    text = _j(lines)
    cmt = _junos_comments(text)
    extra = "ZZOPEN"
    d = next((m for m in re.finditer(r"(?m)^([ \t]*)filter\s+[A-Za-z0-9_.-]+\s*\{", text)
              if not cmt[m.start(0) + len(m.group(1))]), None)
    if d is not None:
        ins = d.start(0)
        # The added filter permits nothing, so on its own it never turns the
        # answer: the second `input` / `output` naming it is the change.
        t2 = text[:ins] + f"{d.group(1)}filter {extra} {{ term t {{ then discard; }} }}\n" + text[ins:]
        cmt2 = _junos_comments(t2)
        for k, m in enumerate(re.finditer(r"\b(input|output)\s+[^;\s{}]+\s*;", t2)):
            if cmt2[m.start()] or not re.search(r"filter\s*\{[^{}]*$", t2[:m.start()]):
                continue
            t = t2[:m.end()] + f" {m.group(1)} {extra};" + t2[m.end():]
            yield ("junos-leaf-dup", f"brace{k}", t, "never", None)
    for i, ln in enumerate(lines):
        m = re.match(r"^(set (?:.* )?interfaces \S+ unit \S+ family (\S+) filter (input|output)) "
                     r"(\S+)\s*$", ln)
        if m:
            t = _j(lines[:i + 1] + [f"{m.group(1)} {extra}"] + lines[i + 1:]
                   + [f"set firewall family {m.group(2)} filter {extra} term t then discard"])
            yield ("junos-leaf-dup", f"set{i + 1}", t, "never", None)


_IPT_OPT = [("-s", "203.0.113.0/24"), ("-d", "203.0.113.0/24"), ("-i", "zz9"),
            ("-o", "zz9"), ("-p", None), ("--dport", "1"), ("--sport", "1"), ("-j", None)]


def _iptables_leaf(lines: List[str]) -> Iterator[Mutant]:
    """One rule option given twice. xshared.c set_option: "multiple -%c
    flags not allowed"; a match option marked XTF_ONLY_ONCE: "Only one of
    --dport allowed" (libxtables). The command is rejected: never."""
    for i, ln in enumerate(lines):
        if not re.match(r"^\s*(?:ip6?tables\s+)?-[AI]\s+\S+", ln):
            continue
        for opt, val in _IPT_OPT:
            m = re.search(rf"(?<!\S){re.escape(opt)} (\S+)", ln)
            if not m:
                continue
            v = val
            if opt == "-p":
                v = "udp" if m.group(1) != "udp" else "tcp"
            elif opt == "-j":
                v = "DROP" if m.group(1) == "ACCEPT" else "ACCEPT"
            elif v == m.group(1):
                v = "2"
            new = ln[:m.end()] + f" {opt} {v}" + ln[m.end():]
            yield ("ipt-option-dup", f"{i + 1}:{opt}", _j(lines[:i] + [new] + lines[i + 1:]),
                   "never", None)


def mutants(text: str, vendor: str) -> Iterator[Mutant]:
    lines = text.split("\n")
    if vendor in _CISCO:
        yield from _cisco(lines, vendor)
        yield from _cisco_dialect(lines, vendor)
    fam = (_iptables if vendor == "iptables" else
           _panos if vendor == "panos" else _junos if vendor == "junos" else
           _aws if vendor == "aws-sg" else None)
    if fam:
        yield from fam(lines)
    leaf = (_iptables_leaf if vendor == "iptables" else _panos_leaf if vendor == "panos"
            else _junos_leaf if vendor == "junos" else None)
    if leaf:
        yield from leaf(lines)
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
        self.ledger: Counter = Counter()
        self.ledger_bad: List[str] = []
        self.marker_bad: List[str] = []

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
            if collect_ledgers is None:
                with redirect_stdout(buf):
                    cli.main([p, "--json", "--policy", pol])
                leds = []
            else:
                with collect_ledgers() as leds, redirect_stdout(buf):
                    cli.main([p, "--json", "--policy", pol])
            rep = json.loads(buf.getvalue())
            v_cli = rep["assertion_verdict"] or "NONE"
            # Round 10 (R9-1, R9-3): a Cisco PASS rests on a marker the
            # dialect writes, by the test's own cited list.
            if v_cli == "PASS" and rep.get("vendor") in _T_MARK and \
                    not _T_MARK[rep["vendor"]].search(text):
                self.marker_bad.append(f"m{self.n} {rep['vendor']}: PASS with no dialect marker")
            # The line-accounting invariant on every mutant (round 8): every
            # ledger closed, nothing unaccounted, a noted line means no PASS.
            self.ledger["configs"] += 1
            flagged = False
            for led in leds:
                c = led.counts()
                self.ledger.update(c)
                flagged |= bool(c["noted"] or c["caught"])
                if not led.closed or c["unaccounted"]:
                    self.ledger_bad.append(f"m{self.n} {led.frontend} {c}")
            if flagged and v_cli == "PASS":
                self.ledger_bad.append(f"m{self.n}: noted line but PASS")
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
    led = dict(run.ledger)
    print("ledger:", led)
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("ledger: " + json.dumps(led) + "\n")
    assert collect_ledgers is not None, "no line-accounting ledger (round 8)"
    assert not run.ledger_bad, "\n".join(run.ledger_bad[:40])
    assert led.get("unaccounted", 0) == 0 and led.get("scope", 0) > 0, led
    assert not run.marker_bad, "\n".join(run.marker_bad[:40])
    for fam in ("cisco-acl-entry-delete", "cisco-acl-seq-mix", "cisco-acl-default",
                "cisco-acl-trailing-token", "cisco-acl-mode-break-abbrev",
                "cisco-acl-mode-break", "cisco-acl-mode-break-unlisted",
                "cisco-global-exit", "cisco-submode-body-exit", "junos-brace",
                "junos-hash-in-word", "panos-quoted-name-space",
                "cisco-post-end", "ipt-comment-out",
                "ipt-continuation", "panos-command-case", "junos-quoted-markers",
                "junos-hash-block", "aws-char-in-string", "sep-joins-lines",
                # round 9 (R8-8)
                "junos-two-terminating", "junos-duplicate-term",
                "junos-term-unknown-stmt", "cisco-acl-seq-range", "cisco-acl-resequence",
                "cisco-acl-cidr-operand", "cisco-acl-log-args", "cisco-acl-keyword-case",
                "ipt-policy-extra-arg", "ipt-commit-spelling", "panos-object-extra-token",
                # round 10 (R9-1, R9-2, R9-3, R9-5)
                "cisco-marker-strip", "cisco-untyped-header", "cisco-dialect-transplant",
                "panos-leaf-dup", "panos-any-plus-member", "junos-leaf-dup",
                "ipt-option-dup"):
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
