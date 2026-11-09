"""The dialect boundary for the PASS allowlist (#42 design v3 section 1.2,
v4 sections 1 and 8 L1). Shadow only: nothing here changes a verdict.

A file clears the boundary only if, on its raw lines:
- exactly one non-Cisco dialect is detected, with every detector run and
  counted, never first-match, and the vendor value (read through the gate's
  aliases) does not name another one. Junos, PAN-OS and iptables have a
  phase-2 grammar; an AWS security-group file clears the boundary but stays
  `file-uncertified` until a grammar lands for it (v3 section 1.2, item 1);
- no Cisco-family detector fires: the line-anchored markers below, the NX-OS
  and EOS detectors, the IOS/ASA fallback finding a rule, the IOS interface
  and binding forms, or a broad Cisco shape inside a comment body;
- no line holds a line separator other than LF (a CR right before LF is a
  line end), no line holds a backslash together with a quote, and in
  iptables no `#` stands anywhere but at line start or inside a quote that
  closes on its line (review of #49, F1, F3, F4); no line matches a pager
  prompt or ends in a backslash continuation, and in iptables no line holds
  both quote kinds or a `<<` (round 2, N1, N2);
- no comment or quoted string spans lines.

Anything else is UNKNOWN with the design's reason: `dialect-not-exclusive`
when a Cisco form fired (or a Cisco vendor value was given),
`dialect-undetected` when no single non-Cisco dialect is left, and
`line-not-allowlisted` for a line the rules above put off. A file that
clears the boundary still has no certificate in this release
(`file-uncertified`): the grammars come in slice 4. Every rule here narrows;
none needs a citation.

The result goes only into a `shadow` block, and only when the environment
variable RULEHAWK_SHADOW is exactly "1" (v4 section 13). The block never
carries a certificate key or an all-clear verdict string: `would_pass` is
always false here.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional

from .model import _PAGER
from .parse import parse_acls
from .parse_awssg import detect as _detect_awssg
from .parse_eos import detect as _detect_eos
from .parse_iptables import detect as _detect_iptables
from .parse_junos import detect as _detect_junos
from .parse_nxos import detect as _detect_nxos
from .parse_panos import detect as _detect_panos

# Dialects with a phase-2 grammar (v3 section 1.2, item 1). AWS security
# groups are non-Cisco but have no allowlist grammar yet.
GRAMMAR_DIALECTS = ("junos", "panos", "iptables")
CISCO_FAMILY = ("ios-asa", "nxos", "eos")

NOT_EXCLUSIVE = "dialect-not-exclusive"
UNDETECTED = "dialect-undetected"
LINE_NOT_ALLOWLISTED = "line-not-allowlisted"
UNCERTIFIED = "file-uncertified"


def shadow_on() -> bool:
    """Shadow output is written only when RULEHAWK_SHADOW is exactly "1"."""
    return os.environ.get("RULEHAWK_SHADOW") == "1"


def raw_lines(raw: bytes) -> List[str]:
    """The veto's own splitter: the raw bytes split on LF only, with no
    banner, `end`, comment, string, pager or after-`end` stripping (v4
    section 1, item 2). A CR stays on its line."""
    return raw.decode("utf-8", errors="replace").split("\n")


_DIALECT_MARKERS = {
    "ios-asa": [
        # IOS `show running-config` (Cisco 800 Series ISR Software
        # Configuration Guide, "Basic Router Configuration"): "Building
        # configuration...", "Current configuration : 986 bytes",
        # "version 12.4", "boot-start-marker".
        # https://www.cisco.com/c/en/us/td/docs/routers/access/800/software/configuration/guide/SCG800Guide/SCG800_Guide_BookMap_chapter_010.html
        re.compile(r"(?m)^Building configuration\.\.\.[ \t\r]*$"),
        re.compile(r"(?m)^Current configuration : \d+ bytes[ \t\r]*$"),
        re.compile(r"(?m)^version \d+\.\d+[ \t\r]*$"),
        re.compile(r"(?m)^boot-start-marker[ \t\r]*$"),
        # IOS ACL headers `ip access-list { extended | standard } NAME`
        # (Catalyst 9400 IOS XE 16.10 command reference,
        # https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9400/software/release/16-10/command_reference/b_1610_9400_cr/security_commands.html);
        # NX-OS has no type word (NX-OS 10.5 security guide,
        # https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus3600/105x/configuration/security/cisco-nexus-3600-switch-nx-os-security-configuration-guide-105x/m-configuring-ip-acls.html). `standard` is left out: whether
        # EOS has a `standard` header is not cited.
        re.compile(r"(?m)^ip access-list extended \S+[ \t\r]*$"),
        # Numbered `access-list N {deny | permit | remark}` (IOS command
        # reference, `access-list (IP extended)`,
        # https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/access-list.htm);
        # NX-OS and EOS have only
        # named ACLs.
        re.compile(r"(?m)^access-list \d+ (?:permit|deny|remark)\s"),
        # ASA: ": Saved", "ASA Version 9.1(5)4" (Cisco document 72273,
        # "Configure DNS Doctoring for Three NAT Interfaces on ASA",
        # https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/72273-dns-doctoring-3zones.html)
        # and `access-list NAME extended | standard` (ASA 9.20 firewall
        # configuration guide,
        # https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config.pdf).
        re.compile(r"(?m)^ASA Version \d"),
        re.compile(r"(?m)^: Saved[ \t\r]*$"),
        re.compile(r"(?m)^access-list \S+ (?:extended|standard) "),
    ],
    "nxos": [
        # NX-OS `show running-config`: "version 9.3(1) Bios:version 05.39"
        # (Nexus 9000 NX-OS 9.3(x) System Management Configuration Guide,
        # "Configuration Replace and Commit-timeout",
        # https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/system-management/b-cisco-nexus-9000-series-nx-os-system-management-configuration-guide-93x/b-cisco-nexus-9000-series-nx-os-system-management-configuration-guide-93x_chapter_011000.html),
        # and the `feature` command ("switch(config)# feature interface-vlan",
        # "Enable the VLAN network interface feature using the feature
        # interface-vlan configuration", Nexus 9000 NX-OS 9.3(x) Interfaces
        # Configuration Guide, VLAN interfaces,
        # https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/interfaces/configuration/guide/b-cisco-nexus-9000-nx-os-interfaces-configuration-guide-93x/b-cisco-nexus-9000-nx-os-interfaces-configuration-guide-93x_chapter_0101.html). `interface EthernetN/N` is not one: IOS names Ethernet
        # ports the same way.
        re.compile(r"(?m)^version \d+\.\d+\(\d+\)"),
        re.compile(r"(?m)^feature \S+[ \t\r]*$"),
    ],
    "eos": [
        # EOS `show running-config`: "! device: r1 (cEOSLab, EOS-4.33.1F-...)"
        # (third-party: the annet tutorial,
        # https://annetutil.github.io/annet/main/usage/tutorial.html; Arista's
        # manual is behind a bot challenge). `! Command: show running-config`
        # is not one: NX-OS writes `!Command: show running-config` too.
        re.compile(r"(?m)^! device: \S+ \(.*\bEOS-\d"),
    ],
}


# The line-anchored IOS interface and binding forms (v3 section 1.2, item 3).
_IOS_LINE_FORMS = [
    re.compile(r"^interface \S+[ \t\r]*$"),
    re.compile(r"^ ip access-group \S+ (?:in|out)[ \t\r]*$"),
]

# Broad Cisco shapes, applied only to a comment body (v4 section 1, item 3).
_BROAD = re.compile(r"(?i)^\s*(interface|ip|ipv6|access-list|router|hostname|line|"
                    r"object-group|banner|vlan|switchport|no)\s")

_DETECTORS = (
    ("junos", _detect_junos),
    ("panos", _detect_panos),
    ("iptables", _detect_iptables),
    ("aws-sg", _detect_awssg),
    ("nxos", _detect_nxos),
    ("eos", _detect_eos),
)


def detect_dialects(text: str) -> List[str]:
    """Every dialect whose detector fires on `text`, sorted. Every detector
    runs (v4 section 8, L1); `ios-asa` is the IOS/ASA fallback parser finding
    at least one rule."""
    found = [name for name, det in _DETECTORS if det(text)]
    if parse_acls(text)[0]:
        found.append("ios-asa")
    return sorted(found)


def _comment_bodies(line: str) -> List[str]:
    """The comment bodies on one raw line: the text after a `#` at line start
    or after whitespace or a shell metacharacter (`;`, `&`, `|`, `(`, `)`;
    review of #49, F4), and the text between a same-line `/*` and `*/`. Over-reading here
    only blocks more: a comment carries no meaning."""
    out = []
    for m in re.finditer(r"/\*(.*?)\*/", line):
        out.append(m.group(1))
    m = re.search(r"(?:^|[\s;&|()])#(.*)$", line)
    if m:
        out.append(m.group(1))
    return out


def cisco_veto(lines: List[str]) -> List[dict]:
    """Each raw line a Cisco-family form fires on, with the form."""
    hits = []
    for n, ln in enumerate(lines, 1):
        form = None
        for fam, rxs in _DIALECT_MARKERS.items():
            if any(rx.search(ln) for rx in rxs):
                form = f"{fam}-marker"
                break
        if form is None and any(rx.match(ln) for rx in _IOS_LINE_FORMS):
            form = "ios-interface-form"
        if form is None and any(_BROAD.match(b) for b in _comment_bodies(ln)):
            form = "cisco-shape-in-comment"
        if form is not None:
            hits.append({"line": n, "form": form})
    return hits


# Line separators other than LF that str.splitlines() honours, so that every
# parser splits there and the veto does not (review of #49, F3). A CR right
# before LF is a CRLF line end, and is not counted here.
_OTHER_SEPARATORS = re.compile("[\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")


def _off_line(lines: List[str], dialect: str) -> Optional[int]:
    """The first raw line that is off the allowlist before any grammar reads
    it, or None:
    - a line separator other than LF (review of #49, F3);
    - a backslash on a line that holds a quote: an escaped quote can carry a
      string across lines with an even quote count on every line (F1);
    - in iptables, a `#` that is not at line start (after optional
      whitespace) and not inside a quote that closes on the line (F4);
    - a comment or quoted string that does not close on the line it opens
      (v4 section 1, item 1)."""
    for n, ln in enumerate(lines, 1):
        body = ln[:-1] if ln.endswith("\r") else ln
        if _OTHER_SEPARATORS.search(body):
            return n
        if "\\" in ln and ('"' in ln or "'" in ln):
            return n
        # Any raw line a pager prompt matches: the parsers strip the prompt
        # and the veto does not (review of #49 round 2, N2).
        if _PAGER.match(ln):
            return n
        # A backslash line continuation joins two lines into one statement.
        if body.rstrip().endswith("\\"):
            return n
        if dialect == "iptables":
            # A line holding both quote kinds can leave a string open with an
            # even count of each; a heredoc body is never run (N1).
            if ('"' in ln and "'" in ln) or "<<" in ln:
                return n
            unquoted = re.sub(r"\"[^\"]*\"|'[^']*'", "", ln)
            if "#" in unquoted and not re.match(r"^\s*#", unquoted):
                return n
        if dialect == "junos":
            rest = re.sub(r"/\*.*?\*/", "", ln)
            if "/*" in rest or "*/" in rest:
                return n
        quotes = ('"', "'") if dialect == "iptables" else ('"',)
        if any(ln.count(q) % 2 for q in quotes):
            return n
    return None


def boundary(raw: bytes, vendor: str = "auto") -> dict:
    """The boundary result for one file's raw bytes under a vendor value."""
    lines = raw_lines(raw)
    text = "\n".join(lines)
    dialects = detect_dialects(text)
    veto = cisco_veto(lines)
    # The NX-OS and EOS detectors and the IOS/ASA fallback read the whole text.
    cisco_found = [d for d in dialects if d in CISCO_FAMILY]
    reason: Optional[str] = None
    line: Optional[int] = None
    if veto or cisco_found or vendor in CISCO_FAMILY:
        reason = NOT_EXCLUSIVE
        line = veto[0]["line"] if veto else None
    else:
        tried = [d for d in dialects if vendor in ("auto", d)]
        if len(dialects) != 1 or len(tried) != 1:
            reason = UNDETECTED
        else:
            line = _off_line(lines, tried[0])
            if line is not None:
                reason = LINE_NOT_ALLOWLISTED
    return {"dialects": dialects, "detectors_fired": len(dialects),
            "cisco_veto": veto, "reason": reason, "line": line}


def shadow_block(raw: bytes, vendor: str = "auto") -> dict:
    """The shadow block for one file (v4 section 13). In this release no
    file is certified, so `would_pass` is false. The first blocking reason
    is the boundary's; then, for a file the boundary lets through as Junos,
    PAN-OS or iptables, that dialect's grammar's (slices 4b to 4d:
    `line-not-allowlisted`, `parse-ambiguous`, `config-incomplete` or
    `write-merge-uncited`, in a `grammar` entry, or `file-uncertified` with
    a `grammar_unavailable` entry when the grammar cannot load); otherwise
    `file-uncertified`. A file the grammar parses also gets its final model
    (slice 5) in a `model` entry."""
    b = boundary(raw, vendor)
    block = {"boundary": b, "would_pass": False,
             "blocking_reason": b["reason"] or UNCERTIFIED}
    if b["reason"] is None and b["dialects"] in (["junos"], ["panos"], ["iptables"]):
        # Imported here, not at module level (review of #51, F3): a grammar
        # resolves its rows on import, and a row that went pending must not
        # break a run with the switch unset. In a shadow run it fails
        # closed: no grammar entry, and the file stays file-uncertified.
        try:
            if b["dialects"] == ["junos"]:
                from . import grammar_junos as grammar
            elif b["dialects"] == ["panos"]:
                from . import grammar_panos as grammar
            else:
                from . import grammar_iptables as grammar
        except KeyError as e:
            block["grammar_unavailable"] = str(e.args[0] if e.args else e)
            return block
        gm, model = grammar.parse_model(raw)
        block["grammar"] = gm
        block["blocking_reason"] = gm["reason"] or UNCERTIFIED
        if model is not None:
            # Slice 5: the final model of a file the grammar parses.
            block["model"] = model
    return block
