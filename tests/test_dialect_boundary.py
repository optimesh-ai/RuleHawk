"""#42 phase 2, slice 3: the dialect boundary in shadow (design v3 section 1.2,
v4 sections 1, 8 L1 and 13).

A file can only ever be certified if exactly one non-Cisco dialect with a
phase-2 grammar (Junos, PAN-OS, iptables) is detected on its raw lines, no
Cisco-family detector fires on any raw line, and no comment or quoted string
spans lines. Under the stopgap this changes no output: the boundary result is
written only into a `shadow` block, and only when RULEHAWK_SHADOW=1. The
block never names a certificate and never holds an all-clear verdict string:
`would_pass` is always false in this slice, because no grammar exists yet.

Run per surface:
- the gate JSON (`files[].shadow`), under every --vendor value;
- the single-file CLI JSON (`shadow`), under auto and each forcing flag;
- MCP audit, which never carries a shadow block (R4-L1), and which must give
  no all-clear on any boundary file under any vendor value.
"""
from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import cli  # noqa: E402
from rulehawk import gate as g  # noqa: E402
from rulehawk import mcp_server as m  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_V = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants")
_D = os.path.join(_V, "design")
_B = os.path.join(_V, "boundary")

_VENDORS = ("auto", "ios-asa", "nxos", "eos", "junos", "panos", "iptables", "aws-sg")
_CLI_FLAGS = {"auto": [], "junos": ["--junos"], "panos": ["--panos"],
              "iptables": ["--iptables"]}
_CISCO_VENDORS = ("ios-asa", "nxos", "eos")

# Reasons a shadow block may give in this slice (names from the design:
# v3 section 1.1/1.2 and v2 section 7). Nothing else.
_REASONS = {"dialect-not-exclusive", "dialect-undetected", "line-not-allowlisted",
            "file-uncertified",
            # slice 4b, the Junos grammar (v3 sections 8 and 9.2)
            "parse-ambiguous", "config-incomplete",
            # review of #51, F1: a second write with no cited merge rule
            # (v2 section 2.1, v3)
            "write-merge-uncited"}
_BOUNDARY_REASONS = {"dialect-not-exclusive", "dialect-undetected",
                     "line-not-allowlisted", "file-uncertified"}

# The Cisco-family attack files of cfg/ and cfg2/ (the B boundary set of the
# attack file, minus the four cfg3 files listed on their own below).
_CISCO_ATTACKS = tuple(sorted(
    f"{d}/{n}" for d in ("cfg", "cfg2") for n in os.listdir(os.path.join(_D, d))
    if any(t in n for t in ("_ios_", "_nxos_", "_asa_"))))

# The design's Junos polyglots: Cisco lines in a comment (k10, k11), the
# veto-dodging forms (k12), and Junos inside an IOS banner (k14).
_POLYGLOTS = {
    "cfg3/k10_junos_comment_holds_cisco_lines.conf": "dialect-not-exclusive",
    "cfg3/k11_polyglot_ios_in_junos_comment.conf": "dialect-not-exclusive",
    # k12's Cisco lines dodge every line-anchored veto form (a space in the
    # interface name, two-space indents), but they sit in a /* */ region
    # that spans lines, which is off the allowlist (v4 section 1, item 1).
    "cfg3/k12_polyglot_veto_dodging_forms.conf": "line-not-allowlisted",
    # k14's IOS lines are `hostname r1`, `banner motd ^` and interfaces with a
    # space in the name: bare tokens, which never veto (v3 section 1.2). Its
    # only detected dialect is Junos, so the boundary lets it through, and
    # slice 4b's Junos grammar has no production for `hostname r1`.
    "cfg3/k14_ios_banner_holds_junos.cfg": "line-not-allowlisted",
}
# The dialect each polyglot is detected as: a vendor value naming another
# non-Cisco dialect leaves no dialect to certify.
_POLYGLOT_DIALECT = "junos"

# v4 section 1 cost list: the three Junos files with a multi-line /* */.
_COST = ("j13_block_comment_multiline.conf", "d01_junos_block_comment_braces.conf",
         "d09_junos_comment_eol_open_brace.conf")

# Positive controls and the may-pass files: the boundary must let them
# through (exactly one non-Cisco dialect, no veto), so the only reason left
# in this slice is file-uncertified. A boundary that blocked these would
# pass every negative test while making slices 4-9 impossible.
_THROUGH = {
    "controls/k00_base.conf": "junos",
    "controls/p00_base.set": "panos",
    "controls/i00_base.sh": "iptables",
    "cfg3/i09_iptables_restore_noflush.rules": "iptables",
    "cfg3/p10_panos_description_holds_cisco_and_quote.set": "panos",
}


def _quiet(fn, *a):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = fn(*a)
    return rc, out.getvalue()


def _gate_shadow(path, vendor="auto"):
    d = json.loads(g.to_json(g.run_gate([path], None, fail_on="high", vendor=vendor)))
    (f,) = d["files"]
    return d, f.get("shadow")


def _cli_shadow(path, vendor="auto"):
    _, out = _quiet(cli.main, [path, "--json", *_CLI_FLAGS[vendor]])
    d = json.loads(out)
    return d, d.get("shadow")


def _keys(x):
    if isinstance(x, dict):
        return set(x) | set().union(*(_keys(v) for v in x.values()))
    if isinstance(x, list):
        return set().union(*(_keys(v) for v in x))
    return set()


def _well_formed(sh):
    """The shadow block's shape: no certificate key, no all-clear string."""
    assert sh is not None, "no shadow block under RULEHAWK_SHADOW=1"
    assert "certified" not in _keys(sh), sh          # R4-L1
    for word in ("PASS", "VERIFIED", "NO_NEW_RISK"):
        assert word not in json.dumps(sh), sh
    assert sh["would_pass"] is False, sh
    assert sh["blocking_reason"] in _REASONS, sh
    b = sh["boundary"]
    assert set(b) >= {"dialects", "cisco_veto", "reason"}, b
    assert b["reason"] in _BOUNDARY_REASONS | {None}, b   # review of #49, I3
    if "grammar" in sh:                              # slice 4b, Junos only
        gm = sh["grammar"]
        # review of #51, F5: `parses`, not the verdict word `accepted`.
        assert set(gm) == {"parses", "reason", "line", "rows", "tags", "pending"}, gm
        assert isinstance(gm["parses"], bool), gm
        assert gm["parses"] == (gm["reason"] is None), gm
    else:
        assert sh["blocking_reason"] not in ("parse-ambiguous", "config-incomplete"), sh
    return sh


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return str(p)


def _read(rel, base=_D):
    with open(os.path.join(base, rel), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture
def shadow(monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")


# ------------------------------------------------------------------ shadow off

@pytest.mark.parametrize("rel", sorted(_THROUGH) + sorted(_POLYGLOTS))
def test_no_shadow_block_without_the_switch(rel, monkeypatch):
    """Without RULEHAWK_SHADOW=1 the output carries no shadow block (v4
    section 13: byte-identical to the stopgap)."""
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    d, sh = _gate_shadow(os.path.join(_D, rel))
    assert sh is None and "shadow" not in d
    d, sh = _cli_shadow(os.path.join(_D, rel))
    assert sh is None


@pytest.mark.parametrize("value", ["0", "", "true", "yes", "1 "])
def test_only_the_exact_switch_turns_shadow_on(value, monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", value)
    _, sh = _gate_shadow(os.path.join(_D, "controls/k00_base.conf"))
    assert sh is None


# ------------------------------------------------------------- B: Cisco family

@pytest.mark.parametrize("vendor", _VENDORS)
@pytest.mark.parametrize("rel", _CISCO_ATTACKS)
def test_cisco_attack_is_not_exclusive_on_the_gate(rel, vendor, shadow):
    _, sh = _gate_shadow(os.path.join(_D, rel), vendor)
    _well_formed(sh)
    assert sh["blocking_reason"] == "dialect-not-exclusive", sh


@pytest.mark.parametrize("vendor", sorted(_CLI_FLAGS))
@pytest.mark.parametrize("rel", _CISCO_ATTACKS)
def test_cisco_attack_is_not_exclusive_on_the_cli(rel, vendor, shadow):
    d, sh = _cli_shadow(os.path.join(_D, rel), vendor)
    assert d["verdict"] in ("FAIL", "UNKNOWN"), d["verdict"]
    _well_formed(sh)
    assert sh["blocking_reason"] == "dialect-not-exclusive", sh


def _want(rel, vendor):
    if vendor in _CISCO_VENDORS or _POLYGLOTS[rel] == "dialect-not-exclusive":
        return "dialect-not-exclusive"
    if vendor not in ("auto", _POLYGLOT_DIALECT):
        return "dialect-undetected"
    return _POLYGLOTS[rel]


@pytest.mark.parametrize("vendor", _VENDORS)
@pytest.mark.parametrize("rel", sorted(_POLYGLOTS))
def test_polyglot_is_blocked_on_the_gate(rel, vendor, shadow):
    _, sh = _gate_shadow(os.path.join(_D, rel), vendor)
    _well_formed(sh)
    assert sh["blocking_reason"] == _want(rel, vendor), sh


@pytest.mark.parametrize("vendor", sorted(_CLI_FLAGS))
@pytest.mark.parametrize("rel", sorted(_POLYGLOTS))
def test_polyglot_is_blocked_on_the_cli(rel, vendor, shadow):
    d, sh = _cli_shadow(os.path.join(_D, rel), vendor)
    assert d["verdict"] in ("FAIL", "UNKNOWN"), d["verdict"]
    _well_formed(sh)
    assert sh["blocking_reason"] == _want(rel, vendor), sh


def test_k10_veto_names_the_raw_cisco_lines(shadow):
    """The veto runs on the raw lines, inside the /* */ region too, and
    names each line it fired on."""
    _, sh = _gate_shadow(os.path.join(_D, "cfg3/k10_junos_comment_holds_cisco_lines.conf"))
    lines = sorted(v["line"] for v in sh["boundary"]["cisco_veto"])
    assert lines == [2, 3], sh


@pytest.mark.parametrize("vendor", _VENDORS)
@pytest.mark.parametrize("rel", _CISCO_ATTACKS + tuple(sorted(_POLYGLOTS)))
def test_mcp_audit_gives_no_all_clear_and_no_shadow(rel, vendor, shadow):
    r = m.audit(os.path.join(_D, rel), "", vendor)
    assert r.get("verdict") not in ("PASS", "ACCEPTED"), r.get("verdict")
    assert r.get("coverage", {}).get("state") != "complete", r.get("coverage")
    assert "shadow" not in json.dumps(r), "the MCP server never carries shadow (R4-L1)"


# ----------------------------------------------------- the controls get through

@pytest.mark.parametrize("rel", sorted(_THROUGH))
def test_control_gets_through_the_boundary(rel, shadow):
    for surface in (_gate_shadow, _cli_shadow):
        _, sh = surface(os.path.join(_D, rel))
        _well_formed(sh)
        b = sh["boundary"]
        assert b["dialects"] == [_THROUGH[rel]], sh
        assert b["cisco_veto"] == [] and b["reason"] is None, sh
        # No grammar yet (slice 4): the first blocking reason is the absence
        # of a certificate, never a boundary reason.
        assert sh["blocking_reason"] == "file-uncertified", sh


@pytest.mark.parametrize("vendor", _CISCO_VENDORS)
@pytest.mark.parametrize("rel", sorted(_THROUGH))
def test_a_cisco_vendor_value_is_not_exclusive(rel, vendor, shadow):
    """--vendor ios-asa / nxos / eos gives dialect-not-exclusive directly
    (v3 section 1.2, item 4)."""
    _, sh = _gate_shadow(os.path.join(_D, rel), vendor)
    assert sh["blocking_reason"] == "dialect-not-exclusive", sh


@pytest.mark.parametrize("rel", sorted(_THROUGH))
def test_a_different_non_cisco_vendor_value_finds_no_dialect(rel, shadow):
    """--vendor only narrows: a vendor value that is not the detected
    dialect leaves no dialect to certify."""
    for vendor in ("junos", "panos", "iptables", "aws-sg"):
        if vendor == _THROUGH[rel]:
            continue
        _, sh = _gate_shadow(os.path.join(_D, rel), vendor)
        assert sh["blocking_reason"] == "dialect-undetected", (vendor, sh)


# ------------------------------------------------------------ v4 section 1 cost

@pytest.mark.parametrize("name", _COST)
def test_multiline_comment_cost_list(name, shadow):
    _, sh = _gate_shadow(os.path.join(_B, name))
    _well_formed(sh)
    assert sh["boundary"]["dialects"] == ["junos"], sh
    assert sh["blocking_reason"] == "line-not-allowlisted", sh


# ------------------------------------------------------- built-up boundary files

def test_two_detectors_fire(tmp_path, shadow):
    """v4 section 8, L1: every detector runs and is counted. A file that both
    the Junos and the PAN-OS detectors fire on is not certifiable."""
    text = _read("controls/k00_base.conf") + _read("controls/p00_base.set")
    _, sh = _gate_shadow(_write(tmp_path, "two.conf", text))
    _well_formed(sh)
    assert sh["boundary"]["dialects"] == ["junos", "panos"], sh
    assert sh["blocking_reason"] == "dialect-undetected", sh


def test_comments_only_file(tmp_path, shadow):
    _, sh = _gate_shadow(_write(tmp_path, "c.conf", "/* nothing */\n# nothing\n\n"))
    _well_formed(sh)
    assert sh["blocking_reason"] == "dialect-undetected", sh


@pytest.mark.parametrize("where", ["prepend", "append"])
@pytest.mark.parametrize("marker,reason", [
    ("interface Gi0/1", "dialect-not-exclusive"),
    ("version 15.2", "dialect-not-exclusive"),
    ("access-list 101 deny ip any any", "dialect-not-exclusive"),
    # These are not in the veto set (bare tokens never veto, v3 section
    # 1.2). The Junos grammar (slice 4b) has no production for them; PAN-OS
    # and iptables get theirs in slices 4c and 4d, so until then those files
    # stay file-uncertified.
    ("!", "grammar"),
    ("hostname x", "grammar"),
    ("end", "grammar"),
])
@pytest.mark.parametrize("rel", ["controls/k00_base.conf", "controls/p00_base.set",
                                 "controls/i00_base.sh"])
def test_control_with_a_cisco_marker_line(rel, marker, reason, where, tmp_path, shadow):
    if reason == "grammar":
        reason = ("line-not-allowlisted" if rel.endswith(".conf")
                  else "file-uncertified")
    body = _read(rel)
    text = (marker + "\n" + body) if where == "prepend" else (body.rstrip("\n") + "\n" + marker + "\n")
    _, sh = _gate_shadow(_write(tmp_path, os.path.basename(rel), text))
    _well_formed(sh)
    assert sh["blocking_reason"] == reason, sh


@pytest.mark.parametrize("comment", [
    "# interface ge-0/0/0",
    "# ip access-group F in",
    "#no shutdown",
    "/* hostname r1 */",
    "    /* access-list 10 permit any */",
])
@pytest.mark.parametrize("rel", ["controls/k00_base.conf", "controls/i00_base.sh"])
def test_broad_shapes_in_a_comment_body_veto(rel, comment, tmp_path, shadow):
    """v4 section 1, item 3: a broad Cisco shape inside a comment body vetoes.
    A comment carries no meaning, so over-blocking there costs nothing."""
    if rel.endswith(".sh") and comment.lstrip().startswith("/*"):
        pytest.skip("iptables scripts have no /* */ comments")
    text = comment + "\n" + _read(rel)
    _, sh = _gate_shadow(_write(tmp_path, os.path.basename(rel), text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "dialect-not-exclusive", sh


def test_a_quoted_string_is_not_a_comment_body(shadow):
    """p10: Cisco text inside a PAN-OS quoted description is mid-line, not a
    comment body; the veto must not fire on it (v4 section 1, item 3)."""
    _, sh = _gate_shadow(os.path.join(_D, "cfg3/p10_panos_description_holds_cisco_and_quote.set"))
    assert sh["boundary"]["cisco_veto"] == [], sh


@pytest.mark.parametrize("rel,line", [
    ("controls/k00_base.conf", '    /* open'),
    ("controls/k00_base.conf", '    */'),
    ("controls/k00_base.conf", '    description "two'),
    ("controls/p00_base.set", 'set rulebase security rules d description "open'),
    ("controls/i00_base.sh", "echo 'open"),
    ("controls/i00_base.sh", 'echo "open'),
])
def test_a_region_that_spans_lines_is_off(rel, line, tmp_path, shadow):
    """v4 section 1, item 1: a /* must close on its line, and a quoted
    string must close on the line it opens."""
    text = _read(rel).rstrip("\n") + "\n" + line + "\n"
    _, sh = _gate_shadow(_write(tmp_path, os.path.basename(rel), text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "line-not-allowlisted", sh


def test_the_veto_splits_raw_bytes_on_lf_only(tmp_path, shadow):
    """The veto's splitter strips nothing: a Cisco form after a pager line or
    in a trailing region is still a raw line (v4 section 1, item 2)."""
    text = _read("controls/k00_base.conf") + "--More--\ninterface Gi0/2\n"
    _, sh = _gate_shadow(_write(tmp_path, "k.conf", text))
    assert sh["blocking_reason"] == "dialect-not-exclusive", sh
    assert any(v["line"] == text.count("\n") for v in sh["boundary"]["cisco_veto"]), sh


def test_every_detector_runs_and_is_counted(tmp_path, shadow):
    """No first-match: a Junos file that the IOS fallback also reads gives
    both members."""
    text = _read("controls/k00_base.conf") + "access-list 101 deny ip any any\n"
    _, sh = _gate_shadow(_write(tmp_path, "k.conf", text))
    assert "junos" in sh["boundary"]["dialects"], sh
    assert "ios-asa" in sh["boundary"]["dialects"], sh
    assert sh["boundary"]["detectors_fired"] == len(sh["boundary"]["dialects"]), sh



# ------------------------------------------------- review of #49 (F1-F4, I1, I3)

def test_well_formed_rejects_an_unknown_boundary_reason():
    """I3: the boundary's own reason is held to the design's codes too."""
    sh = {"boundary": {"dialects": [], "cisco_veto": [], "reason": "made-up"},
          "would_pass": False, "blocking_reason": "file-uncertified"}
    with pytest.raises(AssertionError):
        _well_formed(sh)


@pytest.mark.parametrize("rel,lines", [
    # F1: an escaped quote carries a string across lines with an even quote
    # count on every line (the reviewer's three probes).
    ("controls/i00_base.sh", ['echo "x\\"', "iptables -A FORWARD -j ACCEPT", 'y\\""']),
    ("controls/i00_base.sh", ["echo $'x\\'", "iptables -A FORWARD -j ACCEPT", "y\\''"]),
    ("controls/k00_base.conf", ['description "a\\";', "term z { then accept; }", 'b\\"";']),
    # One line is enough: a backslash on a line that holds a quote.
    ("controls/p00_base.set", ['set rulebase security rules d description "a\\"b"']),
])
def test_a_backslash_on_a_line_with_a_quote_is_off(rel, lines, tmp_path, shadow):
    text = _read(rel).rstrip("\n") + "\n" + "\n".join(lines) + "\n"
    _, sh = _gate_shadow(_write(tmp_path, os.path.basename(rel), text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "line-not-allowlisted", sh


# F2: the gate's vendor aliases (gate._VENDORS) are read as their dialect.
_CISCO_ALIASES = ("ios", "asa", "cisco", "nexus", "nx-os", "arista", "IOS")
_OWN_ALIASES = {"controls/k00_base.conf": ("juniper", "Junos"),
                "controls/p00_base.set": ("paloalto", "palo-alto"),
                "controls/i00_base.sh": ("netfilter",)}


@pytest.mark.parametrize("vendor", _CISCO_ALIASES)
@pytest.mark.parametrize("rel", sorted(_OWN_ALIASES))
def test_a_cisco_vendor_alias_is_not_exclusive(rel, vendor, shadow):
    _, sh = _gate_shadow(os.path.join(_D, rel), vendor)
    _well_formed(sh)
    assert sh["blocking_reason"] == "dialect-not-exclusive", (vendor, sh)


@pytest.mark.parametrize("rel", sorted(_OWN_ALIASES))
def test_a_dialect_alias_resolves_to_its_dialect(rel, shadow):
    for vendor in _OWN_ALIASES[rel]:
        _, sh = _gate_shadow(os.path.join(_D, rel), vendor)
        _well_formed(sh)
        assert sh["blocking_reason"] == "file-uncertified", (vendor, sh)


# F3: every line separator other than LF that str.splitlines() honours.
_SEPARATORS = ["\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "]


@pytest.mark.parametrize("sep", _SEPARATORS, ids=[f"U+{ord(c):04X}" for c in _SEPARATORS])
@pytest.mark.parametrize("rel", ["controls/k00_base.conf", "controls/p00_base.set",
                                 "controls/i00_base.sh"])
def test_a_line_separator_other_than_lf_is_off(rel, sep, tmp_path, shadow):
    text = _read(rel).rstrip("\n") + "\n# x" + sep + "interface Gi0/1" + sep + " ip access-group F in\n"
    if not rel.endswith((".conf", ".sh")):
        text = _read(rel).rstrip("\n") + sep + "interface Gi0/1\n"
    _, sh = _gate_shadow(_write(tmp_path, os.path.basename(rel), text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "line-not-allowlisted", sh


@pytest.mark.parametrize("rel", ["controls/k00_base.conf", "controls/p00_base.set",
                                 "controls/i00_base.sh"])
def test_crlf_line_endings_alone_are_not_a_separator_finding(rel, tmp_path, shadow):
    """A CR directly before LF is a CRLF line end, not a lone CR: the
    boundary lets it through. The Junos grammar (slice 4b) reads LF only
    (v2 section 7: a CR anywhere is off until a per-dialect row is cited),
    so k00 with CRLF ends is off at line 1; PAN-OS and iptables get their
    grammars in slices 4c and 4d."""
    text = _read(rel).replace("\n", "\r\n")
    _, sh = _gate_shadow(_write(tmp_path, os.path.basename(rel), text))
    _well_formed(sh)
    assert sh["boundary"]["reason"] is None, sh
    if rel.endswith(".conf"):
        assert sh["blocking_reason"] == "line-not-allowlisted", sh
        assert sh["grammar"]["line"] == 1, sh
    else:
        assert sh["blocking_reason"] == "file-uncertified", sh


# F4: in a shell script, a # after ; & | ( ) starts a comment.
@pytest.mark.parametrize("line", ["true;#interface Gi0/1", "true&#ip access-group F in",
                                  "true|#no shutdown", "(#hostname r1)"])
def test_a_shell_comment_after_a_metacharacter_is_vetoed(line, tmp_path, shadow):
    text = _read("controls/i00_base.sh") + line + "\n"
    _, sh = _gate_shadow(_write(tmp_path, "i.sh", text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "dialect-not-exclusive", sh


@pytest.mark.parametrize("line", ["true;# hello", "iptables -A FORWARD -j DROP # note",
                                  "echo a#b", "x=1 #"])
def test_a_shell_hash_not_at_line_start_is_off(line, tmp_path, shadow):
    """Most conservative: any # that is not at line start (after optional
    whitespace) in an iptables file is off, unless it sits inside a quote
    that closes on the line."""
    text = _read("controls/i00_base.sh") + line + "\n"
    _, sh = _gate_shadow(_write(tmp_path, "i.sh", text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "line-not-allowlisted", sh


@pytest.mark.parametrize("line", ["  # indented comment", 'echo "a#b"', "echo 'a # b'"])
def test_a_shell_hash_at_line_start_or_in_a_closed_quote_is_not_off(line, tmp_path, shadow):
    text = _read("controls/i00_base.sh") + line + "\n"
    _, sh = _gate_shadow(_write(tmp_path, "i.sh", text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "file-uncertified", sh


def test_tab_in_an_interface_line_is_pinned_with_k14(tmp_path, shadow):
    """I1: `interface<TAB>Gi0/1` is a bare token to the veto (v3 section 1.2),
    like k14's spaced names. The Junos grammar (slice 4b) reads single spaces
    between tokens only, so the line is off."""
    text = _read("controls/k00_base.conf") + "interface\tGi0/1\n"
    _, sh = _gate_shadow(_write(tmp_path, "k.conf", text))
    _well_formed(sh)
    assert sh["boundary"]["cisco_veto"] == [], sh
    assert sh["blocking_reason"] == "line-not-allowlisted", sh
    assert sh["grammar"]["line"] == 16, sh


# ------------------------------------------------- review of #49 round 2 (N1, N2)

@pytest.mark.parametrize("lines", [
    # N1: alternating quotes leave a single-quoted string open across lines
    # with an even count of each quote on every line.
    ["x=\"'\"'", "iptables -A FORWARD -j ACCEPT", "'\"'\""],
    # N1: a heredoc body is never executed.
    ["cat >/dev/null <<'EOF'", "iptables -A FORWARD -j ACCEPT", "EOF"],
    ["cat >/dev/null <<EOF", "iptables -A FORWARD -j ACCEPT", "EOF"],
    ["cat >/dev/null <<-EOF", "iptables -A FORWARD -j ACCEPT", "EOF"],
    # Info: a backslash line continuation joins two lines into one command.
    ["iptables -A FORWARD \\", "-j ACCEPT"],
], ids=["alternating-quotes", "heredoc-quoted", "heredoc", "heredoc-dash",
        "continuation"])
def test_a_shell_region_that_hides_lines_is_off(lines, tmp_path, shadow):
    text = _read("controls/i00_base.sh") + "\n".join(lines) + "\n"
    _, sh = _gate_shadow(_write(tmp_path, "i.sh", text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "line-not-allowlisted", sh


@pytest.mark.parametrize("prompt", ["--More-- ", " --More-- \b\b\b ", "<--- More ---> ",
                                    "---(more 45%)--- "])
@pytest.mark.parametrize("rel", ["controls/k00_base.conf", "controls/p00_base.set",
                                 "controls/i00_base.sh"])
def test_a_pager_prompt_line_is_off(rel, prompt, tmp_path, shadow):
    """N2: the parsers strip a pager prompt at line start and the veto does
    not, so a prompt can hide a line's start from the veto. Any raw line the
    pager pattern matches is off, in every dialect."""
    body = _read(rel).rstrip("\n").split("\n")
    # The prompt goes on a repeated last line, so the dialect is still
    # detected on the unprompted lines (p00 is a single line).
    text = "\n".join(body + [prompt + body[-1]]) + "\n"
    _, sh = _gate_shadow(_write(tmp_path, os.path.basename(rel), text))
    _well_formed(sh)
    assert sh["blocking_reason"] == "line-not-allowlisted", sh
