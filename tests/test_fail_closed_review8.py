"""Fail-closed, eighth review of #42 (review-rh42-r7.md).

The class is closed by a line-accounting invariant: every line inside an
object on the evaluated path (an ACL body, a flat `access-list` line, an
interface line, an iptables rule or table line, a PAN-OS line, a Junos term)
ends in exactly one of two states, consumed (turned into model state, every
token read) or noted (a parse-note, which caps the verdict below PASS). The
parsers fill a `failclosed.Ledger`; its one central `close()` turns every
line still unaccounted into a note.

Findings: mixed numbered / unnumbered ACL entries (R7-1); `no N`, `no
sequence N`, `default N` (R7-2); the sequence-number grammar per vendor and
family (R7-3); `exit` after an opener that is not fully recognised (R7-4);
iptables-restore table blocks without `COMMIT` and rules after it (R7-5);
`statistics per-entry` alone does not make a file NX-OS (R7-7); the mutation
self-check (R7-8).

The configs in tests/fixtures/fail_closed/variants/r7 are the reviewer's
synthetic variants (RFC 5737 / RFC 3849 addresses). Every false PASS must be
non-PASS on the CLI, the gate at every level, MCP rulehawk_audit and the
hosted page.
"""

from __future__ import annotations

import glob
import io
import json
import os
import re
import sys
from contextlib import redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_fail_closed import (  # noqa: E402
    _PASS_KINDS, _assertion_findings, _load_policy, _pol, _reason_codes, _run_cli)
from test_fail_closed_review3 import _hosted  # noqa: E402

from rulehawk import cli  # noqa: E402
from rulehawk import gate as g  # noqa: E402
from rulehawk import mcp_server as m  # noqa: E402
from rulehawk.failclosed import cisco_lex  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FX = os.path.join(_ROOT, "tests", "fixtures", "fail_closed")
_R7 = os.path.join(_FX, "variants", "r7")


def _r7(name: str) -> str:
    p = os.path.join(_R7, name)
    if not os.path.exists(p):
        raise FileNotFoundError(name)
    return p


def _pol_for(name: str) -> str:
    """The reviewer's driver: v6* -> v6_ip, *tcp445* -> v4_tcp445, *reach* ->
    v4_reach_ip, else v4_ip."""
    base = os.path.basename(name)
    if base.startswith("v6"):
        return "v6_ip.json"
    if "tcp445" in base:
        return "v4_tcp445.json"
    if "reach" in base:
        return "v4_reach_ip.json"
    return "v4_ip.json"


def _report(path: str, pol: str = "") -> dict:
    _, out = _run_cli([path, "--json", "--policy", _pol(pol or _pol_for(path))])
    return json.loads(out)


def _codes(report: dict) -> set:
    out = set()
    for f in _assertion_findings(report):
        out |= _reason_codes(f)
    return out


def _never_pass(path: str, pol: str = "", hosted: bool = True) -> str:
    pol = pol or _pol_for(path)
    r = _report(path, pol)
    v = r["assertion_verdict"]
    assert v in ("UNKNOWN", "FAIL"), (os.path.basename(path), v, _codes(r))
    for level in ("high", "critical", "low"):
        gate = g.run_gate([path], _load_policy(pol), fail_on=level)
        assert gate.verdict in ("UNKNOWN", "FAIL"), (path, level, gate.verdict)
        assert gate.exit_code() != 0, (path, level)
    res = m.audit(path, _pol(pol))
    assert res["verdict"] != "PASS", (path, res["verdict"])
    assert not res["segmentation_passed"], res["segmentation_passed"]
    if hosted:
        env = _hosted(path, pol)
        assert env["report_json"]["assertion_verdict"] != "PASS", path
        assert not any(f["kind"] in _PASS_KINDS
                       for f in env["report_json"]["findings"]), path
    return v


def _stays_pass(path: str, pol: str = "") -> None:
    r = _report(path, pol)
    assert r["assertion_verdict"] == "PASS", (os.path.basename(path), _codes(r))


def _write(tmp_path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return str(p)


_IF = ("interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n"
       " ip access-group F in\ninterface GigabitEthernet0/1\n"
       " ip address 192.0.2.1 255.255.255.0\n ip access-group F in\n")
_IF6 = ("interface GigabitEthernet0/0\n ipv6 address 2001:db8:10::1/64\n"
        " ipv6 traffic-filter F6 in\ninterface GigabitEthernet0/1\n"
        " ipv6 address 2001:db8:20::1/64\n ipv6 traffic-filter F6 in\n")
_NX = ("feature interface-vlan\ninterface Ethernet1/1\n  no switchport\n"
       "  ip access-group F in\ninterface Ethernet1/2\n  no switchport\n"
       "  ip access-group F in\n")
_DENY = "deny ip 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255"
_LEAK = "permit ip 192.0.2.0 0.0.0.255 any"
_OTHER = "permit ip 203.0.113.0 0.0.0.255 any"
_NXDENY = "deny ip 192.0.2.0/24 198.51.100.0/24"
_NXLEAK = "permit ip 192.0.2.0/24 any"
_NXOTHER = "permit ip 203.0.113.0/24 any"


def _ios(*body: str) -> str:
    return _IF + "ip access-list extended F\n" + "".join(f" {b}\n" for b in body)


def _nx(*body: str) -> str:
    return _NX + "ip access-list F\n" + "".join(f"  {b}\n" for b in body)


# --------------------------------------------------------------------------- #
# The reviewer's false PASSes, every surface
# --------------------------------------------------------------------------- #
_R7_1 = ["a01_unnumbered_then_seq5_permit.cfg", "a02_seq35_after_unnumbered_deny.cfg",
         "a33_reach_mixed_seq5_deny.cfg", "a35_mixed_named_std.cfg",
         "a36_mixed_seq_v4_two_unnumbered.cfg"]
_R7_2 = ["a03_default_seq_removes_deny.cfg", "a03_default_seq_removes_deny_leak.cfg",
         "a04_default_sequence_kw.cfg", "a04_default_sequence_kw_leak.cfg",
         "a05_no_sequence_kw_v4.cfg", "a05_no_sequence_kw_v4_leak.cfg",
         "a34_default_seq_tab.cfg", "a34_default_seq_tab_leak.cfg",
         "a32_reach_default_removes_permit.cfg", "a29_default_remark.cfg",
         "v6a06_no_sequence_removes_deny.cfg", "v6a06b_no_sequence_leak.cfg"]
_R7_3 = ["a07_sequence_kw_ipv4.cfg", "v6a08_bare_seq_ipv6_ios.cfg"]
_R7_4 = ["c05_management_ios_exit.cfg", "c11_bare_router_exit.cfg",
         "c12_bare_line_exit.cfg", "c13_router_ospf_no_id_exit.cfg",
         "c14_vrf_definition_no_name_exit.cfg", "c15_routemap_no_name_exit.cfg",
         "c16_control_plane_junk_exit.cfg"]
_R7_5 = ["b10_ipt_rule_after_commit.rules", "b10b_ipt_drop_policy_rule_after_commit.rules",
         "b11_ipt_no_commit.rules", "b11b_ipt_drop_policy_no_commit.rules"]
_R7_7 = ["a16_statistics_per_entry_ios.cfg", "a17_no_statistics_per_entry.cfg"]
_GENUINE = ["a14_remark_with_acl_words_control.cfg", "a15_seq_remark.cfg",
            "a18_log_control.cfg", "a19_trailing_log_input.cfg", "a26_tab_fields.cfg",
            "a28_upper_DENY_control.cfg", "b04_loopback_ntp_then_acl_lines.cfg",
            "c03_empty_router_exit_control.cfg", "c06_objgroup_header_exit.cfg",
            "c09_line_exit_after_acl.cfg", "d01_junos_block_comment_braces.conf",
            "d07_junos_control.conf", "d08_junos_two_filters_same_name.conf",
            "d09_junos_comment_eol_open_brace.conf", "d10_junos_hash_after_close_brace.conf",
            "p01_panos_case_dup_names.set", "p03_panos_disabled_no_control.set",
            "p10_panos_control.set"]


@pytest.mark.parametrize("cfg", _R7_1 + _R7_2 + _R7_3 + _R7_4 + _R7_5 + _R7_7)
def test_r7_reviewer_false_passes_never_pass(cfg):
    _never_pass(_r7(cfg))


@pytest.mark.parametrize("cfg", _GENUINE)
def test_r7_genuine_controls_stay_pass(cfg):
    _stays_pass(_r7(cfg))


def test_r7_every_other_reviewer_variant_is_still_not_pass():
    """The variants that were already non-PASS at 3d2cbf3 stay so."""
    keep = set(_GENUINE)
    for path in sorted(glob.glob(os.path.join(_R7, "*"))):
        name = os.path.basename(path)
        if name in keep:
            continue
        r = _report(path)
        assert r["assertion_verdict"] != "PASS", (name, _codes(r))


@pytest.mark.parametrize("rel", ["r5/t11_bang.cfg", "r5/t10_control_same_stanza.cfg",
                                 "r5/u08_no_ip_address_control.cfg",
                                 "r5/i13_control_policy_visible.sh"])
def test_r7_earlier_controls_stay_pass(rel):
    _stays_pass(os.path.join(_FX, "variants", rel))


# --------------------------------------------------------------------------- #
# R7-1: mixed numbered and unnumbered entries
# --------------------------------------------------------------------------- #
def test_r7_1_the_backwards_permit_dead_finding_is_gone():
    """a01: `5 permit` runs before the unnumbered deny (10) on the device, so
    the permit is not dead; the deny is."""
    r = _report(_r7("a01_unnumbered_then_seq5_permit.cfg"))
    assert "intent-inversion-permit-dead" not in {f["kind"] for f in r["findings"]}, \
        [(f["kind"], f.get("title", "")[:80]) for f in r["findings"]]


@pytest.mark.parametrize("cfg", ["a01_unnumbered_then_seq5_permit.cfg",
                                 "a02_seq35_after_unnumbered_deny.cfg",
                                 "a35_mixed_named_std.cfg",
                                 "a36_mixed_seq_v4_two_unnumbered.cfg"])
def test_r7_1_the_device_order_proves_the_leak(cfg):
    """With the device order (an unnumbered entry is the last number + 10),
    the permit runs first and the leak is found: FAIL, not only UNKNOWN."""
    assert _report(_r7(cfg))["assertion_verdict"] == "FAIL"


@pytest.mark.parametrize("text", [
    _ios(_DENY, "5 " + _LEAK, _OTHER),
    _ios("20 " + _OTHER, _DENY, "25 " + _LEAK),
    _nx(_NXDENY, "5 " + _NXLEAK),
    _nx("10 " + _NXOTHER, _NXDENY, "15 " + _NXLEAK),
])
def test_r7_1_synthetic_mixed_numbering(tmp_path, text):
    p = _write(tmp_path, "x.cfg", text)
    assert _never_pass(p, "v4_ip.json", hosted=False) == "FAIL"


@pytest.mark.parametrize("text", [
    _ios("10 remark x", _DENY, _OTHER),
    _ios("10 " + _DENY, "20 " + _OTHER),
    _ios(_DENY, _OTHER),
    _ios("10 " + _DENY, _OTHER),
])
def test_r7_1_order_the_same_as_the_text_stays_pass(tmp_path, text):
    _stays_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json")


def test_r7_1_unnumbered_remark_between_numbered_lines_is_noted(tmp_path):
    """Whether an unnumbered remark takes a sequence number is not cited, and
    here it decides the order: `deny` is 20 or 30, `25 permit` before or
    after it."""
    p = _write(tmp_path, "x.cfg", _ios("10 " + _OTHER, "remark r", _DENY, "25 " + _LEAK))
    _never_pass(p, "v4_ip.json", hosted=False)


# --------------------------------------------------------------------------- #
# R7-2: deletions and `default`
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    _ios("10 " + _DENY, "20 " + _LEAK, "no 10"),
    _nx("10 " + _NXDENY, "20 " + _NXLEAK, "no 10"),
    _IF6 + "ipv6 access-list F6\n sequence 10 deny ipv6 2001:db8:20::/48 2001:db8:10::/48\n"
    " sequence 20 permit ipv6 2001:db8:20::/48 any\n no sequence 10\n",
])
def test_r7_2_a_cited_deletion_is_applied_and_proves_the_leak(tmp_path, text):
    pol = "v6_ip.json" if "ipv6" in text else "v4_ip.json"
    p = _write(tmp_path, "x.cfg", text)
    assert _never_pass(p, pol, hosted=False) == "FAIL"


def test_r7_2_the_reviewer_v6_leak_is_found():
    assert _report(_r7("v6a06b_no_sequence_leak.cfg"))["assertion_verdict"] == "FAIL"


@pytest.mark.parametrize("line", ["no 10", "default 10", "default sequence 10",
                                  "no sequence 10", "default remark", "default 20",
                                  "no remark", "default permit ip any any",
                                  "no 99"])
def test_r7_2_a_deletion_or_default_never_passes(tmp_path, line):
    p = _write(tmp_path, "x.cfg", _ios("10 " + _DENY, "20 " + _OTHER, line))
    _never_pass(p, "v4_ip.json", hosted=False)


# --------------------------------------------------------------------------- #
# R7-3: the sequence-number grammar per vendor and family
# --------------------------------------------------------------------------- #
def test_r7_3_ios_ipv6_sequence_keyword_stays_pass(tmp_path):
    text = (_IF6 + "ipv6 access-list F6\n"
            " sequence 10 deny ipv6 2001:db8:20::/48 2001:db8:10::/48\n"
            " sequence 20 permit ipv6 2001:db8:30::/48 any\n")
    _stays_pass(_write(tmp_path, "x.cfg", text), "v6_ip.json")


def test_r7_3_nxos_bare_numbers_stay_pass(tmp_path):
    _stays_pass(_write(tmp_path, "x.cfg", _nx("10 " + _NXDENY, "20 " + _NXOTHER)),
                "v4_ip.json")


@pytest.mark.parametrize("text", [
    _nx("sequence 10 " + _NXDENY, "sequence 20 " + _NXOTHER),
    _ios("sequence 10 " + _DENY, "sequence 20 " + _OTHER),
])
def test_r7_3_sequence_keyword_outside_ios_ipv6_never_passes(tmp_path, text):
    _never_pass(_write(tmp_path, "x.cfg", text), "v4_ip.json", hosted=False)


# --------------------------------------------------------------------------- #
# R7-4: `exit` is clean only after a fully recognised opener
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("opener", ["router", "router ospf", "line", "route-map",
                                    "vrf definition", "control-plane xyzzy",
                                    "management", "management api http-commands",
                                    "class-map", "policy-map", "router ospf 1 xyzzy",
                                    "line vty", "mac access-list"])
def test_r7_4_exit_after_a_partial_opener(tmp_path, opener):
    p = _write(tmp_path, "x.cfg", opener + "\nexit\n" + _ios(_DENY, _OTHER))
    _never_pass(p, "v4_ip.json", hosted=False)


@pytest.mark.parametrize("opener", ["router ospf 1", "router bgp 65000", "line vty 0 4",
                                    "line con 0", "route-map RM permit 10",
                                    "vrf definition V", "control-plane",
                                    "class-map match-any C", "policy-map P"])
def test_r7_4_exit_after_a_full_opener_stays_pass(tmp_path, opener):
    _stays_pass(_write(tmp_path, "x.cfg", opener + "\nexit\n" + _ios(_DENY, _OTHER)),
                "v4_ip.json")


# --------------------------------------------------------------------------- #
# R7-5: iptables-restore table blocks
# --------------------------------------------------------------------------- #
_SAVE = ("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
         "-A FORWARD -s 203.0.113.0/24 -d 198.51.100.0/24 -j ACCEPT\n")
_ACC = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
_DROPR = "-A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n"


@pytest.mark.parametrize("text", [
    _SAVE,                                        # no COMMIT
    _ACC + _DROPR,                                # no COMMIT, the drop inside
    _ACC + "COMMIT\n" + _DROPR,                   # rule after COMMIT
    _ACC + "COMMIT\n:FORWARD DROP [0:0]\n",       # policy after COMMIT
    _DROPR + _ACC + "COMMIT\n",                   # rule before the table
    _SAVE + "COMMIT\nCOMMIT\n",                   # COMMIT outside a block
])
def test_r7_5_table_blocks_must_be_committed(tmp_path, text):
    _never_pass(_write(tmp_path, "x.rules", text), "v4_ip.json", hosted=False)


def test_r7_5_a_committed_block_stays_pass(tmp_path):
    _stays_pass(_write(tmp_path, "x.rules", _SAVE + "COMMIT\n"), "v4_ip.json")


# --------------------------------------------------------------------------- #
# R7-7: `statistics per-entry` alone is not an NX-OS marker
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cfg", _R7_7)
def test_r7_7_ios_file_stays_ios(cfg):
    assert _report(_r7(cfg))["vendor"] != "nxos"


def test_r7_7_nxos_statistics_per_entry_stays_pass(tmp_path):
    p = _write(tmp_path, "x.cfg", _nx("statistics per-entry", "10 " + _NXDENY,
                                      "20 " + _NXOTHER))
    r = _report(p, "v4_ip.json")
    assert r["vendor"] == "nxos" and r["assertion_verdict"] == "PASS", _codes(r)


# --------------------------------------------------------------------------- #
# The line-accounting invariant
# --------------------------------------------------------------------------- #
def test_ledger_close_notes_every_unaccounted_line():
    from rulehawk.failclosed import Ledger
    led = Ledger("unit")
    led.add(1, "permit ip any any")
    led.add(2, "remark x")
    led.add(3, "default 10")
    led.consume(1)
    notes = []
    led.note(2, notes, "line 2 noted")
    led.close(notes)
    c = led.counts()
    assert c == {"scope": 3, "consumed": 1, "noted": 1, "caught": 1, "unaccounted": 0}, c
    assert len(notes) == 2 and "default 10" in notes[1], notes


def test_ledger_a_line_both_consumed_and_noted_is_noted():
    from rulehawk.failclosed import Ledger
    led = Ledger("unit")
    led.add(1, "x")
    led.consume(1)
    led.note(1, [], "n")
    led.close([])
    assert led.counts()["noted"] == 1 and led.counts()["consumed"] == 0


def test_ledger_the_acl_parser_leaves_nothing_unaccounted():
    """The R7-2 hole by construction: `default 10` makes no model state, so
    the central check notes it even though no branch of the parser does."""
    from rulehawk.failclosed import collect_ledgers
    from rulehawk.parse import parse_acls
    with collect_ledgers() as leds:
        _, notes = parse_acls(_ios("10 " + _DENY, "20 " + _OTHER, "default 10"))
    acl = [led for led in leds if led.frontend == "cisco-acl"]
    assert acl and all(led.closed for led in acl)
    c = acl[0].counts()
    assert c["scope"] == 3 and c["unaccounted"] == 0 and c["consumed"] == 2, c
    assert any("default 10" in n for n in notes), notes


def _config_corpus():
    out = []
    for path in sorted(glob.glob(os.path.join(_FX, "**", "*"), recursive=True)):
        if not os.path.isfile(path) or "/pol/" in path or path.endswith((".json", ".md")):
            continue
        out.append(path)
    for path in sorted(glob.glob(os.path.join(_ROOT, "samples", "*"))):
        if not path.endswith(".json") and os.path.isfile(path):
            out.append(path)
    return out


_ACL_HDR = re.compile(r"(?i)^\s*(?:ip|ipv6) access-list\s")
_ENTRY_LIKE = re.compile(r"(?i)^\s*(?:(?:sequence\s+)?\d+\s+)?(?:permit|deny|remark)\b")


def _own_acl_body_lines(text: str):
    """The test's own reading of ACL bodies (not the lexer's): the lines after
    an `ip|ipv6 access-list` header that are indented or entry-like."""
    lines = text.split("\n")
    out = set()
    for i, ln in enumerate(lines):
        if not _ACL_HDR.match(ln):
            continue
        j = i + 1
        while j < len(lines) and lines[j].strip() and (
                lines[j][:1] in (" ", "\t") or _ENTRY_LIKE.match(lines[j])):
            if not lines[j].strip().startswith("!"):
                out.add(j + 1)
            j += 1
    for i, ln in enumerate(lines):
        if re.match(r"(?i)^\s*access-list\s", ln):
            out.add(i + 1)
    return out


def test_ledger_every_fixture_every_line_accounted():
    """Every config fixture and sample through `cli.main`: every ledger is
    closed, no line is left unaccounted, a noted line means no PASS, and the
    ACL lines the test finds by its own reading are in a Cisco ledger's scope
    (or the file does not PASS)."""
    from rulehawk.failclosed import collect_ledgers
    pol = _pol("v4_ip.json")
    tot = {"files": 0, "scope": 0, "consumed": 0, "noted": 0, "caught": 0,
           "unaccounted": 0}
    bad = []
    for path in _config_corpus():
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        buf = io.StringIO()
        with collect_ledgers() as leds, redirect_stdout(buf):
            cli.main([path, "--json", "--policy", pol])
        try:
            v = json.loads(buf.getvalue())["assertion_verdict"]
        except ValueError:
            v = None
        tot["files"] += 1
        flagged = False
        for led in leds:
            c = led.counts()
            for k in ("scope", "consumed", "noted", "caught", "unaccounted"):
                tot[k] += c[k]
            if not led.closed or c["unaccounted"]:
                bad.append(f"{path}: {led.frontend} {c} closed={led.closed}")
            flagged |= bool(c["noted"] or c["caught"])
        if flagged and v == "PASS":
            bad.append(f"{path}: a line is noted but the verdict is PASS")
        cisco_scope = set()
        for led in leds:
            if led.frontend == "cisco-acl":
                cisco_scope |= {k for k in led.scope if isinstance(k, int)}
        own = _own_acl_body_lines(text)
        if leds and any(led.frontend == "cisco-acl" for led in leds) and v == "PASS":
            lex_post = set(cisco_lex(text).post_end)
            missing = sorted(own - cisco_scope - lex_post)
            if missing:
                bad.append(f"{path}: ACL lines not in scope: {missing[:5]}")
    out = os.environ.get("RULEHAWK_LEDGER_REPORT")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(tot, fh)
    print("\nledger:", tot)
    assert tot["files"] > 300 and tot["scope"] > 1000, tot
    assert tot["unaccounted"] == 0 and not bad, "\n".join(bad[:40])


# --------------------------------------------------------------------------- #
# R7-8: the mutation self-check
# --------------------------------------------------------------------------- #
def test_r7_8_independent_breaks_are_independent_of_every_lexer_list():
    from test_fail_closed_mutation_all import _INDEPENDENT_BREAKS
    from rulehawk.failclosed import _ACL_ENTRY, _EXIT_END, _IF_ALLOW_RX, _TOP_LEVEL
    assert len(_INDEPENDENT_BREAKS) >= 10
    for b in _INDEPENDENT_BREAKS:
        s = b.strip(" \t  ")
        assert not _TOP_LEVEL.match(s), b
        assert not _IF_ALLOW_RX.match(s), b
        assert not _ACL_ENTRY.match(s), b
        assert s.split()[0].lower() not in _EXIT_END, b


def test_r7_8_new_mutation_families_exist():
    from test_fail_closed_mutation_all import mutants
    text = _ios("10 " + _DENY, "20 " + _OTHER)
    fams = {f for f, *_ in mutants(text, "ios-asa")}
    for fam in ("cisco-acl-entry-delete", "cisco-acl-default",
                "cisco-acl-trailing-token", "cisco-acl-mode-break-abbrev"):
        assert fam in fams, (fam, sorted(fams))
    text = _ios(_DENY, _OTHER)
    assert "cisco-acl-seq-mix" in {f for f, *_ in mutants(text, "ios-asa")}


def test_r7_8_junos_mutants_inside_comments_are_back():
    from test_fail_closed_mutation_all import mutants
    text = ("/* a block\nfirewall comment */\nfirewall {\n  # note here\n"
            "  family inet { filter F { term t { then accept; } } }\n}\n")
    got = [(f, tag, kind) for f, tag, _, kind, _ in mutants(text, "junos")]
    assert ("junos-keyword-case", "4", "preserve") in got, got
    assert ("junos-annotation", "2", "never") in got, got
