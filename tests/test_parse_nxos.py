"""Tests for the Cisco NX-OS ACL parser frontend (parse_nxos.py)."""

import pytest
from rulehawk.parse_nxos import detect, parse_nxos


# ---------------------------------------------------------------------------
# Canonical NX-OS sample: version line with parens, feature line, statistics
# ---------------------------------------------------------------------------
_NXOS_SAMPLE = """\
version 9.3(10)
feature interface-vlan

ip access-list CORP-IN
  statistics per-entry
  10 permit tcp 10.0.0.0/8 any eq 22
  20 permit tcp 10.0.0.0/8 any eq 443
  30 deny ip any any log
"""

_NXOS_ETHERNET = """\
version 7.0(3)I7(9)
interface Ethernet1/1

ip access-list PCI-ZONE
  10 permit tcp 192.168.1.0/24 10.10.10.0/24 eq 443
  20 deny ip any any
"""

# Bare `show ip access-lists` paste — the most common operator copy/paste
# from a Nexus.  NO config-mode markers at all: the lower-case
# "IP access list NAME" headers are the only NX-OS signal.  Two ACLs, the
# first ending in a terminal deny, so any cross-ACL merge would falsely kill
# the second ACL's permits.
_NXOS_SHOW_BARE = """\
IP access list ACL-WEB
        statistics per-entry
        10 permit tcp any 10.20.0.0/16 eq 443
        20 deny ip any any
IP access list ACL-DB
        10 permit tcp 10.20.0.0/16 10.30.0.0/16 eq 5432
"""

# Arista EOS `show ip access-lists` renders the header in Title-Case
# ("IP Access List NAME") — must NOT trip the case-sensitive NX-OS signal.
_EOS_SHOW_ACL = """\
IP Access List PCI-ZONE
        10 permit tcp 192.168.10.0/24 10.10.0.0/16 eq 443
        20 deny ip any any
"""

# IOS `show ip access-lists` renders "Extended IP access list NAME" — the
# line never starts with "IP", so the anchored NX-OS signal must not fire.
_IOS_SHOW_ACL = """\
Extended IP access list OUTSIDE-IN
    10 permit tcp 10.0.0.0 0.0.0.255 any eq 443
    20 deny ip any any
"""

_IOS_PLAIN = """\
ip access-list extended OUTSIDE-IN
 permit tcp 10.0.0.0 0.0.0.255 any eq 443
 deny ip any any
"""

_JUNOS_TEXT = """\
firewall {
    family inet {
        filter EDGE {
            term allow-ssh {
                from { source-address 10.0.0.0/8; protocol tcp; destination-port 22; }
                then accept;
            }
        }
    }
}
"""


class TestDetect:
    def test_nxos_version_parens_detected(self):
        assert detect(_NXOS_SAMPLE) is True

    def test_nxos_ethernet_interface_detected(self):
        assert detect(_NXOS_ETHERNET) is True

    def test_plain_ios_not_detected(self):
        # IOS has no NX-OS markers — must NOT be misrouted to nxos.
        assert detect(_IOS_PLAIN) is False

    def test_junos_not_detected(self):
        assert detect(_JUNOS_TEXT) is False

    def test_no_acl_header_not_detected(self):
        # NX-OS marker present but no ACL header — not useful, don't route here.
        text = "version 9.3(10)\nfeature interface-vlan\ninterface Ethernet1/1\n"
        assert detect(text) is False

    def test_statistics_per_entry_marker(self):
        text = "ip access-list TEST\n  statistics per-entry\n  10 permit ip any any\n"
        assert detect(text) is True

    def test_vlan_configuration_marker(self):
        text = "vlan configuration 10\nip access-list VLAN-ACL\n  permit ip any any\n"
        assert detect(text) is True

    def test_bare_show_paste_detected(self):
        # Regression: a bare `show ip access-lists` paste has no config-mode
        # markers, so the lower-case "IP access list NAME" show header itself
        # must count as an NX-OS marker.
        assert detect(_NXOS_SHOW_BARE) is True

    def test_eos_titlecase_show_header_not_detected(self):
        # EOS renders "IP Access List NAME" (Title-Case) — the NX-OS signal
        # is case-sensitive and must not fire.
        assert detect(_EOS_SHOW_ACL) is False

    def test_ios_extended_show_header_not_detected(self):
        # IOS renders "Extended IP access list NAME" — never line-initial
        # "IP access list", so the anchored NX-OS signal must not fire.
        assert detect(_IOS_SHOW_ACL) is False


class TestParseNxos:
    def test_basic_parse_returns_aces(self):
        aces, notes = parse_nxos(_NXOS_SAMPLE)
        assert len(aces) >= 3

    def test_sequence_numbers_stripped(self):
        aces, notes = parse_nxos(_NXOS_SAMPLE)
        # All should parse; the sequence prefix (10, 20, 30) is stripped
        actions = {a.action for a in aces}
        assert "permit" in actions
        assert "deny" in actions

    def test_acl_name_captured(self):
        aces, notes = parse_nxos(_NXOS_SAMPLE)
        assert any(a.acl == "CORP-IN" for a in aces)

    def test_tcp_port_parsed(self):
        aces, notes = parse_nxos(_NXOS_SAMPLE)
        tcp_aces = [a for a in aces if a.proto == "tcp"]
        ports = {a.dst_port.lo for a in tcp_aces}
        assert 22 in ports
        assert 443 in ports

    def test_deny_any_any(self):
        aces, notes = parse_nxos(_NXOS_SAMPLE)
        deny_aces = [a for a in aces if a.action == "deny"]
        assert deny_aces, "expected at least one deny ACE"
        assert any(a.src_any and a.dst_any for a in deny_aces)

    def test_cidr_notation_parsed(self):
        aces, notes = parse_nxos(_NXOS_ETHERNET)
        assert any(str(a.src) == "192.168.1.0/24" for a in aces)

    def test_empty_produces_no_aces(self):
        aces, notes = parse_nxos("")
        assert aces == []

    def test_no_false_notes_on_clean_config(self):
        aces, notes = parse_nxos(_NXOS_SAMPLE)
        # statistics per-entry is a non-ACE line; should not appear as unparsed note
        # (it has no permit/deny keyword so the parser skips it silently)
        for note in notes:
            assert "statistics" not in note

    def test_show_acl_header_normalised(self):
        # "IP access list ACL-WEB" must be rewritten to
        # "ip access-list ACL-WEB" so the ACL name is captured correctly.
        aces, notes = parse_nxos(_NXOS_SHOW_BARE)
        assert any(a.acl == "ACL-WEB" for a in aces)
        assert any(a.acl == "ACL-DB" for a in aces)

    def test_show_paste_no_unnamed_merge(self):
        # Each ACL keeps its own context — nothing lands in "(unnamed)".
        aces, notes = parse_nxos(_NXOS_SHOW_BARE)
        assert sorted({a.acl for a in aces}) == ["ACL-DB", "ACL-WEB"]

    def test_show_paste_all_aces_parsed(self):
        aces, notes = parse_nxos(_NXOS_SHOW_BARE)
        assert len(aces) == 3  # every ACE line parsed, none dropped

    def test_config_form_unchanged_by_normalisation(self):
        # The hyphenated config form must parse identically to before: the
        # show-header rewrite touches only "IP access list" (space) lines.
        aces, notes = parse_nxos(_NXOS_SAMPLE)
        assert any(a.acl == "CORP-IN" for a in aces)
        assert len(aces) >= 3


class TestGateIntegration:
    """Smoke-test the gate-layer auto-detect and forced-vendor paths."""

    def test_auto_detect_routes_to_nxos(self, tmp_path):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_NXOS_SAMPLE, "auto")
        assert label == "nxos"
        assert fn is parse_nxos

    def test_forced_vendor_nxos(self, tmp_path):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_IOS_PLAIN, "nxos")
        assert label == "nxos"

    def test_forced_vendor_nexus_alias(self):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_IOS_PLAIN, "nexus")
        assert label == "nxos"

    def test_forced_vendor_nx_os_alias(self):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_IOS_PLAIN, "nx-os")
        assert label == "nxos"

    def test_plain_ios_still_routes_to_ios_asa(self):
        from rulehawk.gate import _pick_parser
        from rulehawk.parse import parse_acls
        label, fn = _pick_parser(_IOS_PLAIN, "auto")
        assert label == "ios-asa"
        assert fn is parse_acls

    def test_eos_titlecase_show_paste_still_routes_to_eos(self):
        # Cross-vendor guard: the Title-Case EOS show paste must keep routing
        # to the EOS frontend, not get swallowed by the NX-OS show signal.
        from rulehawk.gate import _pick_parser
        from rulehawk.parse_eos import parse_eos
        label, fn = _pick_parser(_EOS_SHOW_ACL, "auto")
        assert label == "eos"
        assert fn is parse_eos

    def test_bare_show_paste_end_to_end(self):
        # Regression for the false-dead-rule vector: a bare two-ACL
        # `show ip access-lists` paste must route to the NX-OS frontend,
        # keep the ACLs distinct (no "(unnamed)" merge), and produce ZERO
        # dead-rule findings — ACL-WEB's terminal `deny ip any any` must not
        # shadow ACL-DB's live permit.
        from rulehawk.analyze import analyze
        from rulehawk.gate import _pick_parser

        label, fn = _pick_parser(_NXOS_SHOW_BARE, "auto")
        assert label == "nxos"
        assert fn is parse_nxos

        aces, notes = fn(_NXOS_SHOW_BARE)
        assert sorted({a.acl for a in aces}) == ["ACL-DB", "ACL-WEB"]
        assert "(unnamed)" not in {a.acl for a in aces}
        assert len(aces) == 3

        findings = analyze(aces)
        assert findings == [], [
            (f.rule_id, f.kind, f.severity) for f in findings
        ]
