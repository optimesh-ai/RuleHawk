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
