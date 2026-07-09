"""Tests for the Arista EOS ACL parser frontend (parse_eos.py)."""

import pytest
from rulehawk.parse_eos import detect, parse_eos


# ---------------------------------------------------------------------------
# Canonical EOS samples
# ---------------------------------------------------------------------------

# Output from `show running-config` on an Arista switch
_EOS_RUNNING_CONFIG = """\
! Command: show running-config
! device: leaf01 (DCS-7050CX3-32S, EOS-4.29.2F)
!
ip access-list CORP-INGRESS
   10 permit tcp 10.0.0.0/8 any eq 22
   20 permit tcp 10.0.0.0/8 any eq 443
   30 deny ip any any log
"""

# Output from `show ip access-lists` — uses "IP Access List NAME" header
_EOS_SHOW_ACL = """\
! Command: show ip access-lists
! device: spine01 (DCS-7060CX-32S, EOS-4.28.5M)
IP Access List PCI-ZONE
        10 permit tcp 192.168.10.0/24 10.10.0.0/16 eq 443
        20 deny ip any any
"""

# Bare `show ip access-lists` paste — the most common operator copy/paste.
# NO `!` provenance comments at all: the title-case "IP Access List NAME"
# headers are the only EOS signal.  Two ACLs, the first ending in a terminal
# deny, so any cross-ACL merge would falsely kill the second ACL's permits.
_EOS_SHOW_BARE = """\
IP Access List MGMT
        10 permit tcp 10.0.0.0/8 any eq 22
        20 deny ip any any log
IP Access List WEB
        10 permit tcp any 10.20.0.0/16 eq 443
        20 permit tcp any 10.20.0.0/16 eq 80
"""

# NX-OS `show ip access-lists` renders the header in lower case
# ("IP access list NAME") — must NOT trip the case-sensitive EOS signal.
_NXOS_SHOW_ACL = """\
IP access list CORP-IN
        10 permit tcp 10.0.0.0/8 any eq 22
        20 deny ip any any
"""

# IOS `show ip access-lists` renders "Extended IP access list NAME" — the
# line never starts with "IP Access List", so the anchored EOS signal
# must not fire.
_IOS_SHOW_ACL = """\
Extended IP access list OUTSIDE-IN
    10 permit tcp 10.0.0.0 0.0.0.255 any eq 443
    20 deny ip any any
"""

# management api block — another EOS marker
_EOS_MGMT_API = """\
management api http-commands
   no shutdown
!
ip access-list MGMT-ONLY
   10 permit tcp 10.1.0.0/16 any eq 8080
   20 deny ip any any
"""

_IOS_PLAIN = """\
ip access-list extended OUTSIDE-IN
 permit tcp 10.0.0.0 0.0.0.255 any eq 443
 deny ip any any
"""

_NXOS_TEXT = """\
version 9.3(10)
feature interface-vlan

ip access-list CORP-IN
  10 permit tcp 10.0.0.0/8 any eq 22
  20 deny ip any any
"""


class TestDetect:
    def test_running_config_detected(self):
        assert detect(_EOS_RUNNING_CONFIG) is True

    def test_show_acl_output_detected(self):
        assert detect(_EOS_SHOW_ACL) is True

    def test_management_api_detected(self):
        assert detect(_EOS_MGMT_API) is True

    def test_plain_ios_not_detected(self):
        assert detect(_IOS_PLAIN) is False

    def test_nxos_not_detected(self):
        # NX-OS has version-in-parens but no EOS markers
        assert detect(_NXOS_TEXT) is False

    def test_no_acl_no_detect(self):
        text = "! Command: show running-config\n! device: leaf01 (EOS-4.29)\n"
        assert detect(text) is False

    def test_bare_show_paste_detected(self):
        # Regression: a bare `show ip access-lists` paste has no `!` comment
        # lines, so the show header itself must count as an EOS marker.
        assert detect(_EOS_SHOW_BARE) is True

    def test_nxos_lowercase_show_header_not_detected(self):
        # NX-OS renders "IP access list NAME" (lower case) — the EOS signal
        # is case-sensitive and must not fire.
        assert detect(_NXOS_SHOW_ACL) is False

    def test_ios_extended_show_header_not_detected(self):
        # IOS renders "Extended IP access list NAME" — never line-initial
        # "IP Access List", so the anchored EOS signal must not fire.
        assert detect(_IOS_SHOW_ACL) is False


class TestParseEos:
    def test_running_config_produces_aces(self):
        aces, notes = parse_eos(_EOS_RUNNING_CONFIG)
        assert len(aces) >= 3

    def test_show_acl_header_normalised(self):
        # "IP Access List PCI-ZONE" must be rewritten to "ip access-list PCI-ZONE"
        # so the ACL name is captured correctly.
        aces, notes = parse_eos(_EOS_SHOW_ACL)
        assert any(a.acl == "PCI-ZONE" for a in aces)

    def test_seq_numbers_stripped(self):
        aces, notes = parse_eos(_EOS_RUNNING_CONFIG)
        actions = {a.action for a in aces}
        assert "permit" in actions
        assert "deny" in actions

    def test_acl_name_captured_running_config(self):
        aces, notes = parse_eos(_EOS_RUNNING_CONFIG)
        assert any(a.acl == "CORP-INGRESS" for a in aces)

    def test_tcp_port_parsed(self):
        aces, notes = parse_eos(_EOS_RUNNING_CONFIG)
        tcp_aces = [a for a in aces if a.proto == "tcp"]
        ports = {a.dst_port.lo for a in tcp_aces}
        assert 22 in ports
        assert 443 in ports

    def test_cidr_src_parsed(self):
        aces, notes = parse_eos(_EOS_SHOW_ACL)
        assert any(str(a.src) == "192.168.10.0/24" for a in aces)

    def test_deny_any_any(self):
        aces, notes = parse_eos(_EOS_RUNNING_CONFIG)
        deny = [a for a in aces if a.action == "deny"]
        assert any(a.src_any and a.dst_any for a in deny)

    def test_mgmt_api_config_parses(self):
        aces, notes = parse_eos(_EOS_MGMT_API)
        assert any(a.acl == "MGMT-ONLY" for a in aces)

    def test_empty_produces_no_aces(self):
        aces, notes = parse_eos("")
        assert aces == []

    def test_command_comment_not_in_notes(self):
        # "! Command:" lines are comments; they carry no permit/deny and
        # must not appear as unparsed notes.
        aces, notes = parse_eos(_EOS_RUNNING_CONFIG)
        for note in notes:
            assert "Command:" not in note


class TestGateIntegration:
    def test_auto_detect_running_config(self):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_EOS_RUNNING_CONFIG, "auto")
        assert label == "eos"
        assert fn is parse_eos

    def test_auto_detect_show_acl(self):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_EOS_SHOW_ACL, "auto")
        assert label == "eos"

    def test_forced_vendor_eos(self):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_IOS_PLAIN, "eos")
        assert label == "eos"

    def test_forced_vendor_arista_alias(self):
        from rulehawk.gate import _pick_parser
        label, fn = _pick_parser(_IOS_PLAIN, "arista")
        assert label == "eos"

    def test_ios_still_routes_ios_asa(self):
        from rulehawk.gate import _pick_parser
        from rulehawk.parse import parse_acls
        label, fn = _pick_parser(_IOS_PLAIN, "auto")
        assert label == "ios-asa"
        assert fn is parse_acls

    def test_bare_show_paste_end_to_end(self):
        # Regression for the false-dead-rule / segcheck-false-PASS vector:
        # a bare two-ACL `show ip access-lists` paste must route to the EOS
        # frontend, keep the ACLs distinct (no "(unnamed)" merge), and
        # produce ZERO dead-rule findings — MGMT's terminal `deny ip any any`
        # must not shadow WEB's live permits.
        from rulehawk.analyze import analyze
        from rulehawk.gate import _pick_parser

        label, fn = _pick_parser(_EOS_SHOW_BARE, "auto")
        assert label == "eos"
        assert fn is parse_eos

        aces, notes = fn(_EOS_SHOW_BARE)
        assert sorted({a.acl for a in aces}) == ["MGMT", "WEB"]
        assert "(unnamed)" not in {a.acl for a in aces}
        assert len(aces) == 4  # every ACE line parsed, none dropped

        findings = analyze(aces)
        assert findings == [], [
            (f.rule_id, f.kind, f.severity) for f in findings
        ]
