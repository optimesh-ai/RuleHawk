"""Regression tests for bugs found in the post-launch audit.

Each guards a confirmed correctness bug; the product's promise is that findings
are trustworthy, so these protect against re-introducing false positives /
silent drops / false PASSes.
"""

from rulehawk.analyze import analyze
from rulehawk.parse import parse_acls
from rulehawk.parse_junos import parse_junos
from rulehawk.segcheck import check_segmentation

# CORP (10.20/16) must not reach PCI (10.10/16) on tcp/445 — the canonical leak.
_SEG = {"zones": {"CORP": ["10.20.0.0/16"], "PCI": ["10.10.0.0/16"]},
        "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                            "ports": [445]}]}


def _seg_kinds(aces):
    return {f.kind for f in check_segmentation(aces, _SEG)}


def _analyze(cfg):
    aces, notes = parse_acls(cfg)
    return aces, notes, [f.kind for f in analyze(aces)]


def test_ios_host_zero_mask_is_not_any_any():
    # `A.B.C.D 0.0.0.0` is an IOS host (/32), NOT 0.0.0.0/0. It must never be
    # resolved to "any" and reported as permit-any-any / broad-any-any.
    aces, _, kinds = _analyze(
        "ip access-list extended T\n"
        " permit ip 10.1.2.3 0.0.0.0 192.168.1.1 0.0.0.0\n")
    assert aces[0].src_any is False and aces[0].dst_any is False
    assert aces[0].imprecise is False
    assert "permit-any-any" not in kinds and "broad-any-any" not in kinds


def test_asa_host_255_mask_is_exact_and_finds_redundancy():
    # `A.B.C.D 255.255.255.255` is an ASA host (/32) and EXACT — so a genuine
    # duplicate must be caught as redundant (was missed when marked imprecise).
    aces, notes, kinds = _analyze(
        "access-list OUT extended permit ip 10.0.0.5 255.255.255.255 any\n"
        "access-list OUT extended permit ip 10.0.0.5 255.255.255.255 any\n")
    assert all(not a.imprecise for a in aces)
    assert "redundant" in kinds
    assert not any("imprecise" in n for n in notes)


def test_multiport_eq_is_not_silently_dropped():
    # IOS `eq 22 3389` keeps only the first port in the model; the rest MUST be
    # surfaced as a note (silently dropping an exposed port is the worst case).
    _, notes, _ = _analyze("ip access-list extended T\n permit tcp any any eq 22 3389\n")
    assert any("multi-port" in n for n in notes)


def test_segmentation_ip_assertion_catches_specific_proto_rule():
    # A `must_not_reach` with no proto means ANY protocol; a tcp permit that
    # enables the flow is a violation (must not falsely PASS).
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 80\n")
    policy = {"zones": {"C": ["10.20.0.0/16"], "P": ["10.10.0.0/16"]},
              "must_not_reach": [{"src": "C", "dst": "P"}]}
    kinds = [f.kind for f in check_segmentation(aces, policy)]
    assert "segmentation-violation" in kinds
    assert "segmentation-ok" not in kinds


def test_asa_show_access_list_line_number_parses():
    # `show access-list` emits `access-list NAME line N extended ...`; the
    # `line N` token must not break parsing.
    aces, notes = parse_acls("access-list OUT line 1 extended permit tcp any any eq 80\n")
    assert len(aces) == 1
    assert aces[0].action == "permit" and aces[0].proto == "tcp"


# === Soundness audit (2026-W26): false-PASS hunt across constructs/vendors ===
# Each test below pins a CONFIRMED false-PASS: a config that REALLY permits
# CORP(10.20/16) -> PCI(10.10/16):445 but used to report segmentation-ok.


def test_multiport_eq_does_not_false_pass_segmentation():
    # `eq www 445` REALLY permits 445, but the old parser kept only the first
    # port (80) and dropped 445 -> segcheck FALSE-PASSed. Now expanded to the
    # exact per-port union, so 445 is a CRITICAL violation, never PASS.
    # Mutation guard: stop expanding multi-port `eq` -> this reverts to a PASS.
    aces, _ = parse_acls(
        "ip access-list extended OUT\n"
        " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq www 445\n")
    kinds = _seg_kinds(aces)
    assert "segmentation-ok" not in kinds, "FALSE PASS: eq www 445 hides port 445"
    assert "segmentation-violation" in kinds


def test_multiport_eq_models_every_port_exactly():
    # Both ports are real exact ACEs now (not one dropped, not over-approximated).
    aces, _ = parse_acls(
        "ip access-list extended T\n permit tcp any any eq 23 3389\n")
    ports = sorted((a.dst_port.lo, a.dst_port.hi) for a in aces)
    assert ports == [(23, 23), (3389, 3389)] and all(not a.imprecise for a in aces)


def test_object_group_permit_fails_closed_not_ok():
    # An object-group permit on the CORP->PCI path can't be modeled; dropping it
    # let segcheck conclude PASS. Now it's a fail-closed opaque ACE -> the flow is
    # INDETERMINATE, never segmentation-ok.
    # Mutation guard: drop object-group lines again -> reverts to segmentation-ok.
    aces, _ = parse_acls(
        "object-group network CORP_NET\n network-object 10.20.0.0 255.255.0.0\n"
        "object-group network PCI_NET\n network-object 10.10.0.0 255.255.0.0\n"
        "ip access-list extended OUT\n"
        " permit tcp object-group CORP_NET object-group PCI_NET eq 445\n")
    kinds = _seg_kinds(aces)
    assert "segmentation-ok" not in kinds, "FALSE PASS: object-group leak hidden"
    assert "segmentation-indeterminate" in kinds


def test_asa_object_reference_fails_closed_not_ok():
    # Modern ASA `object` (singular) operands failed to parse and were dropped ->
    # FALSE PASS. Now kept fail-closed (opaque imprecise ACE) -> not segmentation-ok.
    aces, _ = parse_acls(
        "object network CORP\n subnet 10.20.0.0 255.255.0.0\n"
        "object network PCI\n subnet 10.10.0.0 255.255.0.0\n"
        "access-list OUT extended permit tcp object CORP object PCI eq 445\n")
    assert "segmentation-ok" not in _seg_kinds(aces), \
        "FALSE PASS: ASA object-reference leak hidden"


def test_cross_acl_deny_does_not_shadow_other_acl_permit():
    # INSIDE-IN genuinely PERMITS CORP->PCI. OUTSIDE-IN is a DIFFERENT, independent
    # ACL whose default `deny ip any any` must NOT shadow it in the witness search.
    # The flat model let it -> FALSE PASS (the Cisco/Junos analog of the iptables
    # INPUT-vs-FORWARD bug). Mutation guard: evaluate the witness over all ACLs
    # again (drop the per-ACL scoping) -> reverts to segmentation-ok.
    aces, _ = parse_acls(
        "ip access-list extended OUTSIDE-IN\n"
        " permit tcp 10.30.0.0 0.0.255.255 any eq 80\n"
        " deny ip any any\n"
        "ip access-list extended INSIDE-IN\n"
        " permit ip 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n")
    kinds = _seg_kinds(aces)
    assert "segmentation-ok" not in kinds, "FALSE PASS: ACL1 deny shadowed ACL2 permit"
    assert "segmentation-violation" in kinds


def test_cross_filter_deny_does_not_shadow_other_filter_permit_junos():
    # Same cross-context shadow on the Junos path: filter SAFE's default discard
    # must not hide filter LEAK's accept.
    cfg = """
    firewall { family inet {
      filter SAFE {
        term web { from { source-address 10.30.0.0/16; protocol tcp; destination-port 80; } then accept; }
        term default { then discard; }
      }
      filter LEAK {
        term bad { from { source-address 10.20.0.0/16; destination-address 10.10.0.0/16; protocol tcp; destination-port 445; } then accept; }
      }
    } }
    """
    aces, _ = parse_junos(cfg)
    kinds = _seg_kinds(aces)
    assert "segmentation-ok" not in kinds
    assert "segmentation-violation" in kinds


def test_per_acl_scoping_does_not_over_fail_clean_multi_acl():
    # Guard against over-failing: two independent ACLs, NEITHER permits CORP->PCI,
    # must still cleanly PASS. (Per-ACL scoping must not invent a leak.)
    aces, _ = parse_acls(
        "ip access-list extended OUTSIDE-IN\n"
        " permit tcp 10.30.0.0 0.0.255.255 any eq 80\n deny ip any any\n"
        "ip access-list extended INSIDE-IN\n"
        " permit tcp 10.20.0.0 0.0.255.255 10.40.0.0 0.0.255.255 eq 443\n deny ip any any\n")
    kinds = _seg_kinds(aces)
    assert "segmentation-ok" in kinds and "segmentation-violation" not in kinds


def test_within_acl_earlier_deny_still_blocks():
    # The per-ACL scoping must NOT weaken same-ACL first-match: an earlier deny in
    # the SAME ACL still blocks the permit -> PASS (no false violation).
    aces, _ = parse_acls(
        "ip access-list extended T\n"
        " deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"
        " permit ip any any\n")
    kinds = _seg_kinds(aces)
    assert "segmentation-ok" in kinds and "segmentation-violation" not in kinds
