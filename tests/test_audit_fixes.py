"""Regression tests for bugs found in the post-launch audit.

Each guards a confirmed correctness bug; the product's promise is that findings
are trustworthy, so these protect against re-introducing false positives /
silent drops / false PASSes.
"""

from rulehawk.analyze import analyze
from rulehawk.parse import parse_acls
from rulehawk.segcheck import check_segmentation


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
