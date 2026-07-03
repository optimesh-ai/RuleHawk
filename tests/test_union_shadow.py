"""Union / cumulative shadowing — a rule killed by the UNION of several earlier
rules (not any single one). The detector must be SOUND (no false positives) and
explainable (cite the contributing rules)."""

from rulehawk.analyze import analyze
from rulehawk.parse import parse_acls
from rulehawk.report import to_text


def _findings(cfg):
    aces, _ = parse_acls(cfg)
    return analyze(aces)


def _by_kind(cfg):
    return {f.kind: f for f in _findings(cfg)}


def test_union_of_permits_kills_later_deny_is_critical():
    # Two /24 permits make a /23 deny over their union unreachable (security hole).
    cfg = (
        "ip access-list extended UNION\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " deny tcp 10.0.0.0 0.0.1.255 any eq 443\n")
    f = _by_kind(cfg).get("union-shadowed-deny-dead")
    assert f is not None and f.severity == "critical"
    assert f.rule_id == "UNION:3"
    assert "1" in f.cited and "2" in f.cited       # cites both contributing rules


def test_union_of_denies_kills_later_permit_is_high():
    cfg = (
        "ip access-list extended U2\n"
        " deny tcp 10.0.0.0 0.0.0.255 any eq 22\n"
        " deny tcp 10.0.1.0 0.0.0.255 any eq 22\n"
        " permit tcp 10.0.0.0 0.0.1.255 any eq 22\n")
    f = _by_kind(cfg).get("union-shadowed-permit-dead")
    assert f is not None and f.severity == "high" and f.rule_id == "U2:3"


def test_union_same_action_is_redundant_low():
    cfg = (
        "ip access-list extended U3\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.0.0 0.0.1.255 any eq 443\n")
    f = _by_kind(cfg).get("union-redundant")
    assert f is not None and f.severity == "low" and f.rule_id == "U3:3"


def test_union_redundant_appears_in_cleanup_plan_with_line():
    # The Cleanup plan is the copy-into-ticket section: a union-redundant rule
    # is proven safe to remove, so it MUST be listed there, with its config
    # file line so the operator can apply the deletion without grepping.
    cfg = (
        "ip access-list extended U3\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.0.0 0.0.1.255 any eq 443\n")
    aces, notes = parse_acls(cfg)
    findings = analyze(aces)
    f = {x.kind: x for x in findings}["union-redundant"]
    assert f.line == 4                       # the covered rule's file line
    text = to_text(findings, notes, len(aces))
    assert "Cleanup plan: 1 redundant rule(s) safe to remove:" in text
    plan = text.split("Cleanup plan")[1]
    assert f"- {f.rule_id} (line 4): {f.rule}" in plan


def test_cleanup_plan_counts_both_redundant_kinds_with_lines():
    # One single-rule redundant + one union-redundant -> both in the plan.
    cfg = (
        "ip access-list extended MIX\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 443\n"   # exact dup -> redundant
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.0.0 0.0.1.255 any eq 443\n")  # union of 2+4 -> union-redundant
    aces, notes = parse_acls(cfg)
    findings = analyze(aces)
    kinds = {x.kind for x in findings}
    assert {"redundant", "union-redundant"} <= kinds
    text = to_text(findings, notes, len(aces))
    assert "Cleanup plan: 2 redundant rule(s) safe to remove:" in text
    plan = text.split("Cleanup plan")[1]
    for x in findings:
        if x.kind in ("redundant", "union-redundant"):
            assert f"- {x.rule_id} (line {x.line}): {x.rule}" in plan


def test_partial_union_stays_clean_no_false_positive():
    # Coverers only span 2 of the 4 /24s in the deny's /22 -> residual non-empty.
    cfg = (
        "ip access-list extended PARTIAL\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 443\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " deny tcp 10.0.0.0 0.0.3.255 any eq 443\n")   # /22 = four /24s
    assert not any(f.kind.startswith("union-") for f in _findings(cfg))


def test_union_requires_each_coverer_to_span_ports():
    # Coverers on eq 80 cannot union-shadow a deny on eq 443.
    cfg = (
        "ip access-list extended PORTS\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 80\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 80\n"
        " deny tcp 10.0.0.0 0.0.1.255 any eq 443\n")
    assert not any(f.kind.startswith("union-") for f in _findings(cfg))


def test_union_skips_imprecise_coverer():
    # A neq (imprecise) coverer must never help prove a rule dead.
    cfg = (
        "ip access-list extended IMP\n"
        " permit tcp 10.0.0.0 0.0.0.255 any neq 443\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " deny tcp 10.0.0.0 0.0.1.255 any eq 443\n")
    assert not any(f.kind.startswith("union-") for f in _findings(cfg))


def test_union_skips_established_coverer():
    cfg = (
        "ip access-list extended EST\n"
        " permit tcp 10.0.0.0 0.0.0.255 any eq 443 established\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " deny tcp 10.0.0.0 0.0.1.255 any eq 443\n")
    assert not any(f.kind.startswith("union-") for f in _findings(cfg))


def test_single_rule_shadow_takes_precedence_over_union():
    # rule 3 is covered by rule 1 alone -> reported as the single-rule kind,
    # never as a union finding.
    cfg = (
        "ip access-list extended PREC\n"
        " permit ip any any\n"
        " permit tcp 10.0.1.0 0.0.0.255 any eq 443\n"
        " deny tcp 10.0.0.0 0.0.1.255 any eq 443\n")
    kinds = {f.rule_id: f.kind for f in _findings(cfg)}
    assert kinds.get("PREC:3") == "intent-inversion-deny-dead"
