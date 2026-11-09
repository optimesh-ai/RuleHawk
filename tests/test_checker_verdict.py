"""#42 phase 2, slice 7 (second part): the checker's own evaluation of each
assertion, in shadow (design v2 sections 1.3 and 12).

From its own reading of the raw bytes, the checker evaluates every policy
assertion: it walks the bindings through its own per-role rules (a Junos
`input` filter on the unit whose subnet holds the source; the PAN-OS
rulebase; the iptables FORWARD chain), runs its own first-match search of
the address space, and applies only cited defaults (Junos implicit discard,
an iptables chain policy). Its answer per assertion:
- `must_not_reach`: `witness` (some flow is permitted), `no-witness`, or
  `indeterminate`;
- `must_reach`: `all-permitted`, `hole`, or `indeterminate`.
The engine's reading (the legacy parser and `check_segmentation`) is mapped
to the same words. Both go into a separate shadow field, `checker_verdict`;
a disagreement is `checker-disagrees`.

Nothing here can make a record eligible: `checker-verdict-deferred` stays
on every record, `eligible()` is false for every input, pending rows always
block, and `would_pass` stays false. Mutation families 1, 3 and 5-10 and 12
(v2 section 12) run against `checker_verdict`: no mutant that leaks gets
`no-witness`, and no mutant with a hole gets `all-permitted`.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_K00 = os.path.join(_D, "controls", "k00_base.conf")
_P00 = os.path.join(_D, "controls", "p00_base.set")
_I00 = os.path.join(_D, "controls", "i00_base.sh")
_POL = os.path.join(_D, "pol", "v4_ip.json")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _policy():
    with open(_POL, encoding="utf-8") as fh:
        return json.load(fh)


def _reach_policy():
    p = _policy()
    p["must_reach"] = p.pop("must_not_reach")
    return p


@pytest.fixture
def shadow(monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")


def _shadow(tmp_path, name, text, policy=None, vendor="auto"):
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    pol = _policy() if policy is None else policy
    d = json.loads(g.to_json(g.run_gate([str(p)], pol, fail_on="high", vendor=vendor)))
    (f,) = d["files"]
    return f.get("shadow")


def _verdicts(sh, side="checker"):
    return [a[side] for a in sh["checker_verdict"]["assertions"]]


_K = _read(_K00)
_P = _read(_P00)
_I = _read(_I00)


# ------------------------------------------------------------------ eligibility

def test_no_input_makes_a_record_eligible():
    """Q2 and the part-2 rule: eligible() is false for every record."""
    from rulehawk import certificate
    for rec in ({}, {"blockers": []}, {"blockers": None}, {"blockers": ["x"]},
                {"blockers": [], "subs": [], "config_sha256": "0" * 64}, None, [], "x"):
        assert certificate.eligible(rec) is False, rec


@pytest.mark.parametrize("path", [_K00, _P00, _I00])
def test_every_built_record_keeps_the_deferred_blocker_and_its_pending_rows(path):
    from rulehawk import certificate, dialects
    raw = open(path, "rb").read()
    for pol in (_policy(), _reach_policy(), None, {}):
        sh = dialects.shadow_block(raw, "auto", pol, {"reasons": [], "notes": []})
        rec = certificate.build(raw, sh["grammar"], sh["model"], sh["dual_read"],
                                sh.get("placement"), pol, {"reasons": [], "notes": []})
        assert "checker-verdict-deferred" in rec["blockers"], rec
        assert {f"pending:{p}" for p in sh["grammar"]["pending"]} <= set(rec["blockers"])
        assert sh["grammar"]["pending"], sh       # pending rows remain, so they block
        assert certificate.eligible(rec) is False
        assert sh["would_pass"] is False


# ------------------------------------------------------------------ the controls

@pytest.mark.parametrize("path", [_K00, _P00, _I00])
def test_a_control_checker_and_engine_agree_there_is_no_witness(path, shadow):
    d = json.loads(g.to_json(g.run_gate([path], _policy(), fail_on="high", vendor="auto")))
    sh = d["files"][0]["shadow"]
    cv = sh["checker_verdict"]
    assert set(cv) == {"agrees", "assertions"}, cv
    assert cv["agrees"] is True, cv
    (a,) = cv["assertions"]
    assert set(a) == {"assertion", "checker", "engine"}, a
    assert a["checker"] == "no-witness" and a["engine"] == "no-witness", a
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["would_pass"] is False, sh


@pytest.mark.parametrize("path", [_K00, _P00, _I00])
def test_a_control_under_must_reach_has_a_hole(path, tmp_path, shadow):
    sh = _shadow(tmp_path, os.path.basename(path), _read(path), _reach_policy())
    assert _verdicts(sh) == ["hole"], sh
    assert sh["would_pass"] is False


def test_no_checker_verdict_without_the_switch(tmp_path, monkeypatch):
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    assert _shadow(tmp_path, "k.conf", _K) is None


def test_no_all_clear_word_in_the_field(tmp_path, shadow):
    for name, text in (("k.conf", _K), ("p.set", _P), ("i.sh", _I)):
        s = json.dumps(_shadow(tmp_path, name, text)["checker_verdict"])
        for word in ("PASS", "VERIFIED", "certified", "complete", "ok\""):
            assert word not in s, (name, word)


def test_a_disagreement_blocks(tmp_path, shadow):
    """Family 3: F bound only on the PCI side. The engine searches every
    filter on its own and finds no witness; the checker walks the binding,
    finds CORP's ingress unfiltered, and finds a witness."""
    text = _K.replace("ge-0/0/0 { unit 0 { family inet { filter { input F; } address",
                      "ge-0/0/0 { unit 0 { family inet { address")
    sh = _shadow(tmp_path, "m3.conf", text)
    assert _verdicts(sh) == ["witness"], sh
    assert sh["checker_verdict"]["agrees"] is (_verdicts(sh, "engine") == ["witness"]), sh
    if not sh["checker_verdict"]["agrees"]:
        assert sh["blocking_reason"] == "checker-disagrees", sh
    assert sh["would_pass"] is False


# ------------------------------------------------------------------ mutation families

_LEAK = "leak"          # truth: CORP reaches PCI
_HOLE = "hole"          # under must_reach, truth: some part is denied
_OPEN = None            # truth not settled by cited rows: never no-witness

_MUTANTS = [
    # family 1: cross-line rewrite, re-entry, `no` / `delete`
    ("f1-junos-reentry.conf", _K + "firewall {\n    family inet {\n        filter F {\n"
     "            term z { then accept; }\n        }\n    }\n}\n", None, _LEAK),
    ("f1-panos-second-rule.set", "set rulebase security rules z from any to any source any "
     "destination any application any service any action allow\n" + _P, None, _LEAK),
    ("f1-iptables-delete.sh", _I + "iptables -D FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 "
     "-j DROP\niptables -P FORWARD ACCEPT\n", None, _LEAK),
    ("f1-iptables-policy-twice.sh", _I + "iptables -P FORWARD ACCEPT\n", None, None),
    # family 3: mode and context
    ("f3-junos-unbound-ingress.conf",
     _K.replace("ge-0/0/0 { unit 0 { family inet { filter { input F; } address",
                "ge-0/0/0 { unit 0 { family inet { address"), None, _LEAK),
    ("f3-iptables-input-chain.sh", "iptables -P FORWARD ACCEPT\niptables -A INPUT -s "
     "192.0.2.0/24 -d 198.51.100.0/24 -j DROP\n", None, _LEAK),
    ("f3-junos-output-binding.conf", _K.replace("input F;", "output F;"), None, _LEAK),
    # family 5: anchoring
    ("f5-junos-half-prefix.conf", _K.replace(
        "source-address { 192.0.2.0/24; }", "source-address { 192.0.2.0/25; }").replace(
        "term a { from { source-address { 203.0.113.0/24; } } then accept; }",
        "term a { then accept; }"), None, _LEAK),
    ("f5-panos-half-prefix.set", _P.replace("source 192.0.2.0/24", "source 192.0.2.0/25"),
     None, None),
    ("f5-iptables-half-prefix.sh", "iptables -P FORWARD ACCEPT\niptables -A FORWARD -s "
     "192.0.2.0/25 -d 198.51.100.0/24 -j DROP\n", None, _LEAK),
    # family 6: name versus literal
    ("f6-junos-case.conf", _K.replace("input F;", "input f;"), None, None),
    ("f6-iptables-chain-case.sh", _I.replace("-A FORWARD", "-A forward"), None, None),
    # family 7: remote effect and defaults
    ("f7-iptables-no-policy.sh", "iptables -A FORWARD -s 192.0.2.0/25 -d 198.51.100.0/24 "
     "-j DROP\n", None, None),
    ("f7-iptables-accept-policy.sh", "iptables -P FORWARD ACCEPT\n", None, _LEAK),
    # family 8: platform swap
    ("f8-junos-as-panos.conf", _K, "panos", None),
    ("f8-iptables-as-junos.sh", _I, "junos", None),
    # family 9: completeness
    ("f9-junos-no-interfaces.conf", _K[_K.index("firewall {"):], None, None),
    # family 12: script control flow
    ("f12-iptables-exit.sh", "iptables -P FORWARD ACCEPT\nexit\n" + _I, None, _LEAK),
    ("f12-iptables-accept-first.sh", "iptables -P FORWARD DROP\niptables -A FORWARD -j "
     "ACCEPT\n" + _I.split("\n", 1)[1], None, _LEAK),
    ("f12-iptables-and.sh", _I.replace("\n", " && true\n", 1), None, None),
]


@pytest.mark.parametrize("name,text,vendor,truth", _MUTANTS, ids=[m[0] for m in _MUTANTS])
def test_no_leaking_mutant_gets_no_witness(tmp_path, shadow, name, text, vendor, truth):
    sh = _shadow(tmp_path, name, text, vendor=vendor or "auto")
    assert sh["would_pass"] is False, sh
    if "checker_verdict" not in sh:
        return                                   # refused before the model
    got = _verdicts(sh)
    # Review of #58, shared wrong answer: the checker is held to the
    # mutant's ground truth, never to the engine's answer.
    if truth == _LEAK:
        assert got == ["witness"], (name, sh["checker_verdict"])
    else:
        assert truth is _OPEN, name
        assert "no-witness" not in got, (name, sh["checker_verdict"])
    if not sh["checker_verdict"]["agrees"]:
        assert sh["blocking_reason"] in ("checker-disagrees", "reading-mismatch",
                                         "zones-share-segment"), sh


def test_family_7_an_uncited_default_is_indeterminate(tmp_path, shadow):
    sh = _shadow(tmp_path, "f7.sh", "iptables -A FORWARD -s 192.0.2.0/25 -d "
                 "198.51.100.0/24 -j DROP\n")
    assert _verdicts(sh) == ["indeterminate"], sh


def test_family_7_panos_fall_through_is_indeterminate(tmp_path, shadow):
    """The default rules are pending: a flow no rule matches has no cited
    fate."""
    sh = _shadow(tmp_path, "f7.set", _P.replace("source 192.0.2.0/24", "source 192.0.2.0/25"))
    assert _verdicts(sh) == ["indeterminate"], sh


def test_family_7_junos_fall_through_is_the_cited_discard(tmp_path, shadow):
    sh = _shadow(tmp_path, "f7.conf", _K.replace(
        "source-address { 192.0.2.0/24; }", "source-address { 192.0.2.0/25; }"))
    assert _verdicts(sh) == ["no-witness"], sh


def test_family_9_an_unplaced_source_is_indeterminate(tmp_path, shadow):
    sh = _shadow(tmp_path, "f9.conf", _K[_K.index("firewall {"):])
    assert _verdicts(sh) == ["indeterminate"], sh


_HOLES = [
    ("f10-junos-deny.conf", _K),
    ("f10-iptables-half.sh", "iptables -P FORWARD ACCEPT\niptables -A FORWARD -s "
     "192.0.2.0/25 -d 198.51.100.0/24 -j DROP\n"),
    ("f10-junos-half.conf", _K.replace("source-address { 192.0.2.0/24; }",
                                        "source-address { 192.0.2.0/25; }").replace(
        "term a { from { source-address { 203.0.113.0/24; } } then accept; }",
        "term a { then accept; }")),
    ("f10-iptables-drop-policy.sh", "iptables -P FORWARD DROP\n"),
]


@pytest.mark.parametrize("name,text", _HOLES, ids=[h[0] for h in _HOLES])
def test_family_10_no_mutant_with_a_hole_gets_all_permitted(tmp_path, shadow, name, text):
    sh = _shadow(tmp_path, name, text, _reach_policy())
    assert sh["would_pass"] is False
    if "checker_verdict" in sh:
        assert _verdicts(sh) == ["hole"], (name, sh["checker_verdict"])


def test_family_10_an_open_path_is_indeterminate_without_cited_forwarding(tmp_path, shadow):
    """Review of #58, H3: no cited row says the device forwards what its
    filter permits, so `all-permitted` is never the checker's answer."""
    sh = _shadow(tmp_path, "open.sh", "iptables -P FORWARD ACCEPT\n", _reach_policy())
    assert _verdicts(sh) == ["indeterminate"], sh
    assert sh["would_pass"] is False


def test_the_checker_evaluates_its_own_reading_not_the_record(tmp_path, shadow, monkeypatch):
    """A record whose model is forged to deny does not change the checker's
    answer: it reads the bytes."""
    from rulehawk import certificate
    real = certificate.build

    def forged(raw, gm, model, *a):
        rec = real(raw, gm, model, *a)
        for o in rec["subs"][0]["model"]["objects"]:
            if o["values"].get("then") == "accept":
                o["values"]["then"] = "discard"
        return rec
    monkeypatch.setattr(certificate, "build", forged)
    text = _K.replace("term a { from { source-address { 203.0.113.0/24; } } then accept; }",
                      "term a { then accept; }").replace(
        "source-address { 192.0.2.0/24; }", "source-address { 192.0.2.0/25; }")
    sh = _shadow(tmp_path, "forged.conf", text)
    assert _verdicts(sh) == ["witness"], sh


# The mutants the grammar reads, so the checker evaluates them (the rest are
# refused earlier, which is also not an all-clear). Pinned so the families
# above are not vacuous.
_REACHES_CHECKER = {
    "f3-junos-unbound-ingress.conf", "f3-iptables-input-chain.sh",
    "f5-junos-half-prefix.conf", "f5-panos-half-prefix.set", "f5-iptables-half-prefix.sh",
    "f7-iptables-no-policy.sh", "f7-iptables-accept-policy.sh",
    "f9-junos-no-interfaces.conf", "f12-iptables-accept-first.sh",
}


def test_the_mutants_that_reach_the_checker_are_pinned(tmp_path, shadow):
    got = set()
    for name, text, vendor, _ in _MUTANTS:
        sh = _shadow(tmp_path, name, text, vendor=vendor or "auto")
        if "checker_verdict" in sh:
            got.add(name)
    assert got == _REACHES_CHECKER, (sorted(got - _REACHES_CHECKER),
                                     sorted(_REACHES_CHECKER - got))


# ------------------------------------------------------------ review of #58, H1-H5

_UNITS_3 = _K.replace(
    "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n",
    "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n"
    "    ge-0/0/2 { unit 0 { family inet { address 203.0.113.1/24; } } }\n")


def test_h1_a_third_unit_with_no_filter_is_indeterminate(tmp_path, shadow):
    """H1: the source may enter at any unit, not only its own subnet's;
    an unfiltered unit leaves the flow undecided."""
    assert "ge-0/0/2" in _UNITS_3
    sh = _shadow(tmp_path, "h1.conf", _UNITS_3)
    assert _verdicts(sh) == ["indeterminate"], sh
    assert sh["would_pass"] is False


def test_h1_another_unit_whose_filter_lets_the_source_through_is_a_witness(tmp_path, shadow):
    """H1: every unit's filter is walked for the source, not only the
    filter on the source's own unit."""
    text = _UNITS_3.replace(
        "ge-0/0/2 { unit 0 { family inet { address",
        "ge-0/0/2 { unit 0 { family inet { filter { input G; } address").replace(
        "    }\n}\n", "        filter G {\n            term a { then accept; }\n        }\n"
        "    }\n}\n")
    assert "filter G" in text
    sh = _shadow(tmp_path, "h1g.conf", text)
    assert _verdicts(sh) == ["witness"], sh


def test_h1_every_unit_filtered_by_the_deny_keeps_no_witness(tmp_path, shadow):
    text = _UNITS_3.replace("ge-0/0/2 { unit 0 { family inet { address",
                            "ge-0/0/2 { unit 0 { family inet { filter { input F; } address")
    sh = _shadow(tmp_path, "h1f.conf", text)
    assert _verdicts(sh) == ["no-witness"], sh


@pytest.mark.parametrize("pci", ["192.0.0.0/22", "192.0.2.0/23", "0.0.0.0/0"])
def test_h2_a_destination_over_the_source_segment_is_indeterminate(tmp_path, shadow, pci):
    """H2: a destination that is a supernet of the source's segment (or
    overlaps it) is not decided by the filter."""
    pol = _policy()
    pol["zones"]["PCI"] = [pci]
    sh = _shadow(tmp_path, "h2.conf", _K, pol)
    assert _verdicts(sh) == ["indeterminate"], (pci, sh)


def test_h2_a_destination_overlapping_the_segment_in_part_is_indeterminate(tmp_path, shadow):
    pol = _policy()
    pol["zones"]["CORP"] = ["192.0.2.0/25"]
    pol["zones"]["PCI"] = ["192.0.2.0/24"]
    sh = _shadow(tmp_path, "h2p.conf", _K, pol)
    assert _verdicts(sh) == ["indeterminate"], sh


_ACCEPT_ALL = [
    ("h3.conf", "interfaces {\n"
     "    ge-0/0/0 { unit 0 { family inet { filter { input F; } address 192.0.2.1/24; } } }\n"
     "    ge-0/0/1 { unit 0 { family inet { filter { input F; } address 198.51.100.1/24; } } }\n"
     "}\nfirewall {\n    family inet {\n        filter F {\n"
     "            term a { from { source-address { 192.0.2.0/24; } destination-address "
     "{ 198.51.100.0/24; } } then accept; }\n        }\n    }\n}\n"),
    ("h3.sh", "iptables -P FORWARD DROP\niptables -A FORWARD -s 192.0.2.0/24 -d "
     "198.51.100.0/24 -j ACCEPT\n"),
    ("h3.set", "set rulebase security rules a from any to any source 192.0.2.0/24 "
     "destination 198.51.100.0/24 application any service any action allow\n"),
]


@pytest.mark.parametrize("name,text", _ACCEPT_ALL, ids=[a[0] for a in _ACCEPT_ALL])
def test_h3_must_reach_is_never_all_permitted_without_cited_forwarding(tmp_path, shadow,
                                                                       name, text):
    sh = _shadow(tmp_path, name, text, _reach_policy())
    assert "checker_verdict" in sh, sh
    assert _verdicts(sh) == ["indeterminate"], (name, sh["checker_verdict"])
    assert sh["would_pass"] is False


def test_h4_a_destination_on_the_source_segment_is_a_witness(tmp_path, shadow):
    """H4: source and destination on one segment never cross a filter, so
    a filter that denies everything still leaves a witness (kills the
    mutant that drops the same-segment rule)."""
    pol = _policy()
    pol["zones"]["CORP"] = ["192.0.2.0/25"]
    pol["zones"]["PCI"] = ["192.0.2.128/25"]
    text = _K.replace(
        "term a { from { source-address { 203.0.113.0/24; } } then accept; }",
        "term z { then discard; }")
    sh = _shadow(tmp_path, "h4.conf", text, pol)
    assert _verdicts(sh) == ["witness"], sh
    assert sh["would_pass"] is False


def test_h5_an_engine_reading_that_fails_blocks(tmp_path, shadow, monkeypatch):
    """H5: an error in the engine's reading fails closed: the field says
    `error` for each assertion and the run is `checker-disagrees`."""
    from rulehawk import certificate

    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(certificate, "engine_reading", boom)
    sh = _shadow(tmp_path, "h5.conf", _K)
    cv = sh["checker_verdict"]
    assert cv["agrees"] is False, cv
    assert _verdicts(sh, "engine") == ["error"], cv
    assert sh["blocking_reason"] == "checker-disagrees", sh
    assert sh["would_pass"] is False


def test_the_checker_evaluates_the_raw_policy(tmp_path, shadow, monkeypatch):
    """G11 carried to the evaluation: an engine that resolves a zone
    wrongly does not change what the checker evaluates."""
    from rulehawk import certificate
    real = certificate.assertions

    def forged(policy):
        return [a.replace("192.0.2.0/24", "203.0.113.0/24") for a in real(policy)]
    monkeypatch.setattr(certificate, "assertions", forged)
    sh = _shadow(tmp_path, "g11.conf", _K)
    assert _verdicts(sh) == ["no-witness"], sh
    assert sh["blocking_reason"] == "checker-disagrees", sh
