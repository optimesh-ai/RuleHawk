"""Compliance-evidence artifact — the GRC/audit-vault output.

The value of this artifact is that a reviewer can trust it, so these are mostly
honesty tests: provenance must be re-derivable, VERIFIED must mean something was
proved, an unaudited config must poison the fleet claim, and we must never claim
a control we did not test.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls  # noqa: E402
from rulehawk.analyze import analyze  # noqa: E402
from rulehawk.evidence import (  # noqa: E402
    CONTROL_MAP, CONTROL_TITLES, FAILED, INDETERMINATE, SCHEMA, VERIFIED,
    Subject, build_evidence, controls_for, sha256, to_evidence_markdown,
)
from rulehawk.gate import _KIND_HELP  # noqa: E402
from rulehawk.segcheck import check_segmentation  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"],
              "DMZ": ["203.0.113.0/24"]},
    "must_not_reach": [
        {"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]},
        {"src": "DMZ", "dst": "PCI", "proto": "ip"},
    ],
}

# CORP->PCI:445 permitted (violation); DMZ->PCI denied first (verified).
_LEAKY = ("ip access-list extended T\n"
          " deny ip 203.0.113.0 0.0.0.255 10.10.0.0 0.0.255.255\n"
          " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n"
          " deny ip any any\n")

_CLEAN = ("ip access-list extended T\n"
          " deny ip 203.0.113.0 0.0.0.255 10.10.0.0 0.0.255.255\n"
          " deny ip 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255\n"
          " permit tcp 10.20.0.0 0.0.255.255 host 10.30.0.1 eq 443\n"
          " deny ip any any\n")

_UNPARSEABLE = "this file is not a firewall config at all\n"


def _subject(text, name="t.txt", policy=_POLICY):
    aces, notes = parse_acls(text)
    findings = analyze(aces)
    if policy:
        findings += check_segmentation(aces, policy)
    return Subject(source=name, raw=text.encode(), vendor="ios-asa",
                   aces=aces, findings=findings, notes=notes)


def _build(*texts, policy=_POLICY, **kw):
    subjects = [_subject(t, f"cfg{i}.txt", policy) for i, t in enumerate(texts)]
    return build_evidence(subjects, policy=policy, policy_source="p.json",
                          policy_raw=json.dumps(policy).encode(), **kw)


# --------------------------------------------------------------------------- #
# provenance
# --------------------------------------------------------------------------- #
def test_digest_is_of_the_exact_bytes_audited():
    art = _build(_LEAKY)
    assert art["subjects"][0]["sha256"] == (
        "sha256:" + hashlib.sha256(_LEAKY.encode()).hexdigest())
    assert art["subjects"][0]["bytes"] == len(_LEAKY.encode())


def test_provenance_fields_present():
    art = _build(_LEAKY)
    assert art["schema"] == SCHEMA
    assert art["tool"]["name"] == "rulehawk" and art["tool"]["version"]
    assert art["tool"]["generator"] == "cli"
    assert art["generated_at"].endswith("Z")
    assert art["policy"]["sha256"].startswith("sha256:")
    assert art["policy"]["assertions"] == 2


def test_generator_distinguishes_ci_from_a_browser():
    """Evidence CI produced on every merge is not evidence someone made by hand
    in a browser; a reviewer is entitled to tell them apart."""
    assert _build(_LEAKY, generator="ci")["tool"]["generator"] == "ci"
    hosted = _build(_LEAKY, generator="hosted")
    assert hosted["tool"]["generator"] == "hosted"
    assert any("Generated in-browser" in l for l in hosted["scope"]["limits"])
    assert not any("Generated in-browser" in l
                   for l in _build(_LEAKY)["scope"]["limits"])


def test_declared_version_matches_pyproject():
    from rulehawk import __version__
    text = open(os.path.join(_ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert __version__ in next(
        l for l in text.splitlines() if l.startswith("version"))


def test_artifact_is_deterministic_apart_from_timestamp():
    a = _build(_LEAKY, generated_at="2026-01-01T00:00:00Z")
    b = _build(_LEAKY, generated_at="2026-01-01T00:00:00Z")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --------------------------------------------------------------------------- #
# attestations
# --------------------------------------------------------------------------- #
def test_pass_and_fail_are_attributed_to_the_right_assertion():
    art = _build(_LEAKY)
    by_claim = {a["claim"]: a for a in art["attestations"]}
    corp = by_claim["CORP cannot reach PCI on tcp/445"]
    assert corp["status"] == FAILED
    assert "10.20.0.1 -> 10.10.0.1:445" in corp["witness"]
    assert by_claim["DMZ cannot reach PCI"]["status"] == VERIFIED


def test_clean_config_yields_verified_attestations():
    art = _build(_CLEAN)
    assert [a["status"] for a in art["attestations"]] == [VERIFIED, VERIFIED]
    assert art["result"]["attestations_verified"] == 2


def test_must_reach_is_attested_too():
    """A required flow is a policy claim like any other, and it is about
    AVAILABILITY — it must not be scored as an isolation control."""
    policy = {"zones": _POLICY["zones"],
              "must_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                              "ports": [443]}]}
    art = _build(_LEAKY, policy=policy)
    a = art["attestations"][0]
    assert a["direction"] == "must_reach"
    assert a["claim"] == "CORP must reach PCI on tcp/443"
    assert a["status"] == FAILED           # the ACL denies it
    ids = {(c["framework"], c["control"]) for c in a["controls"]}
    assert ("SOC2-TSC-2017", "A1.2") in ids        # availability
    assert ("PCI-DSS-4.0", "11.4.5") not in ids    # NOT segmentation testing


def test_no_policy_makes_no_isolation_claim():
    art = build_evidence([_subject(_CLEAN, policy=None)], policy=None)
    assert art["attestations"] == [] and art["policy"] is None
    assert "NO isolation claim" in art["scope"]["note"]
    assert not any(c["status"] == VERIFIED for c in art["controls"])


def test_unknown_zone_is_indeterminate_not_verified():
    policy = {"zones": {"PCI": ["10.10.0.0/16"]},
              "must_not_reach": [{"src": "TYPO", "dst": "PCI", "proto": "ip"}]}
    assert _build(_LEAKY, policy=policy)["attestations"][0]["status"] == INDETERMINATE


def test_unknown_proto_is_indeterminate_not_verified():
    policy = {"zones": _POLICY["zones"],
              "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tpc"}]}
    assert _build(_CLEAN, policy=policy)["attestations"][0]["status"] == INDETERMINATE


def test_per_assertion_split_matches_one_combined_run():
    """Attestations re-check each assertion alone; pin the equivalence."""
    aces, _ = parse_acls(_LEAKY)
    combined = sorted((f.kind, f.rule_id) for f in check_segmentation(aces, _POLICY))
    split = []
    for a in _POLICY["must_not_reach"]:
        split += [(f.kind, f.rule_id) for f in check_segmentation(
            aces, {"zones": _POLICY["zones"], "must_not_reach": [a]})]
    assert combined == sorted(split)


# --------------------------------------------------------------------------- #
# fleet semantics
# --------------------------------------------------------------------------- #
def test_one_leaky_config_fails_the_whole_fleet_claim():
    art = _build(_CLEAN, _CLEAN, _LEAKY)
    corp = next(a for a in art["attestations"] if a["claim"].startswith("CORP"))
    assert corp["status"] == FAILED
    assert [f["subject"] for f in corp["failed_on"]] == ["cfg2.txt"]
    assert corp["verified_on"] == ["cfg0.txt", "cfg1.txt"]


def test_all_clean_configs_verify_and_name_their_basis():
    corp = next(a for a in _build(_CLEAN, _CLEAN)["attestations"]
                if a["claim"].startswith("CORP"))
    assert corp["status"] == VERIFIED
    assert corp["basis"] == "no audited ruleset permits this flow"


def test_unparseable_config_blocks_every_verified_attestation():
    """The leak could be in the file we could not read."""
    art = _build(_CLEAN, _UNPARSEABLE)
    assert art["coverage"]["complete"] is False
    assert all(a["status"] == INDETERMINATE for a in art["attestations"])
    assert "unaudited config may break it" in art["attestations"][0]["detail"]


def test_unparseable_config_does_not_mask_a_real_failure():
    """Incomplete coverage downgrades a PASS, but must never hide a FAIL."""
    corp = next(a for a in _build(_LEAKY, _UNPARSEABLE)["attestations"]
                if a["claim"].startswith("CORP"))
    assert corp["status"] == FAILED


def test_coverage_is_reported_honestly():
    art = _build(_CLEAN, _LEAKY, _UNPARSEABLE)
    assert art["coverage"]["subjects"] == 3
    assert art["coverage"]["subjects_audited"] == 2
    assert art["coverage"]["subjects_not_audited"] == 1
    assert art["coverage"]["complete"] is False


def test_findings_are_attributed_to_their_subject():
    art = _build(_CLEAN, _LEAKY)
    viol = next(f for f in art["findings"] if f["kind"] == "segmentation-violation")
    assert viol["subject"] == "cfg1.txt"


# --------------------------------------------------------------------------- #
# control mapping
# --------------------------------------------------------------------------- #
def test_every_finding_kind_the_engine_emits_is_mapped():
    """An unmapped kind silently drops out of the control rollup — the finding
    would appear in the artifact bearing on no requirement at all."""
    unmapped = set(_KIND_HELP) - set(CONTROL_MAP)
    assert not unmapped, f"finding kinds with no control mapping: {sorted(unmapped)}"


def test_every_mapped_control_id_has_a_title():
    for kind, frameworks in CONTROL_MAP.items():
        for fw, ids in frameworks.items():
            assert fw in CONTROL_TITLES, f"{kind}: unknown framework {fw}"
            for cid in ids:
                assert CONTROL_TITLES[fw].get(cid), f"{kind}: {fw} {cid} untitled"


def test_unmapped_kind_yields_no_controls():
    assert controls_for("some-future-finding-kind") == []


def test_controls_only_appear_when_evidence_exists():
    """PCI 11.4.5 is segmentation testing — not present without one."""
    art = build_evidence([_subject(_CLEAN, policy=None)], policy=None)
    ids = {(c["framework"], c["control"]) for c in art["controls"]}
    assert ("PCI-DSS-4.0", "11.4.5") not in ids


def test_failed_attestation_fails_its_controls():
    seg = {(c["framework"], c["control"]): c for c in _build(_LEAKY)["controls"]}
    assert seg[("PCI-DSS-4.0", "11.4.5")]["status"] == FAILED
    assert seg[("ISO-27001-2022", "A.8.22")]["status"] == FAILED
    assert seg[("NIST-800-53r5", "SC-7(21)")]["status"] == FAILED


def test_connectivity_loss_does_not_map_to_confidentiality_criteria():
    """A dead permit costs availability, not confidentiality."""
    for kind in ("intent-inversion-permit-dead", "union-shadowed-permit-dead",
                 "connectivity-broken"):
        fws = CONTROL_MAP[kind]
        assert "HIPAA-SECURITY" not in fws
        assert fws.get("SOC2-TSC-2017", []) == ["A1.2"]
        assert "11.4.5" not in fws.get("PCI-DSS-4.0", [])


def test_scope_limits_are_embedded():
    art = _build(_LEAKY)
    blob = " ".join(art["scope"]["limits"]).lower()
    assert "nat is not modeled" in blob and "routing" in blob
    assert "was not audited" in blob
    assert "not a certification" in art["scope"]["disclaimer"].lower()


def test_unparseable_input_is_not_a_clean_bill_of_health():
    art = build_evidence([_subject(_UNPARSEABLE, policy=None)], policy=None)
    assert art["subjects"][0]["status"] == "no_rules_parsed"
    assert art["result"]["hygiene_score"] is None


# --------------------------------------------------------------------------- #
# markdown rendering
# --------------------------------------------------------------------------- #
def test_markdown_leads_with_the_verdict_and_the_witness():
    md = to_evidence_markdown(_build(_LEAKY))
    assert "**FAIL — 1 claim(s) disproved.**" in md
    assert "10.20.0.1 -> 10.10.0.1:445" in md
    assert "PCI-DSS-4.0" in md and "11.4.5" in md


def test_markdown_warns_when_coverage_is_incomplete():
    md = to_evidence_markdown(_build(_CLEAN, _UNPARSEABLE))
    assert "Coverage is incomplete" in md


def test_markdown_tables_are_not_broken_by_pipes_in_control_titles():
    """NIST titles contain '|'; unescaped they corrupt the whole table."""
    md = to_evidence_markdown(_build(_LEAKY))
    rows = [l for l in md.splitlines() if l.startswith("| NIST-800-53r5")]
    assert rows
    for row in rows:
        assert len(row.split("|")) - 1 - row.count("\\|") == 5, f"broken: {row}"
    assert "Boundary Protection \\| Isolation" in md


def test_markdown_renders_for_every_shape_without_error():
    for art in (_build(_CLEAN), _build(_LEAKY, _CLEAN, _UNPARSEABLE),
                build_evidence([], policy=None),
                build_evidence([_subject(_CLEAN, policy=None)], policy=None)):
        assert to_evidence_markdown(art).startswith("# Segmentation evidence")


# --------------------------------------------------------------------------- #
# CLI + gate wiring
# --------------------------------------------------------------------------- #
def _run(args, **kw):
    return subprocess.run([sys.executable, "-m", "rulehawk", *args],
                          cwd=_ROOT, capture_output=True, text=True, **kw)


def test_cli_evidence_flag_emits_valid_artifact(tmp_path):
    cfg = tmp_path / "acl.txt"; cfg.write_bytes(_LEAKY.encode())
    pol = tmp_path / "p.json"; pol.write_text(json.dumps(_POLICY))
    proc = _run([str(cfg), "--policy", str(pol), "--evidence"])
    art = json.loads(proc.stdout)
    assert art["schema"] == SCHEMA
    assert art["subjects"][0]["sha256"] == sha256(_LEAKY.encode())
    assert proc.returncode == 1          # still gates on critical/high


def test_cli_evidence_md_flag_emits_document(tmp_path):
    cfg = tmp_path / "acl.txt"; cfg.write_bytes(_LEAKY.encode())
    pol = tmp_path / "p.json"; pol.write_text(json.dumps(_POLICY))
    out = _run([str(cfg), "--policy", str(pol), "--evidence-md"]).stdout
    assert out.startswith("# Segmentation evidence")
    assert "10.20.0.1 -> 10.10.0.1:445" in out


def test_cli_evidence_hash_matches_the_file_on_disk(tmp_path):
    """Guard the decode-then-hash regression: digest is of the file's bytes."""
    cfg = tmp_path / "acl.txt"
    cfg.write_bytes(_LEAKY.encode() + b" description \xff\xfe\n")
    art = json.loads(_run([str(cfg), "--evidence"]).stdout)
    assert art["subjects"][0]["sha256"] == sha256(cfg.read_bytes())


def test_cli_evidence_still_fails_closed_on_unparseable_input(tmp_path):
    cfg = tmp_path / "x.txt"; cfg.write_text(_UNPARSEABLE)
    proc = _run([str(cfg), "--evidence"])
    assert proc.returncode == 2          # parse failure, not a clean audit
    assert json.loads(proc.stdout)["subjects"][0]["status"] == "no_rules_parsed"


def test_gate_emits_fleet_evidence_across_every_config(tmp_path):
    (tmp_path / "a.txt").write_text(_CLEAN)
    (tmp_path / "b.txt").write_text(_LEAKY)
    pol = tmp_path / "p.json"; pol.write_text(json.dumps(_POLICY))
    out, md = tmp_path / "ev.json", tmp_path / "ev.md"
    _run(["gate", str(tmp_path / "*.txt"), "--policy", str(pol),
          "--evidence", str(out), "--evidence-md", str(md), "-q"])
    art = json.loads(out.read_text())
    assert art["tool"]["generator"] == "ci"
    assert art["coverage"]["subjects"] == 2 and art["coverage"]["complete"]
    corp = next(a for a in art["attestations"] if a["claim"].startswith("CORP"))
    assert corp["status"] == FAILED
    assert [f["subject"] for f in corp["failed_on"]] == [str(tmp_path / "b.txt")]
    assert md.read_text().startswith("# Segmentation evidence")


def test_gate_evidence_digests_match_the_files_on_disk(tmp_path):
    (tmp_path / "a.txt").write_text(_CLEAN)
    (tmp_path / "b.txt").write_text(_LEAKY)
    out = tmp_path / "ev.json"
    _run(["gate", str(tmp_path / "*.txt"), "--evidence", str(out), "-q"])
    for s in json.loads(out.read_text())["subjects"]:
        assert s["sha256"] == sha256(open(s["source"], "rb").read())
