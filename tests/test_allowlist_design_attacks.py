"""PASS-allowlist design reviews of #42 (review-rh42-design.md and its
round 2): the reviewers' attack configs, one test per (file, surface).

Fixtures are in tests/fixtures/fail_closed/variants/design:
- cfg/: 18 configs from round 1, rows in EXPECTED.tsv;
- cfg2/: 10 configs from round 2, rows in EXPECTED-r2.tsv;
- cfg3/: 52 configs from round 3 aimed at the non-Cisco path, rows in
  EXPECTED-r3.tsv. Two of them (i09, p10) may PASS by design and are only
  checked for their assertion verdict (_MAY_PASS);
- cfg4/: 2 configs from the v4 delta check (p17, p18), rows in
  EXPECTED-r4.tsv. Both PASS on the #42 engine at a6d9d61;
- controls/: positive controls. They must be all-clear on every surface
  once PASS is restored (design v4, slice 9). Without them, a build that
  answered UNKNOWN to everything would pass this file.

The base is #44, the 0.4.1 fail-closed stopgap, under which no surface ever
emits PASS. So until slice 9:
- the controls' all-clear tests, and i09's PASS verdict, are
  `xfail(strict=True, raises=AssertionError)` with reason "stopgap: no
  PASS", and their stopgap observations are pinned (_STOPGAP_CONTROL for
  the observations, _STOPGAP_MAY_PASS for i09);
- the per-assertion verdict is read from the findings, because the stopgap
  removed the JSON key `assertion_verdict`.

All addresses are RFC 5737.

The rule is the design's all-clear invariant (design v3, section 3): no
surface may give an all-clear for an attack file. An all-clear is any of
these:
- exit 0 or `passed: true`;
- PASS, ACCEPTED, VERIFIED or NO_NEW_RISK;
- `coverage.state == complete` or a non-empty `segmentation_passed`;
- a check-mark headline;
- an empty SARIF.

Phase 2 ships B, with no Cisco-family PASS. So every Cisco attack file,
g01 and r2_10 included, must exit non-zero on the CLI and the gate.

How the red cells are kept honest (review round 2, M10):
- every red (file, surface) cell is `xfail(strict=True,
  raises=AssertionError)`, so a crash or a fixture error still counts as a
  failure;
- each red cell also has a pinned test that asserts today's exact wrong
  observation, so the xfail cannot absorb a different wrong answer;
- when phase 2 fixes a cell, its strict xfail and its pinned test both fail
  until the cell is taken out of _RED;
- the phase-3 gate runs this file with RULEHAWK_PHASE3_GATE=1, which fails
  while _RED, _RED_B, _STOPGAP_CONTROL or _STOPGAP_MAY_PASS is not empty.
"""

from __future__ import annotations

import collections
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import cli  # noqa: E402
from rulehawk import combine  # noqa: E402
from rulehawk import gate as g  # noqa: E402
from rulehawk import mcp_server as m  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")

# file (relative to _D) -> (policy, allowed assertion verdicts), from the
# "expected RuleHawk" column of EXPECTED.tsv and EXPECTED-r2.tsv.
_ATTACKS = {
    "cfg/a01_ios_no_ip_access_list_after_bind.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a02_ios_seq_reorder_permit_first.cfg": ("v4_ip.json", {"FAIL"}),
    "cfg/a03_ios_remark_only_acl.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a04_ios_description_holds_binding_text.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a05_ios_banner_delim_midline.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a06_ios_portchannel_member_binding.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a07_ios_subinterface_parent_binding.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a08_ios_alias_shutdown_reenable.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a09_ios_out_only_bindings_platform.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a10_ios_crlf_tab_in_deny.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a11_ios_excerpt_bytecount_mismatch.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/a12_ios_reach_urpf_inert_ruling.cfg": ("v4_reach_ip.json", {"UNKNOWN"}),
    "cfg/g01_ios_accepted_violation_gate.cfg": ("v4_ip_accepted.json", {"FAIL"}),
    "cfg/i01_iptables_exit_before_drop.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/j01_junos_except_inverts_source.conf": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg/n01_nxos_unlisted_admin_state.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg/p01_panos_object_named_like_literal.set": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg/s01_asa_control_plane_binding.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_01_ios_version_contradicts_declared_release.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_02_ios_svi_only_dialect_declared.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_03_ios_svi_secondary_same_vlan.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_04_ios_pacl_then_no_switchport.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_05_ios_dynamic_default_port_both_modes.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_06_ios_banner_single_line_close.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_07_ios_banner_caret_literal.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_08_ios_binding_name_case_folded.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_09_ios_bytecount_within_tolerance_missing_iface.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg2/r2_10_ios_accepted_plus_unallowlisted_line.cfg": ("v4_ip_accepted.json", {"FAIL"}),
    # round 3 (EXPECTED-r3.tsv), all aimed at the non-Cisco path except k14
    "cfg3/i02_iptables_goto_falls_to_policy.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i03_iptables_limit_on_drop.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i04_iptables_return_in_user_chain.sh": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg3/i05_iptables_policy_twice.sh": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg3/i06_iptables_ipset_accept_first.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i07_iptables_heredoc_not_executed.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i08_iptables_fragment_only_drop.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i10_iptables_lowercase_chain.sh": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg3/i11_iptables_function_never_called.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i12_iptables_time_window_drop.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i13_iptables_nfqueue_bypass.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i14_iptables_insert_accept_top.sh": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg3/i15_iptables_shell_var_reassigned.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i16_iptables_conditional_drop.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i17_iptables_save_two_filter_blocks.rules": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i18_iptables_save_invalid_line_aborts.rules": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/i19_iptables_iprange_partial.sh": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k01_junos_count_only_term.conf": ("v4_ip.json", {"FAIL"}),
    "cfg3/k02_junos_noncontiguous_mask.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k03_junos_dscp_narrowed_deny.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k04_junos_interface_range_unfiltered.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k05_junos_delete_annotation_binding.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k06_junos_apply_path_prefix_list.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k07_junos_prefix_list_except.conf": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg3/k08_junos_set_deactivate_term.set": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg3/k09_junos_policer_term.conf": ("v4_ip.json", {"FAIL"}),
    "cfg3/k10_junos_comment_holds_cisco_lines.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k11_polyglot_ios_in_junos_comment.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k12_polyglot_veto_dodging_forms.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k13_junos_irb_both_zones_one_unit.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k14_ios_banner_holds_junos.cfg": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k15_junos_pci_nexthop_on_corp_segment.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k16_junos_coloc_masked_by_other_finding.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k17_junos_apply_groups_wildcard_unit.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k18_junos_replace_tag_subtree_save.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/k19_junos_inactive_binding.conf": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p02_panos_rule_type_interzone_deny.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p03_panos_same_zone_two_segments.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p04_panos_move_rule_top.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p05_panos_vsys_split_rulebase.set": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    "cfg3/p06_panos_shared_object_shadowed.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p07_panos_ip_range_partial.set": ("v4_ip.json", {"FAIL"}),
    "cfg3/p08_panos_dnat_prenat_destination.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p09_panos_zone_defined_twice.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p11_panos_list_attr_set_twice.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p12_panos_post_rulebase_before_local.set": ("v4_ip.json", {"FAIL"}),
    "cfg3/p13_panos_edl_source.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p14_panos_pci_nexthop_on_corp_segment.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg3/p15_panos_disabled_deny.set": ("v4_ip.json", {"FAIL"}),
    "cfg3/p16_panos_negate_source_deny.set": ("v4_ip.json", {"FAIL", "UNKNOWN"}),
    # v4 delta check (EXPECTED-r4.tsv): static-route next hops, R4-M1, R4-H1
    "cfg4/p17_panos_default_route_via_corp_segment.set": ("v4_ip.json", {"UNKNOWN"}),
    "cfg4/p18_panos_recursive_nexthop_via_corp_segment.set": ("v4_ip.json", {"UNKNOWN"}),
}

# Round-3 files whose expected answer includes PASS: i09 (PASS with the
# printed flushing-restore assumption, R3-L4) and p10 (PASS only if the
# quoted-string row is cited; the veto must not fire on mid-line Cisco
# text). They are not attack files: only their assertion verdict is checked.
_MAY_PASS = {
    "cfg3/i09_iptables_restore_noflush.rules": ("v4_ip.json", {"PASS"}),
    "cfg3/p10_panos_description_holds_cisco_and_quote.set": ("v4_ip.json", {"PASS", "UNKNOWN"}),
}

# Files whose correct answer may be a certified FAIL (review r3, L2). For
# them `coverage: complete` and NO_NEW_RISK against itself are allowed when
# the audit verdict is FAIL. Every other attack file is not certifiable by
# construction, so those two are red for it.
_CERTIFIABLE_FAIL = frozenset(f"cfg3/{n}" for n in (
    "k01_junos_count_only_term.conf", "k08_junos_set_deactivate_term.set",
    "k09_junos_policer_term.conf", "i05_iptables_policy_twice.sh",
    "i10_iptables_lowercase_chain.sh", "i14_iptables_insert_accept_top.sh",
    "p05_panos_vsys_split_rulebase.set", "p07_panos_ip_range_partial.set",
    "p12_panos_post_rulebase_before_local.set", "p15_panos_disabled_deny.set"))

# Positive controls: genuine PASSes today. They are non-Cisco, so B does not
# make them UNKNOWN.
_CONTROLS = {
    "controls/i00_base.sh": "v4_ip.json",
    "controls/k00_base.conf": "v4_ip.json",
    "controls/p00_base.set": "v4_ip.json",
}

_LEVELS = ("critical", "high", "medium", "low", "none")


def _p(rel: str) -> str:
    p = os.path.join(_D, rel)
    if not os.path.exists(p):
        raise FileNotFoundError(rel)
    return p


def _pol(name: str) -> str:
    return os.path.join(_D, "pol", name)


def _policy(name: str) -> dict:
    with open(_pol(name), encoding="utf-8") as fh:
        return json.load(fh)


def _quiet(fn, *a):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = fn(*a)
    return rc, out.getvalue()


# --------------------------------------------------------------------------
# Surfaces. Each observer returns a short observation string, which the
# pinned tests compare exactly. bad(obs, allowed, rel) says whether the
# observation is an all-clear, or a wrong assertion verdict, for an attack
# file. good(obs) says whether it is the all-clear a positive control must
# give.
#
# Exit-code surfaces read the per-assertion verdict as well as rc (review
# r3, M5). Otherwise an unrelated finding (k16's `term a accept`) turns the
# gate, combine and SARIF red while the assertion itself is a false PASS.
# --------------------------------------------------------------------------

# Assertion findings: segmentation (must_not_reach) and connectivity
# (must_reach). Every other kind of these two families is undecided.
_SEG = {"segmentation-ok": "PASS", "segmentation-violation": "FAIL",
        "connectivity-ok": "PASS", "connectivity-broken": "FAIL"}
_ASSERTION_KINDS = ("segmentation-", "connectivity-")
_ASSERTION_OK = frozenset(k for k, v in _SEG.items() if v == "PASS")


def _assertion_of(gate_json: dict) -> str:
    """The per-assertion verdicts in a gate JSON, e.g. "PASS" or
    "FAIL,UNKNOWN", or "none"."""
    vs = set()
    for f in gate_json.get("files", []):
        for x in f.get("findings", []):
            k = x.get("kind", "")
            if k.startswith(_ASSERTION_KINDS):
                vs.add(_SEG.get(k, "UNKNOWN"))
    return ",".join(sorted(vs)) or "none"


def _assert_bad(a: str, allowed) -> bool:
    return any(v not in allowed for v in a.split(",")) or a == "none"


def _obs_cli_json(path, pol, _tmp):
    # The stopgap removed `assertion_verdict`; read the assertion findings.
    _, out = _quiet(cli.main, [path, "--json", "--policy", _pol(pol)])
    return _assertion_of({"files": [json.loads(out)]})


def _obs_cli_text(path, pol, _tmp):
    rc, out = _quiet(cli.main, [path, "--policy", _pol(pol)])
    return f"rc={rc} pass_line={'verdict: PASS' in out}"


def _obs_cli_evidence(path, pol, _tmp):
    _, out = _quiet(cli.main, [path, "--policy", _pol(pol), "--evidence"])
    sts = sorted({a["status"] for a in json.loads(out).get("attestations", [])})
    return ",".join(sts) or "none"


def _obs_gate(level):
    def obs(path, pol, _tmp):
        gate = g.run_gate([path], _policy(pol), fail_on=level)
        d = json.loads(g.to_json(gate))
        ck = g.to_markdown(gate).lstrip().startswith("## ✅")
        return (f"{gate.verdict}/passed={gate.passed}/json_passed={d['passed']}"
                f"/exit={gate.exit_code()}/check_mark={ck}/assert={_assertion_of(d)}")
    return obs


def _gate_bad(level):
    def bad(obs, allowed, _rel):
        v, passed, jp, ex, ck, a = obs.split("/")
        return (v in ("PASS", "ACCEPTED") or passed != "passed=False"
                or jp != "json_passed=False" or ck != "check_mark=False"
                or (level != "none" and ex == "exit=0")
                or _assert_bad(a[len("assert="):], allowed))
    return bad


def _gate_good(obs):
    return obs == ("PASS/passed=True/json_passed=True/exit=0/check_mark=True"
                   "/assert=PASS")


def _obs_gate_cli(path, pol, _tmp):
    r = subprocess.run(
        [sys.executable, "-m", "rulehawk", "gate", path, "--policy", _pol(pol),
         "--json", "-", "-q"],
        cwd=_ROOT, capture_output=True, text=True)
    try:
        a = _assertion_of(json.loads(r.stdout))
    except ValueError:
        a = "unreadable"
    return f"rc={r.returncode} assert={a}"


def _obs_sarif(path, pol, _tmp):
    gate = g.run_gate([path], _policy(pol), fail_on="high")
    ids = sorted({r["ruleId"] for r in json.loads(g.to_sarif(gate))["runs"][0]["results"]})
    # Only a result about the assertion (or an uncertified file) shows that
    # the assertion is not clean. A hygiene result does not, and neither does
    # a segmentation-ok or connectivity-ok result (review v4 delta, R4-L3).
    seg = [i for i in ids if (i.startswith(_ASSERTION_KINDS) and i not in _ASSERTION_OK)
           or i == "rulehawk/uncertified"]
    return f"results={len(ids)} assertion_results={','.join(seg) or 'none'}"


def _obs_mcp_audit(path, pol, _tmp):
    r = m.audit(path, _pol(pol))
    return (f"{r['verdict']}/seg_passed={len(r['segmentation_passed'])}"
            f"/coverage={r['coverage']['state']}")


def _mcp_audit_bad(obs, _allowed, rel):
    # `complete` means every file is file-certified (design v2 section 3).
    # Only a file whose correct answer may be a certified FAIL may be
    # complete, and then only with a FAIL verdict (review r3, L2).
    v, sp, cov = obs.split("/")
    return (v in ("PASS", "ACCEPTED") or sp != "seg_passed=0"
            or (cov == "coverage=complete"
                and not (rel in _CERTIFIABLE_FAIL and v == "FAIL")))


def _obs_mcp_compare(path, pol, _tmp):
    # compare(f, f): no textual change, so the answer rests on certification
    # alone. NO_NEW_RISK needs both sides file-certified and every new-side
    # assertion decided (design v3 section 3).
    return (f"{m.compare(path, path, _pol(pol))['verdict']}"
            f"/audit={m.audit(path, _pol(pol))['verdict']}")


def _mcp_compare_bad(obs, _allowed, rel):
    v, a = obs.split("/")
    return v == "NO_NEW_RISK" and not (rel in _CERTIFIABLE_FAIL and a == "audit=FAIL")


def _obs_combine(path, pol, tmp):
    d = tmp / "records"
    d.mkdir()
    _quiet(g.main, [path, "--policy", _pol(pol), "--result", str(d / "r.json"), "-q"])
    vf, cm = tmp / "verdict.txt", tmp / "comment.md"
    rc, _ = _quiet(combine.main, [str(d), "-q", "--verdict", str(vf), "--comment", str(cm)])
    v = vf.read_text(encoding="utf-8").split("\n")[0] if vf.exists() else "none"
    proven = cm.exists() and "Segmentation proven" in cm.read_text(encoding="utf-8")
    return f"rc={rc} verdict={v} proven_line={proven}"


def _combine_bad(obs, _allowed, _rel):
    rc, v, pl = obs.split(" ")
    return rc == "rc=0" or v in ("verdict=PASS", "verdict=ACCEPTED") or pl == "proven_line=True"


def _obs_hosted(path, pol, _tmp):
    from tests.test_hosted_parity import _WORKER, _analyze_py, _read, _run_hosted
    with open(path, encoding="utf-8", newline="") as fh:   # keep CR bytes (a10)
        cfg = fh.read()
    with open(_pol(pol), encoding="utf-8") as fh:
        ptxt = fh.read()
    r = _run_hosted(_analyze_py(_read(_WORKER)), cfg, ptxt)["report_json"]
    return _assertion_of({"files": [r]})


# name -> (observer, bad(obs, allowed, rel), good(obs) or None)
_SURFACES = {
    "cli_json": (_obs_cli_json, lambda o, a, r: o not in a, lambda o: o == "PASS"),
    "cli_text": (_obs_cli_text,
                 lambda o, a, r: o.startswith("rc=0 ") or o.endswith("pass_line=True"),
                 lambda o: o == "rc=0 pass_line=True"),
    "cli_evidence": (_obs_cli_evidence,
                     lambda o, a, r: "VERIFIED" in o.split(","),
                     lambda o: o == "VERIFIED"),
    **{f"gate_{lv}": (_obs_gate(lv), _gate_bad(lv), _gate_good) for lv in _LEVELS},
    "gate_cli": (_obs_gate_cli,
                 lambda o, a, r: o.startswith("rc=0 ") or _assert_bad(o.split("assert=")[1], a),
                 lambda o: o == "rc=0 assert=PASS"),
    # A clean PASS may legitimately carry no SARIF results, so no control check.
    "sarif": (_obs_sarif, lambda o, a, r: o.endswith("assertion_results=none"), None),
    "mcp_audit": (_obs_mcp_audit, _mcp_audit_bad,
                  lambda o: o.startswith("PASS/") and o.endswith("/coverage=complete")
                  and o.split("/")[1] != "seg_passed=0"),
    "mcp_compare": (_obs_mcp_compare, _mcp_compare_bad,
                    lambda o: o == "NO_NEW_RISK/audit=PASS"),
    "combine": (_obs_combine, _combine_bad,
                lambda o: o == "rc=0 verdict=PASS proven_line=True"),
    "hosted": (_obs_hosted, lambda o, a, r: o not in a, lambda o: o == "PASS"),
}


def _observe(surface, rel, pol, tmp_path):
    return _SURFACES[surface][0](_p(rel), pol, tmp_path)


# Red at e04630e, the head of #44 (the 0.4.1 fail-closed stopgap): (file,
# surface) -> the exact observation there. The stopgap clears every
# PASS-shaped cell. These 97 are left, all on two surfaces (93 on the
# round 1-3 files, as at 85c83fe, plus 4 on cfg4):
# - 49 mcp_audit `coverage=complete` on files that are UNKNOWN, or that are
#   not certifiable (design v2 section 3.1: complete means file-certified);
# - 48 sarif with no assertion result: an UNKNOWN run whose SARIF is empty
#   or holds only hygiene results.
# Slice 2 (design v4 section 12) turns all of them green. Each cell is a
# strict xfail in test_attack_surface and is pinned by test_red_cell_is_pinned.
_RED = {
    # cfg/a01_ios_no_ip_access_list_after_bind.cfg
    ('cfg/a01_ios_no_ip_access_list_after_bind.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a01_ios_no_ip_access_list_after_bind.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a03_ios_remark_only_acl.cfg
    ('cfg/a03_ios_remark_only_acl.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a03_ios_remark_only_acl.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a04_ios_description_holds_binding_text.cfg
    ('cfg/a04_ios_description_holds_binding_text.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a04_ios_description_holds_binding_text.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a05_ios_banner_delim_midline.cfg
    ('cfg/a05_ios_banner_delim_midline.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a05_ios_banner_delim_midline.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a06_ios_portchannel_member_binding.cfg
    ('cfg/a06_ios_portchannel_member_binding.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a06_ios_portchannel_member_binding.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a07_ios_subinterface_parent_binding.cfg
    ('cfg/a07_ios_subinterface_parent_binding.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a07_ios_subinterface_parent_binding.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a08_ios_alias_shutdown_reenable.cfg
    ('cfg/a08_ios_alias_shutdown_reenable.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a08_ios_alias_shutdown_reenable.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a09_ios_out_only_bindings_platform.cfg
    ('cfg/a09_ios_out_only_bindings_platform.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a09_ios_out_only_bindings_platform.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a10_ios_crlf_tab_in_deny.cfg
    ('cfg/a10_ios_crlf_tab_in_deny.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a10_ios_crlf_tab_in_deny.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a11_ios_excerpt_bytecount_mismatch.cfg
    ('cfg/a11_ios_excerpt_bytecount_mismatch.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a11_ios_excerpt_bytecount_mismatch.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/a12_ios_reach_urpf_inert_ruling.cfg
    ('cfg/a12_ios_reach_urpf_inert_ruling.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/a12_ios_reach_urpf_inert_ruling.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/g01_ios_accepted_violation_gate.cfg
    ('cfg/g01_ios_accepted_violation_gate.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/i01_iptables_exit_before_drop.sh
    ('cfg/i01_iptables_exit_before_drop.sh',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/i01_iptables_exit_before_drop.sh',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/n01_nxos_unlisted_admin_state.cfg
    ('cfg/n01_nxos_unlisted_admin_state.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/n01_nxos_unlisted_admin_state.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg/p01_panos_object_named_like_literal.set
    ('cfg/p01_panos_object_named_like_literal.set',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg/s01_asa_control_plane_binding.cfg
    ('cfg/s01_asa_control_plane_binding.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg/s01_asa_control_plane_binding.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_01_ios_version_contradicts_declared_release.cfg
    ('cfg2/r2_01_ios_version_contradicts_declared_release.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_01_ios_version_contradicts_declared_release.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_02_ios_svi_only_dialect_declared.cfg
    ('cfg2/r2_02_ios_svi_only_dialect_declared.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_02_ios_svi_only_dialect_declared.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_03_ios_svi_secondary_same_vlan.cfg
    ('cfg2/r2_03_ios_svi_secondary_same_vlan.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_03_ios_svi_secondary_same_vlan.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_04_ios_pacl_then_no_switchport.cfg
    ('cfg2/r2_04_ios_pacl_then_no_switchport.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_04_ios_pacl_then_no_switchport.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_05_ios_dynamic_default_port_both_modes.cfg
    ('cfg2/r2_05_ios_dynamic_default_port_both_modes.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_05_ios_dynamic_default_port_both_modes.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_06_ios_banner_single_line_close.cfg
    ('cfg2/r2_06_ios_banner_single_line_close.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_06_ios_banner_single_line_close.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_07_ios_banner_caret_literal.cfg
    ('cfg2/r2_07_ios_banner_caret_literal.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_07_ios_banner_caret_literal.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_08_ios_binding_name_case_folded.cfg
    ('cfg2/r2_08_ios_binding_name_case_folded.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_08_ios_binding_name_case_folded.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_09_ios_bytecount_within_tolerance_missing_iface.cfg
    ('cfg2/r2_09_ios_bytecount_within_tolerance_missing_iface.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg2/r2_09_ios_bytecount_within_tolerance_missing_iface.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg2/r2_10_ios_accepted_plus_unallowlisted_line.cfg
    ('cfg2/r2_10_ios_accepted_plus_unallowlisted_line.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/i07_iptables_heredoc_not_executed.sh
    ('cfg3/i07_iptables_heredoc_not_executed.sh',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/i07_iptables_heredoc_not_executed.sh',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/i11_iptables_function_never_called.sh
    ('cfg3/i11_iptables_function_never_called.sh',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/i11_iptables_function_never_called.sh',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/i16_iptables_conditional_drop.sh
    ('cfg3/i16_iptables_conditional_drop.sh',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/i16_iptables_conditional_drop.sh',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/i17_iptables_save_two_filter_blocks.rules
    ('cfg3/i17_iptables_save_two_filter_blocks.rules',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/i17_iptables_save_two_filter_blocks.rules',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/i18_iptables_save_invalid_line_aborts.rules
    ('cfg3/i18_iptables_save_invalid_line_aborts.rules',
     'sarif'): 'results=1 assertion_results=none',
    # cfg3/k04_junos_interface_range_unfiltered.conf
    ('cfg3/k04_junos_interface_range_unfiltered.conf',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/k04_junos_interface_range_unfiltered.conf',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/k05_junos_delete_annotation_binding.conf
    ('cfg3/k05_junos_delete_annotation_binding.conf',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k05_junos_delete_annotation_binding.conf',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/k10_junos_comment_holds_cisco_lines.conf
    ('cfg3/k10_junos_comment_holds_cisco_lines.conf',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k10_junos_comment_holds_cisco_lines.conf',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/k11_polyglot_ios_in_junos_comment.conf
    ('cfg3/k11_polyglot_ios_in_junos_comment.conf',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k11_polyglot_ios_in_junos_comment.conf',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/k12_polyglot_veto_dodging_forms.conf
    ('cfg3/k12_polyglot_veto_dodging_forms.conf',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k12_polyglot_veto_dodging_forms.conf',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/k13_junos_irb_both_zones_one_unit.conf
    ('cfg3/k13_junos_irb_both_zones_one_unit.conf',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k13_junos_irb_both_zones_one_unit.conf',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/k14_ios_banner_holds_junos.cfg
    ('cfg3/k14_ios_banner_holds_junos.cfg',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k14_ios_banner_holds_junos.cfg',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/k15_junos_pci_nexthop_on_corp_segment.conf
    ('cfg3/k15_junos_pci_nexthop_on_corp_segment.conf',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k15_junos_pci_nexthop_on_corp_segment.conf',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/k16_junos_coloc_masked_by_other_finding.conf
    ('cfg3/k16_junos_coloc_masked_by_other_finding.conf',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/k16_junos_coloc_masked_by_other_finding.conf',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/k17_junos_apply_groups_wildcard_unit.conf
    ('cfg3/k17_junos_apply_groups_wildcard_unit.conf',
     'sarif'): 'results=0 assertion_results=none',
    # cfg3/k18_junos_replace_tag_subtree_save.conf
    ('cfg3/k18_junos_replace_tag_subtree_save.conf',
     'sarif'): 'results=2 assertion_results=none',
    ('cfg3/k18_junos_replace_tag_subtree_save.conf',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/k19_junos_inactive_binding.conf
    ('cfg3/k19_junos_inactive_binding.conf',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/k19_junos_inactive_binding.conf',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg3/p02_panos_rule_type_interzone_deny.set
    ('cfg3/p02_panos_rule_type_interzone_deny.set',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/p02_panos_rule_type_interzone_deny.set',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/p04_panos_move_rule_top.set
    ('cfg3/p04_panos_move_rule_top.set',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/p04_panos_move_rule_top.set',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/p06_panos_shared_object_shadowed.set
    ('cfg3/p06_panos_shared_object_shadowed.set',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/p06_panos_shared_object_shadowed.set',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/p08_panos_dnat_prenat_destination.set
    ('cfg3/p08_panos_dnat_prenat_destination.set',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/p08_panos_dnat_prenat_destination.set',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/p11_panos_list_attr_set_twice.set
    ('cfg3/p11_panos_list_attr_set_twice.set',
     'sarif'): 'results=1 assertion_results=none',
    ('cfg3/p11_panos_list_attr_set_twice.set',
     'mcp_audit'): 'FAIL/seg_passed=0/coverage=complete',
    # cfg3/p14_panos_pci_nexthop_on_corp_segment.set
    ('cfg3/p14_panos_pci_nexthop_on_corp_segment.set',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg3/p14_panos_pci_nexthop_on_corp_segment.set',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg4/p17_panos_default_route_via_corp_segment.set
    ('cfg4/p17_panos_default_route_via_corp_segment.set',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg4/p17_panos_default_route_via_corp_segment.set',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
    # cfg4/p18_panos_recursive_nexthop_via_corp_segment.set
    ('cfg4/p18_panos_recursive_nexthop_via_corp_segment.set',
     'sarif'): 'results=0 assertion_results=none',
    ('cfg4/p18_panos_recursive_nexthop_via_corp_segment.set',
     'mcp_audit'): 'UNKNOWN/seg_passed=0/coverage=complete',
}

# Red boundary cells: (file, --vendor) -> the exact observation. None at
# e04630e: the stopgap never gives a gate PASS, under any --vendor value. The
# 32 cells that were red on the #42 engine (49c4e89) are green here.
_RED_B: dict = {}


# The B boundary (design v3 section 1.2, review r3 H1): every Cisco-family
# attack file, and the Junos files that carry IOS lines in a comment (k10,
# k11, k12) or the reverse (k14), run through the gate under every --vendor
# value. None may PASS: not the gate verdict and not the assertion.
_B_FILES = tuple(sorted(
    [r for r in _ATTACKS if r.startswith(("cfg/", "cfg2/"))
     and any(t in r for t in ("_ios_", "_nxos_", "_asa_"))]
    + [f"cfg3/{n}" for n in ("k10_junos_comment_holds_cisco_lines.conf",
                             "k11_polyglot_ios_in_junos_comment.conf",
                             "k12_polyglot_veto_dodging_forms.conf",
                             "k14_ios_banner_holds_junos.cfg")]))
_VENDORS = ("auto", "ios-asa", "nxos", "eos", "junos", "panos", "iptables", "aws-sg")


def _obs_boundary(rel, vendor):
    pol, _ = _ATTACKS[rel]
    gate = g.run_gate([_p(rel)], _policy(pol), fail_on="high", vendor=vendor)
    return f"{gate.verdict}/assert={_assertion_of(json.loads(g.to_json(gate)))}"


def _boundary_bad(obs):
    v, a = obs.split("/")
    return v in ("PASS", "ACCEPTED") or "PASS" in a[len("assert="):].split(",")


# Non-assertion findings each attack file carries, counted per kind (review
# r3 M5 lint; counts per review v4 delta R4-L3). Counts are as at e04630e;
# the kinds are the same as on the #42 engine at 49c4e89. Each one belongs
# to the file's review row:
# - permit-any-any: the row's trailing allow-all, which turns a lost deny
#   into reach (k16 adds it to k13 on purpose, as the masking probe);
# - intent-inversion-deny-dead: the attacked deny, shown dead;
# - redundant: k18's `replace:` subtree.
# Any other finding fails test_attack_file_carries_no_second_finding.
# Because the exit-code predicates read the assertion, these findings no
# longer hide a false PASS (k16, k18, p11).
_ROW_FINDINGS = {
    'cfg/a02_ios_seq_reorder_permit_first.cfg': {'intent-inversion-deny-dead': 1},
    'cfg/p01_panos_object_named_like_literal.set': {'intent-inversion-deny-dead': 1},
    'cfg3/i02_iptables_goto_falls_to_policy.sh': {'permit-any-any': 1},
    'cfg3/i03_iptables_limit_on_drop.sh': {'permit-any-any': 1},
    'cfg3/i04_iptables_return_in_user_chain.sh': {'permit-any-any': 1},
    'cfg3/i05_iptables_policy_twice.sh': {'permit-any-any': 1},
    'cfg3/i07_iptables_heredoc_not_executed.sh': {'permit-any-any': 1},
    'cfg3/i08_iptables_fragment_only_drop.sh': {'permit-any-any': 1},
    'cfg3/i10_iptables_lowercase_chain.sh': {'permit-any-any': 1},
    'cfg3/i11_iptables_function_never_called.sh': {'permit-any-any': 1},
    'cfg3/i12_iptables_time_window_drop.sh': {'permit-any-any': 1},
    'cfg3/i14_iptables_insert_accept_top.sh': {'intent-inversion-deny-dead': 1},
    'cfg3/i15_iptables_shell_var_reassigned.sh': {'permit-any-any': 1},
    'cfg3/i16_iptables_conditional_drop.sh': {'permit-any-any': 1},
    'cfg3/i17_iptables_save_two_filter_blocks.rules': {'permit-any-any': 3},
    'cfg3/i18_iptables_save_invalid_line_aborts.rules': {'permit-any-any': 2},
    'cfg3/i19_iptables_iprange_partial.sh': {'permit-any-any': 1},
    'cfg3/k01_junos_count_only_term.conf': {'intent-inversion-deny-dead': 1},
    'cfg3/k02_junos_noncontiguous_mask.conf': {'permit-any-any': 1},
    'cfg3/k03_junos_dscp_narrowed_deny.conf': {'permit-any-any': 1},
    'cfg3/k04_junos_interface_range_unfiltered.conf': {'permit-any-any': 1},
    'cfg3/k06_junos_apply_path_prefix_list.conf': {'permit-any-any': 1},
    'cfg3/k07_junos_prefix_list_except.conf': {'permit-any-any': 1},
    'cfg3/k08_junos_set_deactivate_term.set': {'permit-any-any': 1},
    'cfg3/k09_junos_policer_term.conf': {'permit-any-any': 1},
    'cfg3/k16_junos_coloc_masked_by_other_finding.conf': {'permit-any-any': 1},
    'cfg3/k18_junos_replace_tag_subtree_save.conf': {'permit-any-any': 1, 'redundant': 1},
    'cfg3/p02_panos_rule_type_interzone_deny.set': {'permit-any-any': 1},
    'cfg3/p04_panos_move_rule_top.set': {'permit-any-any': 1},
    'cfg3/p05_panos_vsys_split_rulebase.set': {'permit-any-any': 2},
    'cfg3/p06_panos_shared_object_shadowed.set': {'permit-any-any': 1},
    'cfg3/p07_panos_ip_range_partial.set': {'permit-any-any': 1},
    'cfg3/p08_panos_dnat_prenat_destination.set': {'permit-any-any': 1},
    'cfg3/p09_panos_zone_defined_twice.set': {'permit-any-any': 1},
    'cfg3/p11_panos_list_attr_set_twice.set': {'permit-any-any': 1},
    'cfg3/p12_panos_post_rulebase_before_local.set': {'permit-any-any': 1},
    'cfg3/p13_panos_edl_source.set': {'permit-any-any': 1},
    'cfg3/p15_panos_disabled_deny.set': {'permit-any-any': 1},
    'cfg3/p16_panos_negate_source_deny.set': {'permit-any-any': 1},
}


def _id(rel, surface):
    parts = os.path.basename(rel).split("_")
    head = "_".join(parts[:2]) if rel.startswith("cfg2/") else parts[0]
    return f"{head}-{surface}"


def _attack_params():
    for rel in sorted(_ATTACKS):
        for s in _SURFACES:
            marks = ([pytest.mark.xfail(strict=True, raises=AssertionError,
                                        reason=f"red today: {_RED[(rel, s)]}")]
                     if (rel, s) in _RED else [])
            yield pytest.param(rel, s, marks=marks, id=_id(rel, s))


def _boundary_params():
    for rel in _B_FILES:
        for v in _VENDORS:
            marks = ([pytest.mark.xfail(strict=True, raises=AssertionError,
                                        reason=f"red today: {_RED_B[(rel, v)]}")]
                     if (rel, v) in _RED_B else [])
            yield pytest.param(rel, v, marks=marks, id=_id(rel, f"vendor_{v}"))


def test_fixture_dirs_hold_exactly_the_listed_files():
    listed = set(_ATTACKS) | set(_CONTROLS) | set(_MAY_PASS)
    for sub in ("cfg", "cfg2", "cfg3", "cfg4", "controls"):
        on_disk = {f"{sub}/{n}" for n in os.listdir(os.path.join(_D, sub))}
        want = {k for k in listed if k.startswith(sub + "/")}
        assert on_disk == want, sorted(on_disk ^ want)


def test_red_cells_are_real_cells():
    for rel, s in _RED:
        assert rel in _ATTACKS and s in _SURFACES, (rel, s)
    for rel, v in _RED_B:
        assert rel in _B_FILES and v in _VENDORS, (rel, v)
    assert _CERTIFIABLE_FAIL <= set(_ATTACKS)
    for rel in _STOPGAP_MAY_PASS:
        assert _MAY_PASS[rel][1] == {"PASS"}, rel


@pytest.mark.parametrize("rel,surface", list(_attack_params()))
def test_attack_surface(rel, surface, tmp_path):
    pol, allowed = _ATTACKS[rel]
    obs = _observe(surface, rel, pol, tmp_path)
    assert not _SURFACES[surface][1](obs, allowed, rel), (rel, surface, obs)


@pytest.mark.parametrize("rel,surface", sorted(_RED), ids=[_id(*k) for k in sorted(_RED)])
def test_red_cell_is_pinned(rel, surface, tmp_path):
    """Today's exact wrong observation. When phase 2 changes it, this test
    fails along with the strict xfail, and both go when the cell leaves _RED."""
    pol, _ = _ATTACKS[rel]
    assert _observe(surface, rel, pol, tmp_path) == _RED[(rel, surface)]


@pytest.mark.parametrize("rel,vendor", list(_boundary_params()))
def test_b_boundary(rel, vendor):
    obs = _obs_boundary(rel, vendor)
    assert not _boundary_bad(obs), (rel, vendor, obs)


@pytest.mark.parametrize("rel,vendor", sorted(_RED_B),
                         ids=[_id(r, f"vendor_{v}") for r, v in sorted(_RED_B)])
def test_b_boundary_red_cell_is_pinned(rel, vendor):
    assert _obs_boundary(rel, vendor) == _RED_B[(rel, vendor)]


@pytest.mark.parametrize("rel", sorted(_ATTACKS), ids=lambda r: _id(r, "findings"))
def test_attack_file_carries_no_second_finding(rel):
    # Counts per kind, not a set of kinds (review v4 delta, R4-L3): a second
    # finding of a kind the row already has must fail too.
    pol, _ = _ATTACKS[rel]
    d = json.loads(g.to_json(g.run_gate([_p(rel)], _policy(pol), fail_on="high")))
    kinds = collections.Counter(x["kind"] for f in d["files"] for x in f["findings"]
                                if not x["kind"].startswith(_ASSERTION_KINDS))
    assert dict(kinds) == _ROW_FINDINGS.get(rel, {}), (rel, dict(kinds))


# Under #44's stopgap no surface emits PASS (0.4.1), so the tests that need
# one are strict xfails until slice 9 (design v4, section 12) restores PASS
# where a certificate holds. A crash still fails (raises=AssertionError).
_STOPGAP_XFAIL = pytest.mark.xfail(strict=True, raises=AssertionError,
                                   reason="stopgap: no PASS")

# What those tests see under the stopgap, pinned so the xfail cannot absorb
# a different wrong answer (review round 2, M10). Every control gives the same
# observation per surface. i09's verdict is pinned as "verdict", and the
# controls' gate verdict under --vendor auto as "boundary".
_STOPGAP_CONTROL = {
    "cli_json": "UNKNOWN",
    "cli_text": "rc=3 pass_line=False",
    "cli_evidence": "INDETERMINATE",
    "gate_critical": "UNKNOWN/passed=False/json_passed=False/exit=3/check_mark=False/assert=UNKNOWN",
    "gate_high": "UNKNOWN/passed=False/json_passed=False/exit=3/check_mark=False/assert=UNKNOWN",
    "gate_medium": "UNKNOWN/passed=False/json_passed=False/exit=3/check_mark=False/assert=UNKNOWN",
    "gate_low": "UNKNOWN/passed=False/json_passed=False/exit=3/check_mark=False/assert=UNKNOWN",
    "gate_none": "UNKNOWN/passed=False/json_passed=False/exit=0/check_mark=False/assert=UNKNOWN",
    "gate_cli": "rc=3 assert=UNKNOWN",
    "mcp_audit": "UNKNOWN/seg_passed=0/coverage=complete",
    "mcp_compare": "UNKNOWN/audit=UNKNOWN",
    "combine": "rc=2 verdict=UNKNOWN proven_line=False",
    "hosted": "UNKNOWN",
    "boundary": "UNKNOWN/assert=UNKNOWN",
    "verdict": "UNKNOWN",
}
# _MAY_PASS files whose PASS verdict is an xfail under the stopgap (i09).
# Slice 9 empties this set; i09's allowed verdicts stay {"PASS"}.
_STOPGAP_MAY_PASS = frozenset({"cfg3/i09_iptables_restore_noflush.rules"})


def _control_params():
    for r in sorted(_CONTROLS):
        for s in _SURFACES:
            if _SURFACES[s][2] is not None:
                yield pytest.param(r, s, id=f"{os.path.basename(r).split('_')[0]}-{s}")


@pytest.mark.parametrize("rel", [
    pytest.param(r, marks=[_STOPGAP_XFAIL] if r in _STOPGAP_MAY_PASS else [],
                 id=_id(r, "verdict")) for r in sorted(_MAY_PASS)])
def test_may_pass_file_verdict(rel, tmp_path):
    pol, allowed = _MAY_PASS[rel]
    for s in ("cli_json", "hosted"):
        obs = _observe(s, rel, pol, tmp_path)
        assert obs in allowed, (rel, s, obs)


@pytest.mark.parametrize("rel", sorted(_STOPGAP_MAY_PASS), ids=lambda r: _id(r, "verdict"))
def test_may_pass_stopgap_verdict_is_pinned(rel, tmp_path):
    pol, _ = _MAY_PASS[rel]
    for s in ("cli_json", "hosted"):
        assert _observe(s, rel, pol, tmp_path) == _STOPGAP_CONTROL["verdict"], (rel, s)


@_STOPGAP_XFAIL
@pytest.mark.parametrize("rel,surface", list(_control_params()))
def test_positive_control_is_all_clear(rel, surface, tmp_path):
    obs = _observe(surface, rel, _CONTROLS[rel], tmp_path)
    assert _SURFACES[surface][2](obs), (rel, surface, obs)


@pytest.mark.parametrize("rel,surface", list(_control_params()))
def test_positive_control_stopgap_observation_is_pinned(rel, surface, tmp_path):
    assert _observe(surface, rel, _CONTROLS[rel], tmp_path) == _STOPGAP_CONTROL[surface]


@_STOPGAP_XFAIL
@pytest.mark.parametrize("rel,vendor", [(r, "auto") for r in sorted(_CONTROLS)],
                         ids=lambda x: str(x))
def test_positive_control_boundary(rel, vendor):
    assert _obs_boundary_control(rel, vendor) == "PASS/assert=PASS"


@pytest.mark.parametrize("rel", sorted(_CONTROLS), ids=lambda x: str(x))
def test_positive_control_boundary_stopgap_is_pinned(rel):
    assert _obs_boundary_control(rel, "auto") == _STOPGAP_CONTROL["boundary"]


def _obs_boundary_control(rel, vendor):
    gate = g.run_gate([_p(rel)], _policy(_CONTROLS[rel]), fail_on="high", vendor=vendor)
    return f"{gate.verdict}/assert={_assertion_of(json.loads(g.to_json(gate)))}"


@pytest.mark.skipif(os.environ.get("RULEHAWK_PHASE3_GATE") != "1",
                    reason="phase-3 gate only (design v3, section 9)")
def test_phase3_gate_no_red_cell_left():
    assert not _RED and not _RED_B, (sorted(_RED), sorted(_RED_B))
    # Slice 9 removes the stopgap xfails (_STOPGAP_CONTROL, _STOPGAP_MAY_PASS)
    # along with the stopgap.
    assert not _STOPGAP_CONTROL and not _STOPGAP_MAY_PASS


# --------------------------------------------------------------------------- #
# The safety net itself fails closed (review of #46: M1, L1, L2).
# --------------------------------------------------------------------------- #
def _one_finding(kind, verdict=None):
    return {"files": [{"findings": [{"kind": kind, "verdict": verdict}]}]}


@pytest.mark.parametrize("kind,verdict", [
    ("segmentation-certified", None), ("segmentation-certified", "UNKNOWN"),
    ("segmentation-pass", None), ("segmentation-accepted", "UNKNOWN"),
    ("connectivity-proven", None),
])
def test_assertion_reader_rejects_an_unrecognised_kind(kind, verdict):
    """M1: a new assertion kind reads as a value no allowed set holds, never
    as UNKNOWN, whatever verdict it carries."""
    a = _assertion_of(_one_finding(kind, verdict))
    assert a.startswith("UNRECOGNISED:"), a
    for allowed in ({"UNKNOWN"}, {"FAIL", "UNKNOWN"}, {"FAIL"}):
        assert _assert_bad(a, allowed)


@pytest.mark.parametrize("kind,verdict", [
    ("segmentation-unknown", "PASS"), ("segmentation-violation", "PASS"),
    ("segmentation-indeterminate", "ACCEPTED"), ("connectivity-broken", "UNKNOWN"),
    ("segmentation-ok", "UNKNOWN"),
])
def test_assertion_reader_rejects_a_verdict_that_disagrees_with_its_kind(kind, verdict):
    a = _assertion_of(_one_finding(kind, verdict))
    assert a.startswith("MISMATCH:"), a
    assert _assert_bad(a, {"FAIL", "UNKNOWN"})


@pytest.mark.parametrize("kind,verdict,want", [
    ("segmentation-unknown", "UNKNOWN", "UNKNOWN"),
    ("segmentation-indeterminate", None, "UNKNOWN"),
    ("segmentation-violation", None, "FAIL"),
    ("segmentation-violation", "FAIL", "FAIL"),
    ("connectivity-broken", None, "FAIL"),
    ("segmentation-ok", None, "PASS"),
    ("segmentation-ok", "PASS", "PASS"),
])
def test_assertion_reader_reads_known_kinds(kind, verdict, want):
    assert _assertion_of(_one_finding(kind, verdict)) == want


def test_every_engine_assertion_kind_is_in_the_reader_table():
    """A kind the engine can emit must be in _KIND_VERDICT or
    _UNDECIDED_KINDS, so the reader never meets one by surprise."""
    import ast
    known = set(_KIND_VERDICT) | _UNDECIDED_KINDS
    help_kinds = {k for k in g._KIND_HELP if k.startswith(_ASSERTION_KINDS)}
    assert help_kinds <= known, sorted(help_kinds - known)
    pkg = os.path.join(_ROOT, "rulehawk")
    lit = set()
    for n in sorted(os.listdir(pkg)):
        if n.endswith(".py"):
            tree = ast.parse(open(os.path.join(pkg, n), encoding="utf-8").read())
            lit |= {x.value for x in ast.walk(tree)
                    if isinstance(x, ast.Constant) and isinstance(x.value, str)
                    and x.value.startswith(_ASSERTION_KINDS)
                    and x.value.replace("-", "").isalpha() and x.value.islower()}
    assert lit <= known, sorted(lit - known)


def test_sarif_ok_result_on_an_attack_file_is_bad(monkeypatch, tmp_path):
    """L1: an `-ok` result in an attack file's SARIF is a PASS claim on that
    surface, even next to a violation."""
    rel = "cfg/a02_ios_seq_reorder_permit_first.cfg"
    real = g.to_sarif

    def plus_ok(gate, version=None):
        s = json.loads(real(gate, version))
        r = dict(s["runs"][0]["results"][0])
        r["ruleId"] = "segmentation-ok"
        s["runs"][0]["results"].append(r)
        return json.dumps(s)

    pol, allowed = _ATTACKS[rel]
    before = _observe("sarif", rel, pol, tmp_path)
    assert not _SURFACES["sarif"][1](before, allowed, rel), before
    monkeypatch.setattr(g, "to_sarif", plus_ok)
    after = _observe("sarif", rel, pol, tmp_path)
    assert _SURFACES["sarif"][1](after, allowed, rel), after


def test_sarif_observation_counts_results_not_rule_ids(monkeypatch, tmp_path):
    rel = "cfg/a02_ios_seq_reorder_permit_first.cfg"
    real = g.to_sarif

    def twice(gate, version=None):
        s = json.loads(real(gate, version))
        s["runs"][0]["results"] = s["runs"][0]["results"] * 2
        return json.dumps(s)

    pol, _ = _ATTACKS[rel]
    before = _observe("sarif", rel, pol, tmp_path)
    monkeypatch.setattr(g, "to_sarif", twice)
    assert _observe("sarif", rel, pol, tmp_path) != before


def test_red_sets_stay_within_the_stopgap():
    """L2: under the stopgap no boundary cell is red, and every red cell is
    on the two surfaces slice 2 turns green. Widening either is an edit here."""
    assert not _RED_B, sorted(_RED_B)
    assert {s for _, s in _RED} <= {"sarif", "mcp_audit"}, sorted({s for _, s in _RED})
