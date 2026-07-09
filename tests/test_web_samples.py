"""Honest-confidence guard for the web tool's multi-vendor sample gallery.

docs/index.html advertises six vendors and ships a one-click "Load a sample"
gallery (Cisco IOS/ASA, Juniper Junos, Linux iptables, Cisco NX-OS). Each button
pre-fills a config whose caption PROMISES a specific finding. The lead-magnet
pitch collapses the moment a caption over-promises — a prospect who loads the
Junos sample and sees nothing will never forward the tool.

So this test extracts the actual `const SAMPLE_*` strings straight out of the
shipped HTML and runs each through the SAME vendor-dispatch + analysis the page
runs in-browser (mirrors the ANALYZE_PY block in index.html and gate._pick_parser),
asserting every advertised finding is really emitted. If someone edits a sample
and breaks its promised finding, this fails instead of shipping a lie.
"""

from __future__ import annotations

import json
import os
import re

import pytest

from rulehawk.analyze import analyze
from rulehawk.parse import parse_acls
from rulehawk.parse_junos import detect as detect_junos, parse_junos
from rulehawk.parse_panos import detect as detect_panos, parse_panos
from rulehawk.parse_iptables import detect as detect_iptables, parse_iptables
from rulehawk.parse_nxos import detect as detect_nxos, parse_nxos
from rulehawk.parse_eos import detect as detect_eos, parse_eos
from rulehawk.segcheck import check_segmentation

_INDEX_HTML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "index.html"
)


def _extract_const(name: str) -> str:
    """Pull a `const NAME = \\`...\\`;` template-literal value out of index.html.

    The samples deliberately contain no backticks, so a non-greedy match to the
    next backtick is exact.
    """
    html = open(_INDEX_HTML, encoding="utf-8").read()
    m = re.search(r"const\s+" + re.escape(name) + r"\s*=\s*`([^`]*)`", html)
    assert m, f"{name} not found in docs/index.html"
    return m.group(1)


def _route_and_analyze(cfg: str, policy_str: str):
    """Same dispatch order as index.html's ANALYZE_PY / gate._pick_parser."""
    if detect_junos(cfg):
        vendor, (aces, _notes) = "Juniper Junos", parse_junos(cfg)
    elif detect_panos(cfg):
        vendor, (aces, _notes) = "Palo Alto PAN-OS", parse_panos(cfg)
    elif detect_iptables(cfg):
        vendor, (aces, _notes) = "Linux iptables", parse_iptables(cfg)
    elif detect_nxos(cfg):
        vendor, (aces, _notes) = "Cisco NX-OS", parse_nxos(cfg)
    elif detect_eos(cfg):
        vendor, (aces, _notes) = "Arista EOS", parse_eos(cfg)
    else:
        vendor, (aces, _notes) = "Cisco IOS / ASA", parse_acls(cfg)
    findings = list(analyze(aces))
    if policy_str.strip():
        findings += list(check_segmentation(aces, json.loads(policy_str)))
    return vendor, findings


@pytest.fixture(scope="module")
def policy() -> str:
    return _extract_const("SAMPLE_POLICY")


def _kinds(findings):
    return {f.kind for f in findings}


def _seg_witness(findings):
    viol = [f for f in findings if f.kind == "segmentation-violation"]
    assert viol, "expected a segmentation-violation with a witness packet"
    return viol[0]


def test_ios_sample_routes_and_finds(policy):
    vendor, findings = _route_and_analyze(_extract_const("SAMPLE_ACL"), policy)
    assert vendor == "Cisco IOS / ASA"
    assert "permit-any-any" in _kinds(findings)         # advertised
    assert ":445" in _seg_witness(findings).witness      # CORP->PCI:445 witness


def test_junos_sample_routes_and_finds(policy):
    vendor, findings = _route_and_analyze(_extract_const("SAMPLE_JUNOS"), policy)
    assert vendor == "Juniper Junos"                     # NOT misrouted to IOS
    w = _seg_witness(findings)
    assert ":445" in w.witness and w.severity == "critical"
    # caption promises "a term shadowed by the default discard"
    assert "intent-inversion-permit-dead" in _kinds(findings)


def test_iptables_sample_routes_and_finds(policy):
    vendor, findings = _route_and_analyze(_extract_const("SAMPLE_IPTABLES"), policy)
    assert vendor == "Linux iptables"
    # caption promises the FORWARD leak CORP->PCI on 445
    w = _seg_witness(findings)
    assert ":445" in w.witness and w.severity == "critical"


def test_nxos_sample_routes_and_finds(policy):
    vendor, findings = _route_and_analyze(_extract_const("SAMPLE_NXOS"), policy)
    assert vendor == "Cisco NX-OS"                       # NOT misrouted to IOS
    w = _seg_witness(findings)
    assert ":445" in w.witness and w.severity == "critical"
    # caption promises "a permit killed by an earlier deny-any"
    assert "intent-inversion-permit-dead" in _kinds(findings)


def test_every_gallery_button_maps_to_a_defined_sample():
    """Guard the wiring: each data-sample key in the HTML has a SAMPLES entry
    with a config, and every SAMPLES config is reachable from a button."""
    html = open(_INDEX_HTML, encoding="utf-8").read()
    btn_keys = set(re.findall(r'data-sample="([^"]+)"', html))
    assert btn_keys == {"ios", "junos", "iptables", "nxos"}
    # SAMPLES map object keys
    block = re.search(r"const SAMPLES\s*=\s*\{(.*?)\n\};", html, re.S).group(1)
    map_keys = set(re.findall(r"(\w+):\s*\{\s*cfg:", block))
    assert btn_keys == map_keys, f"button keys {btn_keys} != SAMPLES keys {map_keys}"
