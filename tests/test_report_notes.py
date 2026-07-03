"""Soundness regression: the text report must SURFACE every parse note, never
silently drop unmodeled lines. The old hard `[:20]` truncation hid most notes on
large real-world configs (hundreds of object-group lines) while the header still
claimed the full count — a quiet violation of "surface, never drop"."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import parse_acls, to_json, to_text  # noqa: E402

# 25 object-group lines: each is recognized as an ACE but not fully modeled, so
# each becomes a parse note (AND a fail-closed opaque ACE — see the soundness
# audit). 25 > the old cap of 20, so this still exercises note non-truncation.
_CONFIG = "ip access-list extended TEST\n" + "\n".join(
    f" permit tcp object-group GRP{i} any eq 80" for i in range(1, 26))


def test_all_notes_present_in_json():
    _, notes = parse_acls(_CONFIG)
    assert len(notes) == 25
    doc = json.loads(to_json([], notes, 0))
    assert len(doc["parse_notes"]) == 25  # JSON is always complete


def test_text_report_does_not_silently_drop_notes():
    aces, notes = parse_acls(_CONFIG)
    assert len(notes) == 25
    text = to_text([], notes, len(aces))
    shown = text.count("unmodeled (object-group)")
    assert shown == 25, f"expected all 25 notes printed, got {shown}"
    # The header count must match what's actually shown — no lying.
    assert f"Parse notes ({len(notes)} line(s)" in text


def test_text_report_elides_with_explicit_pointer_past_cap():
    # Far past the cap: we may elide, but must say how many and where to look —
    # never a silent drop.
    notes = [f"unmodeled (object-group): line {i}" for i in range(500)]
    text = to_text([], notes, 0)
    assert "and " in text and "more not shown" in text
    assert "--json" in text  # tells the user how to get the complete list


# --- Segmentation witness packet in the CLI text report ------------------
# The witness is the concrete provable packet (segcheck's whole promise:
# "every violation is a real packet an auditor can verify"). Every other
# surface (JSON, SARIF, step summary, PR comment) shows it; the day-1 CLI
# text report must too.

from rulehawk.analyze import Finding  # noqa: E402


def _seg_finding(**kw):
    base = dict(
        rule_id="ACL:10",
        kind="segmentation",
        severity="critical",
        message=("SEGMENTATION VIOLATION: policy forbids guest -> pci, but "
                 "rule PERMITS 10.20.0.1 -> 10.10.0.1:445"),
        rule="permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445",
        cited="policy: deny guest -> pci",
        fix="deny tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445",
        witness="10.20.0.1 -> 10.10.0.1:445 (tcp)",
        line=12,
    )
    base.update(kw)
    return Finding(**base)


def test_text_report_shows_witness_packet():
    text = to_text([_seg_finding()], [], 5)
    assert "   pkt  : 10.20.0.1 -> 10.10.0.1:445 (tcp)" in text
    # It must sit alongside the rest of the finding block, not replace anything.
    assert "   rule : " in text
    assert "   cause: " in text
    assert "   why  : " in text
    assert "   fix  : " in text


def test_text_report_omits_pkt_line_when_no_witness():
    # Non-segmentation findings (witness == "") must not grow an empty pkt line.
    text = to_text([_seg_finding(witness="", kind="shadowed", severity="high")],
                   [], 5)
    assert "pkt  :" not in text


def test_json_still_carries_witness():
    # Guard the existing JSON surface: additive change must not regress it.
    doc = json.loads(to_json([_seg_finding()], [], 5))
    assert doc["findings"][0]["witness"] == "10.20.0.1 -> 10.10.0.1:445 (tcp)"
