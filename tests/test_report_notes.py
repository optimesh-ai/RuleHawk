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

# 25 object-group lines: each is recognized as an ACE but not fully modeled,
# so each becomes a parse note. 25 > the old cap of 20.
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
    # n_rules==0 here (all 25 lines are unmodeled), exercising the no-rules branch.
    text = to_text([], notes, len(aces))
    shown = text.count("unmodeled (object-group)")
    assert shown == 25, f"expected all 25 notes printed, got {shown}"
    # The header count must match what's actually shown — no lying.
    assert "Parse notes (25)" in text


def test_text_report_elides_with_explicit_pointer_past_cap():
    # Far past the cap: we may elide, but must say how many and where to look —
    # never a silent drop.
    notes = [f"unmodeled (object-group): line {i}" for i in range(500)]
    text = to_text([], notes, 0)
    assert "and " in text and "more not shown" in text
    assert "--json" in text  # tells the user how to get the complete list
