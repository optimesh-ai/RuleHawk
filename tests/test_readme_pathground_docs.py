"""README must document the Hammerhead path-grounding feature.

Guards the doc fix for the "flagship feature invisible outside cli.py" gap:
the `--hh-snapshot`/`--hh-from` flags, the fail-closed soundness rule, and the
`rulehawk/pathground.py` module must all be discoverable from README.md. If a
future edit drops them, this test fails rather than letting the docs silently
regress to "feature only visible in shell history".
"""

from __future__ import annotations

import pathlib
import re

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"


def _readme_text() -> str:
    return README.read_text(encoding="utf-8")


def test_readme_exists() -> None:
    assert README.is_file(), f"README missing at {README}"


def test_readme_documents_pathground_flags() -> None:
    text = _readme_text()
    assert "--hh-snapshot" in text, "README must document --hh-snapshot"
    assert "--hh-from" in text, "README must document --hh-from"
    # A copy-pasteable usage line pairing both flags with --policy.
    assert re.search(
        r"--policy\s+\S+\s+--hh-snapshot\s+\S+\s+--hh-from\s+\S+", text
    ), "README must show a usage line combining --policy/--hh-snapshot/--hh-from"


def test_readme_states_fail_closed_soundness_rule() -> None:
    """The soundness contract from cli.py's docstring must be user-visible:
    only a deterministic NAT-free 'not delivered' downgrades; everything else
    fails closed and keeps the finding."""
    text = _readme_text()
    lower = text.lower()
    # Locate the path-grounding section specifically, not the general
    # fail-closed language elsewhere in the README.
    m = re.search(r"path[- ]ground", lower)
    assert m, "README must have a path-grounding section"
    section = lower[m.start():m.start() + 2000]
    assert "not delivered" in section, (
        "path-grounding section must state that only a 'not delivered' "
        "verdict downgrades a finding"
    )
    assert "nat" in section, (
        "path-grounding section must mention the NAT fail-closed condition"
    )
    assert "fail closed" in section or "fails closed" in section or \
        "fail-closed" in section, (
        "path-grounding section must state the fail-closed rule"
    )


def test_readme_layout_lists_pathground_module() -> None:
    text = _readme_text()
    assert "rulehawk/pathground.py" in text, (
        "README Layout section must list rulehawk/pathground.py"
    )
