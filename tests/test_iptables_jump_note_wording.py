"""Regression: the custom-chain jump parse note must not contradict the
precision-resolution note (BUILD packet 29).

Before the fix, `add_rule` unconditionally appended a note saying the sub-chain
effect was "not modeled ... verify the chain manually", while the post-parse
precision pass appended "resolved precisely — N ACE(s) emitted" for the SAME
jump. A user auditing a Docker/Kubernetes-style iptables-save saw two directly
contradictory notes and could not tell whether RuleHawk modeled their chain.

The note now states the actual behavior: transit-path jumps are resolved
precisely when the target chain is fully modeled, otherwise kept indeterminate
(fail-closed); host INPUT/OUTPUT jumps are surfaced only. These tests pin that
the contradictory phrasing is gone in every outcome while the load-bearing
substrings ("custom chain" + backticked chain name) survive.
"""

from rulehawk.parse_iptables import parse_iptables

# Contradictory claims the jump note must never make again: the parser DOES
# model fully-provable transit jumps, and never asks for a manual review of a
# chain it resolved precisely.
_STALE_PHRASES = ("not modeled", "verify the chain manually", "flatten or verify")


_RESOLVED_CFG = (
    "*filter\n"
    ":INPUT DROP [0:0]\n"
    ":FORWARD DROP [0:0]\n"
    ":CROSSZONE - [0:0]\n"
    "-A FORWARD -j CROSSZONE\n"
    "-A CROSSZONE -s 10.20.0.0/16 -d 10.10.0.0/16 -p tcp --dport 445 -j ACCEPT\n"
    "COMMIT\n"
)

_UNRESOLVED_CFG = (
    "*filter\n"
    ":FORWARD DROP [0:0]\n"
    "-A FORWARD -s 10.20.0.0/16 -j MISSING_CHAIN\n"
    "COMMIT\n"
)

_HOST_HOOK_CFG = (
    "*filter\n"
    ":INPUT DROP [0:0]\n"
    ":SSHGUARD - [0:0]\n"
    "-A INPUT -p tcp --dport 22 -j SSHGUARD\n"
    "-A SSHGUARD -s 192.0.2.0/24 -j ACCEPT\n"
    "COMMIT\n"
)


def _jump_notes(notes, chain):
    return [n for n in notes if "custom chain" in n and f"`-j {chain}`" in n]


def test_resolved_jump_notes_are_not_contradictory():
    """A fully-modeled transit jump gets BOTH the surface note and the
    'resolved precisely' note — and the surface note must no longer claim the
    chain is unmodeled / needs manual review."""
    _, notes = parse_iptables(_RESOLVED_CFG)
    jn = _jump_notes(notes, "CROSSZONE")
    assert jn, "jump must still be surfaced (never an invisible hole)"
    for n in jn:
        for phrase in _STALE_PHRASES:
            assert phrase not in n, (
                f"jump note contradicts precision resolution: {phrase!r} in {n!r}")
    assert any("resolved precisely" in n and "CROSSZONE" in n for n in notes)


def test_unresolved_jump_note_states_fail_closed_not_manual_flatten():
    """An unprovable jump (absent chain) keeps the fail-closed placeholder; the
    note must say so honestly without the stale 'not modeled' wording."""
    _, notes = parse_iptables(_UNRESOLVED_CFG)
    jn = _jump_notes(notes, "MISSING_CHAIN")
    assert jn, "unresolved jump must still be surfaced"
    for n in jn:
        for phrase in _STALE_PHRASES:
            assert phrase not in n, f"stale phrasing survives: {phrase!r} in {n!r}"
        assert "fail-closed" in n or "indeterminate" in n, (
            "note must state the honest fail-closed outcome")
    assert not any("resolved precisely" in n for n in notes)


def test_host_hook_jump_note_survives_and_is_honest():
    """INPUT/OUTPUT jumps are never resolved (surfaced only); the shared note
    wording must cover that case without promising a resolution."""
    _, notes = parse_iptables(_HOST_HOOK_CFG)
    jn = _jump_notes(notes, "SSHGUARD")
    assert jn, "host-hook jump must be surfaced"
    for n in jn:
        for phrase in _STALE_PHRASES:
            assert phrase not in n
    assert not any("resolved precisely" in n for n in notes), (
        "host-hook jumps are surfaced only, never resolved")


def test_module_docstring_documents_precise_resolution():
    """The module docstring soundness paragraph must describe the actual
    behavior: precise resolution when provable, fail-closed otherwise."""
    import importlib
    m = importlib.import_module("rulehawk.parse_iptables")
    doc = m.__doc__
    assert "resolved to precise ACEs" in doc
    assert "fail" in doc.lower() and "closed" in doc.lower()
    assert "NAT/custom-chain jumps and other" not in doc, (
        "stale docstring claim that custom-chain jumps are merely surfaced")
