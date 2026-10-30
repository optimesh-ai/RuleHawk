"""A config captured from an interactive `show running-config` (no
`terminal length 0`) carries pager prompts. The prompt and its backspaces
must not cost a rule, and must not shift any line number a finding cites."""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rulehawk import cli, gate  # noqa: E402
from rulehawk.model import strip_pager  # noqa: E402

IOS = os.path.join(ROOT, "samples", "ios_acl.txt")
BS = "\x08" * 10


def _captured(lines, at, prompt):
    out = list(lines)
    out[at] = prompt + out[at]
    return "\n".join(out) + "\n"


def _audit(tmp_path, text, name="cap.txt"):
    p = tmp_path / name
    p.write_text(text)
    return gate.audit_file(str(p), None)


def test_cisco_more_prompt_with_backspaces_keeps_every_rule(tmp_path):
    lines = open(IOS).read().splitlines()
    clean = gate.audit_file(IOS, None)
    for prompt in (f" --More-- {BS}{' ' * 10}{BS}", " --More-- ", "<--- More --->     ",
                   f"---(more 45%)---{BS}"):
        fr = _audit(tmp_path, _captured(lines, 7, prompt))
        assert fr.n_rules == clean.n_rules, prompt
        assert not [n for n in fr.notes if "unparsed" in n], (prompt, fr.notes)
        assert [(f.kind, fr.line_of(f)) for f in fr.findings] == \
               [(f.kind, clean.line_of(f)) for f in clean.findings]


def test_a_prompt_on_its_own_line_is_dropped(tmp_path):
    lines = open(IOS).read().splitlines()
    text = "\n".join(lines[:6] + [" --More-- "] + lines[6:]) + "\n"
    fr = _audit(tmp_path, text)
    assert fr.n_rules == 10


def test_strip_pager_never_changes_line_count_or_ordinary_text():
    text = "ip access-list extended MORE_RULES\n remark more is more\n --More-- \n"
    out = strip_pager(text)
    assert out.count("\n") == text.count("\n")
    assert "MORE_RULES" in out and "remark more is more" in out
    assert "--More--" not in out


def test_cli_reads_a_paged_capture(tmp_path, capsys):
    lines = open(IOS).read().splitlines()
    p = tmp_path / "cap.txt"
    p.write_text(_captured(lines, 7, f" --More-- {BS}{' ' * 10}{BS}"))
    cli.main([str(p)])
    assert "10 rules analyzed" in capsys.readouterr().out
