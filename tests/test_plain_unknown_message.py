"""The sentence that goes with reason code `fail-closed-stopgap` is plain.

A first-time user who runs RuleHawk on a file with no blocking finding gets
UNKNOWN, not PASS. The reason text must say why in plain words, be the same
sentence on every surface, and never claim the config is safe, clean or
passed (with a policy, a run can have no blocking finding while a violation
the engine does not model exists). It names no verdict word either: an MCP
result under fail_on=none is ADVISORY and carries the same reason, and an
evidence claim with it is INDETERMINATE.

The reason CODE, every verdict, every exit code and every JSON key stay as
they were; only the text changes.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re

import pytest

from rulehawk import cli, combine, exitcodes, gate, mcp_server
from rulehawk.analyze import STOPGAP_CODE, STOPGAP_MESSAGE

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_S = os.path.join(_ROOT, "samples")
CLEAN = os.path.join(_S, "adv_realistic.txt")       # no finding at any level
POLICY = os.path.join(_S, "policy.json")
# A high finding (telnet to a host in no zone) and no isolation violation:
# a FAIL run whose declared isolations are still undecided.
FAIL_CFG = "ip access-list extended EDGE\n permit tcp any host 192.0.2.10 eq 23\n"

SENTENCE = ("this version of RuleHawk never gives an all-clear (PASS), even when "
            "it reports no blocking finding (see 'Read this first' in the README)")

# Words the sentence must not contain: verdict words (it is attached to more
# than one verdict), claims about the config, and project jargon.
BANNED_WORDS = (r"\bUNKNOWN\b", r"\bADVISORY\b", r"\bINDETERMINATE\b",
                r"\bsafe\b", r"\bclean\b", r"\bverified\b", r"\bcompliant\b",
                r"no problems", r"stopgap", r"fail-closed", r"soundness",
                r"certificate", r"checker", r"\bpassed\b", r"\bpasses\b",
                r"\ba pass\b")


def _cli(args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = cli.main(args)
    return rc, out.getvalue()


def _reason_messages(obj):
    """Every `message` of a fail-closed-stopgap reason anywhere in `obj`."""
    found = []
    if isinstance(obj, dict):
        if obj.get("code") == STOPGAP_CODE and "message" in obj:
            found.append(obj["message"])
        for v in obj.values():
            found += _reason_messages(v)
    elif isinstance(obj, list):
        for v in obj:
            found += _reason_messages(v)
    return found


def test_the_sentence_is_plain():
    assert STOPGAP_MESSAGE == SENTENCE
    for pat in BANNED_WORDS:
        assert not re.search(pat, SENTENCE, re.I), pat
    # one sentence: no full stop inside, and the surfaces add their own
    assert "." not in SENTENCE.replace("'Read this first'", "")
    assert '"' not in SENTENCE and "`" not in SENTENCE   # safe in shell echo


def test_readme_has_the_section_the_sentence_points_at():
    readme = open(os.path.join(_ROOT, "README.md"), encoding="utf-8").read()
    assert "**Read this first:" in readme


def _surfaces(tmp_path):
    """(label, text) for every surface that carries the reason text."""
    out = []
    rc, text = _cli([CLEAN])
    assert rc == 3
    head = [l for l in text.splitlines() if "VERDICT: UNKNOWN (exit 3)" in l]
    out.append(("cli headline", head[0].split(f"{STOPGAP_CODE}: ", 1)[1]))
    zero = [l for l in text.splitlines() if "verdict UNKNOWN:" in l]
    out.append(("cli 0 findings line",
                zero[0].split("verdict UNKNOWN: ", 1)[1].rstrip(".")))
    rc, js = _cli([CLEAN, "--json"])
    out += [("cli json reasons", m) for m in _reason_messages(json.loads(js))]
    rc, ev = _cli([CLEAN, "--evidence", "--policy", POLICY])
    ev = json.loads(ev)
    ind = [a for a in ev["attestations"] if a["status"] == "INDETERMINATE"]
    assert ind
    out += [("evidence INDETERMINATE", m) for a in ind for m in _reason_messages(a)]

    g = gate.run_gate([CLEAN], json.load(open(POLICY)), "high")
    out += [("gate json reasons", m) for m in _reason_messages(json.loads(gate.to_json(g)))]
    sarif = json.loads(gate.to_sarif(g, version="x"))
    notes = [r["message"]["text"] for r in sarif["runs"][0]["results"]
             if r["ruleId"] == "rulehawk/uncertified"]
    assert len(notes) == 1
    out.append(("sarif note", notes[0]))
    out.append(("gate markdown", gate.to_markdown(g)))
    out.append(("gate comment", gate.comment_body(g)))
    out.append(("gate console", gate.to_console(g)))

    rd = tmp_path / "res"
    rd.mkdir()
    (rd / "r.json").write_text(gate.to_result(g, "lbl"))
    out.append(("combine", combine.render([str(rd)])[0]))

    a = mcp_server.audit(CLEAN, POLICY, fail_on="high")
    assert a["verdict"] == "UNKNOWN"
    out += [("mcp UNKNOWN reasons", m) for m in _reason_messages(a["reasons"])]
    out.append(("mcp UNKNOWN verdict_reason", a["verdict_reason"]))
    a = mcp_server.audit(CLEAN, POLICY, fail_on="none")
    assert a["verdict"] == "ADVISORY"
    out += [("mcp ADVISORY reasons", m) for m in _reason_messages(a["reasons"])]
    out.append(("mcp coverage", a["coverage"]["explanation"]))
    out.append(("mcp instructions", mcp_server.INSTRUCTIONS))

    cfg = tmp_path / "fail.cfg"
    cfg.write_text(FAIL_CFG)
    gf = gate.run_gate([str(cfg)], json.load(open(POLICY)), "high")
    assert gf.verdict == "FAIL"
    seg = [f.message for fr in gf.files for f in fr.findings
           if f.kind == "segmentation-unknown"]
    assert seg
    out += [("segmentation-unknown finding in a FAIL run", m) for m in seg]
    out.append(("gate kind help segmentation-unknown",
                gate._KIND_HELP["segmentation-unknown"]))
    out.append(("gate kind help connectivity-unknown",
                gate._KIND_HELP["connectivity-unknown"]))

    for cmd in ("file", "gate"):
        out.append((f"--help exit codes {cmd}",
                    " ".join(exitcodes.help_section(cmd).split())))
    out.append(("exit-code table", exitcodes.markdown_table()))
    # action.yml and comment/action.yml are not listed: their guard blocks,
    # annotation text included, are pinned byte for byte to e04630e
    # (tests/test_exitcodes_allclear.py, test_guard_blocks_are_byte_for_byte_
    # from_e04630e). The PR comment they post is gate.comment_body, above.
    return out


def test_every_surface_carries_the_one_sentence(tmp_path):
    surfaces = _surfaces(tmp_path)
    labels = {l for l, _ in surfaces}
    for want in ("cli headline", "cli json reasons", "evidence INDETERMINATE",
                 "sarif note", "mcp UNKNOWN reasons", "mcp ADVISORY reasons",
                 "segmentation-unknown finding in a FAIL run", "combine",
                 "gate comment"):
        assert want in labels, want
    for label, text in surfaces:
        assert SENTENCE in text, label
        assert "pending soundness review" not in text, label


@pytest.mark.parametrize("label", ["cli headline", "cli 0 findings line",
                                   "cli json reasons", "evidence INDETERMINATE",
                                   "gate json reasons", "mcp UNKNOWN reasons",
                                   "mcp ADVISORY reasons"])
def test_reason_text_is_exactly_the_sentence(tmp_path, label):
    got = [t for l, t in _surfaces(tmp_path) if l == label]
    assert got and all(t == SENTENCE for t in got), (label, got)


def _pyproject_version():
    text = open(os.path.join(_ROOT, "pyproject.toml"), encoding="utf-8").read()
    return re.search(r'^version = "([^"]+)"', text, re.M).group(1)


def test_versions_agree():
    import rulehawk
    server = json.load(open(os.path.join(_ROOT, "server.json"), encoding="utf-8"))
    got = {"pyproject": _pyproject_version(),
           "rulehawk.__version__": rulehawk.__version__,
           "server.json version": server["version"]}
    got.update({f"server.json packages[{i}].version": p["version"]
                for i, p in enumerate(server.get("packages", []))})
    for i, p in enumerate(server.get("packages", [])):
        for a in p.get("runtimeArguments", []):
            m = re.fullmatch(r"rulehawk\[mcp\]==(.+)", str(a.get("value", "")))
            if m:
                got[f"server.json packages[{i}] --from pin"] = m.group(1)
    assert set(got.values()) == {"0.4.2"}, got
