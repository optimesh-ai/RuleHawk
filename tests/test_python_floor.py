"""Every shipped .py must parse on the OLDEST Python the project supports.

`pyproject.toml` declares `requires-python = ">=3.9"`, and CI runs the suite on
3.9. Newer interpreters accept syntax 3.9 rejects — most notably PEP 701
(Python 3.12+), which allows a backslash inside an f-string expression. Writing
that on a modern local interpreter produces a file that imports fine for the
author and is a hard SyntaxError for every 3.9 user and the 3.9 CI job.

This test caught exactly that: an f-string in tests/test_action.py used \\" and
collapsed the whole 3.9 collection run.
"""

from __future__ import annotations

import ast
import os
import re
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _floor() -> tuple:
    text = open(os.path.join(_ROOT, "pyproject.toml"), encoding="utf-8").read()
    m = re.search(r'requires-python\s*=\s*"[><=~^]*\s*(\d+)\.(\d+)', text)
    assert m, "requires-python not declared in pyproject.toml"
    return int(m.group(1)), int(m.group(2))


def _py_files():
    skip = {".git", "__pycache__", ".pytest_cache", "build", "dist"}
    for root, dirs, files in os.walk(_ROOT):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def test_requires_python_floor_is_declared():
    major, minor = _floor()
    assert (major, minor) >= (3, 8)


@pytest.mark.skipif(sys.version_info < (3, 12),
                    reason="only newer interpreters can accept 3.9-invalid syntax")
def test_no_backslash_inside_an_fstring_expression():
    """PEP 701 (3.12+) permits this; 3.9 raises SyntaxError at import time."""
    offenders = []
    for path in _py_files():
        src = open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue                       # covered by the parse test below
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            for part in node.values:
                if not isinstance(part, ast.FormattedValue):
                    continue
                seg = ast.get_source_segment(src, part.value) or ""
                if "\\" in seg:
                    offenders.append(
                        f"{os.path.relpath(path, _ROOT)}:{node.lineno}: {seg[:60]}")
    assert not offenders, (
        "backslash inside an f-string expression — valid on this interpreter "
        "(PEP 701, 3.12+) but a SyntaxError on the declared floor:\n  "
        + "\n  ".join(offenders))


def test_every_shipped_file_parses():
    """A blanket parse of the tree, so a syntax error anywhere fails here rather
    than by collapsing an unrelated CI job's collection phase."""
    broken = []
    for path in _py_files():
        try:
            ast.parse(open(path, encoding="utf-8").read())
        except SyntaxError as e:
            broken.append(f"{os.path.relpath(path, _ROOT)}: {e}")
    assert not broken, "unparseable file(s):\n  " + "\n  ".join(broken)
