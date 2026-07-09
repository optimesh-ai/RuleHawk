"""Hosted tool boot-progress gate.

The Pyodide boot spans four multi-second stages (runtime download, loadPyodide,
12 engine-module fetches, warm-up import). The worker posts ADDITIVE
``{type:'progress'}`` messages at each stage and ``index.html`` maps them to
honest staged status text, so first-time visitors on slow links see evidence of
progress instead of one static spinner that looks hung.

This module pins:
  * the worker posts each stage at the RIGHT point (runtime before the CDN
    importScripts, engine with loaded/total inside the module loop, start
    before the warm-up import) — ordering, not just presence;
  * the page handles ``progress`` and maps every stage to distinct, honest text
    (including an N-of-total count derived from ENGINE_MODULES);
  * the main-thread fallback (bootMain) emits the same staged status at its
    equivalent points;
  * the change is purely additive: ready/error/result posts survive and the
    embedded ANALYZE_PY entrypoint is untouched (no progress code can leak
    into the audit path).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOCS = os.path.join(_ROOT, "docs")
_WORKER = os.path.join(_DOCS, "worker.js")
_INDEX = os.path.join(_DOCS, "index.html")

_STAGES = ("runtime", "engine", "start")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _analyze_py(js: str) -> str:
    m = re.search(r"const ANALYZE_PY\s*=\s*`(.*?)`;", js, re.S)
    assert m, "ANALYZE_PY template not found"
    return m.group(1)


# --------------------------------------------------------------------------- #
# 1. worker posts each stage at the right point (ordering matters)
# --------------------------------------------------------------------------- #
def test_worker_posts_progress_type_additively():
    worker = _read(_WORKER)
    # the helper posts the additive message shape the page keys on
    assert re.search(r'postMessage\(\{\s*type:\s*"progress"', worker), \
        "worker never posts a {type:'progress'} message"
    # existing boot outcomes are untouched
    assert re.search(r'postMessage\(\{\s*type:\s*"ready"', worker)
    assert re.search(r'postMessage\(\{\s*type:\s*"error"', worker)
    assert re.search(r'postMessage\(\{\s*type:\s*"result"', worker)


def test_worker_stage_ordering_matches_boot_phases():
    worker = _read(_WORKER)
    runtime_at = worker.index('progress("runtime")')
    import_at = worker.index("importScripts(")
    engine_at = worker.index('progress("engine"')
    fetch_at = worker.index("await fetch(`./rulehawk/")
    start_at = worker.index('progress("start")')
    warmup_at = worker.index('pyodide.runPython("import sys')
    # runtime stage announced BEFORE the multi-MB CDN download begins
    assert runtime_at < import_at, "runtime progress must precede importScripts"
    # engine stage announced inside the loop, before each module fetch
    assert import_at < engine_at < fetch_at, \
        "engine progress must sit between importScripts and the module fetch"
    # start stage announced before the warm-up import
    assert fetch_at < start_at < warmup_at, \
        "start progress must precede the warm-up runPython"


def test_worker_engine_progress_carries_honest_counts():
    worker = _read(_WORKER)
    assert re.search(r'progress\("engine",\s*i,\s*ENGINE_MODULES\.length\)', worker), \
        "engine progress must report loaded index and ENGINE_MODULES.length total"


def test_worker_analyze_py_untouched_by_progress():
    """Progress is boot chrome only — it must never enter the audit entrypoint
    (that literal is pinned by test_hosted_parity.py and must stay pure engine)."""
    assert "progress" not in _analyze_py(_read(_WORKER)).lower()


# --------------------------------------------------------------------------- #
# 2. the page maps every stage to honest staged text
# --------------------------------------------------------------------------- #
def test_index_handles_progress_messages():
    index = _read(_INDEX)
    assert re.search(r'm\.type\s*===\s*"progress"', index), \
        "index.html onmessage must handle the additive progress type"
    # existing handlers survive
    for t in ("ready", "error", "result"):
        assert re.search(rf'm\.type\s*===\s*"{t}"', index)
    # a booted-main page must not have its status stomped by a stray worker post
    assert re.search(r'"progress"[^\n]*mode\s*!==\s*"main"', index), \
        "progress handler must not overwrite main-thread status after fallback"


def test_index_maps_all_three_stages_to_distinct_text():
    index = _read(_INDEX)
    m = re.search(r"function bootProgressHtml\(m\)\{(.*?)\n\}", index, re.S)
    assert m, "bootProgressHtml mapper not found"
    body = m.group(1)
    for stage in _STAGES:
        assert f'"{stage}"' in body, f"stage {stage!r} has no status mapping"
    assert "Downloading analysis runtime" in body       # honest: it IS a download
    assert "Loading RuleHawk engine (" in body          # honest: N-of-total count
    assert "Starting engine" in body
    # total falls back to the pinned module list, never a made-up number
    assert "ENGINE_MODULES.length" in body


def test_index_engine_count_derives_from_message_or_module_list():
    index = _read(_INDEX)
    m = re.search(r"function bootProgressHtml\(m\)\{(.*?)\n\}", index, re.S)
    body = m.group(1)
    assert re.search(r"m\.total", body) and re.search(r"m\.loaded", body), \
        "engine text must reflect the worker's actual loaded/total counters"


# --------------------------------------------------------------------------- #
# 3. the main-thread fallback stages its own boot identically
# --------------------------------------------------------------------------- #
def test_bootmain_emits_same_staged_status():
    index = _read(_INDEX)
    m = re.search(r"async function bootMain\(\)\{(.*?)\n\}", index, re.S)
    assert m, "bootMain not found"
    body = m.group(1)
    runtime_at = body.index('bootProgressHtml({stage:"runtime"})')
    load_at = body.index("await loadPyodide()")
    engine_at = body.index('bootProgressHtml({stage:"engine"')
    fetch_at = body.index("await fetch(`./rulehawk/")
    start_at = body.index('bootProgressHtml({stage:"start"})')
    warmup_at = body.index('pyodide.runPython("import sys')
    assert runtime_at < load_at, "bootMain: runtime stage must precede loadPyodide"
    assert load_at < engine_at < fetch_at, "bootMain: engine stage must precede each fetch"
    assert fetch_at < start_at < warmup_at, "bootMain: start stage must precede warm-up"
    assert 'loaded:i, total:ENGINE_MODULES.length' in body


def test_index_fallback_analyze_py_untouched_by_progress():
    assert "progress" not in _analyze_py(_read(_INDEX)).lower()


# --------------------------------------------------------------------------- #
# 4. the shipped JS still parses (catches typos in the additive edits)
# --------------------------------------------------------------------------- #
_NODE = shutil.which("node")


@pytest.mark.skipif(_NODE is None, reason="node not available for syntax check")
def test_worker_js_parses():
    r = subprocess.run([_NODE, "--check", _WORKER], capture_output=True, text=True)
    assert r.returncode == 0, f"worker.js has a syntax error:\n{r.stderr}"


@pytest.mark.skipif(_NODE is None, reason="node not available for syntax check")
def test_index_inline_scripts_parse():
    index = _read(_INDEX)
    blocks = re.findall(r"<script>(.*?)</script>", index, re.S)
    assert blocks, "no inline script blocks found"
    for i, block in enumerate(blocks):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write(block)
            path = fh.name
        try:
            r = subprocess.run([_NODE, "--check", path], capture_output=True, text=True)
            assert r.returncode == 0, \
                f"index.html inline script #{i} has a syntax error:\n{r.stderr}"
        finally:
            os.unlink(path)
