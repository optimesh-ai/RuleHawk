"""The hosted worker must load every module the engine package imports.

Outage guard (2026-07-01): rulehawk/__init__.py gained `from .pathground
import ...` and the byte-identical docs/ mirror was synced — but worker.js's
ENGINE_MODULES list was not updated, so Pyodide never wrote pathground.py
into its FS and `import rulehawk` failed, taking the public hosted tool down.
Byte-parity of the mirrored files is necessary but NOT sufficient: the loader
list must cover the transitive import closure of the package root.

This test computes that closure from the actual source (top-level
`from .X import` statements, followed transitively) and asserts every module
in it is listed in ENGINE_MODULES. Lazy in-function imports (e.g. cli.py's
`from .gate import ...`) are intentionally out of scope — they never run in
the browser.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "rulehawk"
WORKER = ROOT / "docs" / "worker.js"

_REL_IMPORT = re.compile(r"^from \.(\w+) import", re.MULTILINE)


def _top_level_relative_imports(module: str) -> set[str]:
    text = (PKG / f"{module}.py").read_text(encoding="utf-8")
    # Only TOP-LEVEL imports matter for module load: strip indented lines so
    # lazy in-function imports don't inflate the closure.
    top = "\n".join(l for l in text.splitlines() if l and not l[0].isspace())
    return set(_REL_IMPORT.findall(top))


def _import_closure(root: str = "__init__") -> set[str]:
    seen: set[str] = {root}
    frontier = [root]
    while frontier:
        mod = frontier.pop()
        for dep in _top_level_relative_imports(mod):
            if dep not in seen and (PKG / f"{dep}.py").is_file():
                seen.add(dep)
                frontier.append(dep)
    return seen


def _engine_modules() -> set[str]:
    m = re.search(r"ENGINE_MODULES\s*=\s*\[(.*?)\]", WORKER.read_text(), re.S)
    assert m, "ENGINE_MODULES list not found in docs/worker.js"
    return set(re.findall(r'"(\w+)"', m.group(1)))


def test_worker_loads_the_full_import_closure():
    closure = _import_closure()
    listed = _engine_modules()
    missing = sorted(closure - listed)
    assert not missing, (
        f"docs/worker.js ENGINE_MODULES is missing {missing} — the hosted "
        f"tool will crash at `import rulehawk`. Add them to the list."
    )
