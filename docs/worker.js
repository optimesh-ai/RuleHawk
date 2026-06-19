/* RuleHawk analysis worker — runs the vendored Python engine off the main
   thread so large ACLs don't freeze the tab. Same-origin: it fetches the
   engine from ./rulehawk/ (next to this file) so the config never leaves the
   browser. Loaded by docs/index.html; falls back to main-thread if unavailable. */

const ENGINE_MODULES = ["__init__", "model", "parse", "analyze", "report", "segcheck"];

// Build the report envelope: structured JSON + human-readable text + a
// rule_id -> source-line map so the UI can jump from a finding to its rule.
const ANALYZE_PY = `
import json
from rulehawk.parse import parse_acls
from rulehawk.analyze import analyze
from rulehawk.report import to_json, to_text
from rulehawk.segcheck import check_segmentation
aces, notes = parse_acls(cfg)
findings = analyze(aces)
_pol = pol.strip()
if _pol:
    try:
        findings = findings + check_segmentation(aces, json.loads(_pol))
    except Exception as e:
        notes = notes + ["segmentation policy error: " + str(e)]
_lines = cfg.split("\\n")
_rl, _cur = {}, 0
for a in aces:
    for _i in range(_cur, len(_lines)):
        if _lines[_i].strip() == a.raw.strip():
            _rl[a.acl + ":" + str(a.seq)] = _i + 1
            _cur = _i + 1
            break
json.dumps({"report_json": json.loads(to_json(findings, notes, len(aces))),
            "report_text": to_text(findings, notes, len(aces)),
            "rule_lines": _rl})
`;

let pyReady = null;

async function boot() {
  importScripts("https://cdn.jsdelivr.net/pyodide/v0.26.4/full/pyodide.js");
  const pyodide = await loadPyodide();
  pyodide.FS.mkdir("rulehawk");
  for (const m of ENGINE_MODULES) {
    const r = await fetch(`./rulehawk/${m}.py`, { cache: "no-cache" });
    if (!r.ok) throw new Error(`could not load engine module ${m}.py (${r.status})`);
    pyodide.FS.writeFile(`rulehawk/${m}.py`, await r.text());
  }
  pyodide.runPython("import sys; sys.path.insert(0, '.'); import rulehawk.parse, rulehawk.analyze, rulehawk.report, rulehawk.segcheck");
  return pyodide;
}

self.onmessage = async (e) => {
  const msg = e.data || {};
  if (msg.type !== "audit") return;
  try {
    if (!pyReady) pyReady = boot();
    const pyodide = await pyReady;
    pyodide.globals.set("cfg", msg.cfg);
    pyodide.globals.set("pol", msg.policy || "");
    const envelope = pyodide.runPython(ANALYZE_PY);
    self.postMessage({ type: "result", id: msg.id, envelope });
  } catch (err) {
    self.postMessage({ type: "result", id: msg.id, error: String((err && err.message) || err) });
  }
};

// Boot eagerly and announce readiness (or failure, so the page can fall back).
(async () => {
  try { await (pyReady = boot()); self.postMessage({ type: "ready" }); }
  catch (err) { self.postMessage({ type: "error", message: String((err && err.message) || err) }); }
})();
