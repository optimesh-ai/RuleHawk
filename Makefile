.PHONY: test sync-web check-vendor-sync serve-web

# Run the analysis-engine test suite (includes the vendor-sync guard).
test:
	python -m pytest -q

# Re-sync the in-browser demo's vendored engine copy after changing rulehawk/.
# The web demo (docs/) runs the engine client-side via Pyodide and is served
# same-origin by GitHub Pages, so it ships a vendored copy of the package.
sync-web:
	rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' rulehawk/ docs/rulehawk/

# Assert that docs/rulehawk/ (the hosted-tool vendored engine) is byte-identical
# to rulehawk/ (the canonical engine).  Run after ``make sync-web`` to confirm
# the sync succeeded, or in local dev before pushing.  CI enforces this via
# pytest (test_vendor_sync.py) and the workflow rsync step.
check-vendor-sync:
	python scripts/check_vendor_sync.py

# Preview the web demo locally.
serve-web:
	python -m http.server 8000 --directory docs
