.PHONY: test sync-web serve-web

# Run the analysis-engine test suite.
test:
	python -m pytest -q

# Re-sync the in-browser demo's vendored engine copy after changing rulehawk/.
# The web demo (docs/) runs the engine client-side via Pyodide and is served
# same-origin by GitHub Pages, so it ships a vendored copy of the package.
sync-web:
	rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' rulehawk/ docs/rulehawk/

# Preview the web demo locally.
serve-web:
	python -m http.server 8000 --directory docs
