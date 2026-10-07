.PHONY: install test lint demo catalogue metrics

PY ?= python

install:
	$(PY) -m pip install -r pipeline/requirements.txt -r triage-assistant/requirements.txt

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m pip install -q ruff && $(PY) -m ruff check .

# Triage a bundled sample alert end-to-end; needs no API keys or network.
demo:
	cd triage-assistant && $(PY) -m app.main --alert sample_alerts/example_rdp_bruteforce_alert.json

# Regenerate docs/rule-catalogue.md and the README table from rules/sigma/.
catalogue:
	$(PY) pipeline/rule_catalogue.py

metrics:
	$(PY) pipeline/compute_metrics.py
