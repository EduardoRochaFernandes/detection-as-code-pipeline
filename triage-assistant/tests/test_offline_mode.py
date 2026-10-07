"""
The assistant must degrade gracefully: with no API keys, no LLM and no network it
still produces a complete, honestly-labelled report from the bundled sample alert.
"""

import json
from pathlib import Path

import pytest
from app import main as triage_main

SAMPLES = Path(__file__).resolve().parents[1] / "sample_alerts"
ENV_VARS = [
    "LLM_PROVIDER", "LLM_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY",
    "OTX_API_KEY", "ESCALATION_WEBHOOK_URL",
]


@pytest.fixture(autouse=True)
def no_keys(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def test_sample_alert_triages_offline():
    rep = triage_main.triage_one(
        _load("example_rdp_bruteforce_alert.json"), _load("example_related_events.json")
    )
    assert rep.generated_by == "deterministic-fallback"
    assert 0 <= rep.composite_score <= 100
    assert rep.enrichment.sources_available == []
    assert "offline" in rep.narrative_markdown
    assert "Machine-generated" in rep.narrative_markdown


def test_cli_writes_report_files(tmp_path, monkeypatch, capsys):
    alert = SAMPLES / "example_rdp_bruteforce_alert.json"
    monkeypatch.setattr("sys.argv", ["app.main", "--alert", str(alert), "--out", str(tmp_path)])
    assert triage_main.main() == 0
    assert list(tmp_path.glob("report_*.md")) and list(tmp_path.glob("report_*.json"))
    assert "deterministic-fallback" in capsys.readouterr().out


def test_unreachable_llm_falls_back_instead_of_crashing(monkeypatch):
    # Provider requested but the backend is unusable: must fall back, not raise.
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:9")  # nothing listens here
    rep = triage_main.triage_one(_load("example_rdp_bruteforce_alert.json"))
    assert rep.generated_by == "deterministic-fallback"
    assert "LLM path failed" in rep.narrative_markdown
