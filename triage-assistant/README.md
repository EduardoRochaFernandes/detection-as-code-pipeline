# AI-Powered SIEM Alert Triage Assistant (Phase 2)

Takes **one alert** and produces **one investigation report** — faster and more
consistently than a first-pass human triage. It augments a Tier-1 analyst; it
does **not** make the final incident call (brief Section 7.1). Every report is
labelled machine-generated and requires human review.

## The loop
```
ingest → enrich → correlate → score → report
```
- **ingest** — normalize a Wazuh (or manual) alert into a common schema.
- **enrich** — reputation for IOCs via VirusTotal / AbuseIPDB / OTX (free tiers),
  with an in-memory cache and VT rate-limiting. Missing keys → offline mode.
- **correlate** — pull related events (live Elastic, or an offline JSON list) and
  build a chronological timeline.
- **score** — a **deterministic** 0-100 composite (see `app/score.py`). The LLM
  never guesses severity; it cites this computed number.
- **report** — synthesize a structured Markdown report. Provider is selectable:
  `anthropic` (cloud), `ollama` (local/offline), or a deterministic template
  fallback when no LLM is configured. `generated_by` records which ran, so
  output is never misrepresented.

## Design choices worth an interview sentence
- **Facts computed by code, narrative written by the LLM.** Enrichment, timeline
  and score are all deterministic; the model only narrates them, and a
  post-generation guard discards any report that mentions an IP not in the input
  (anti-hallucination, brief Section 12).
- **Offline-capable by design.** Runs with zero API keys and zero SIEM — useful
  for demos and for air-gapped / data-sensitive environments that can't send
  logs to a third-party API.

## Run it (offline, no keys)
```bash
cd triage-assistant
python -m pip install -r requirements.txt
python -m app.main --alert sample_alerts/example_rdp_bruteforce_alert.json
```
Outputs `reports/report_<id>.md` and `.json`. Add `--related-logs <file.json>`
to supply your own correlation events.

## Enable cloud/local LLM + threat intel
Set in `.env` (see `../.env.example`): `LLM_PROVIDER=anthropic` + `LLM_API_KEY`
(or `LLM_PROVIDER=ollama` with a local model), and the `VT_API_KEY` /
`ABUSEIPDB_API_KEY` / `OTX_API_KEY` reputation keys.

## Phase 1 ↔ Phase 2 bridge
`app.main.poll_wazuh()` polls the Wazuh API for new alerts and triages each one
(ready to run once the lab is up). If `ESCALATION_WEBHOOK_URL` is set and a
report scores ≥ 70, it posts a Slack/Discord notification.

## Tests
```bash
python -m pytest tests/ -q   # deterministic scoring + ingest, fully offline
```
