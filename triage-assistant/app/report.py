"""
Report synthesis (brief Section 7.5).

The LLM is a *narration* layer over facts already computed by code (enrichment,
timeline, deterministic score). It is explicitly told not to invent facts. Three
modes, selected by LLM_PROVIDER:
  * "anthropic" -> cloud Claude
  * "ollama"    -> local/offline model (data never leaves the host)
  * unset / unavailable -> a deterministic template renderer (no LLM at all)

The deterministic fallback means the assistant always produces a well-structured
report -- useful for demos, air-gapped use, and CI. Whichever path runs is
recorded in TriageReport.generated_by, so the output is never misrepresented as
LLM-written when it wasn't.
"""

from __future__ import annotations

import json
import os
import re

from app.models import Enrichment, NormalizedAlert, TimelineEvent

REPORT_PROMPT_TEMPLATE = """You are assisting a SOC analyst by drafting the FIRST PASS of an incident
investigation report. You are given structured, already-verified facts. Do NOT
invent any fact not present in the data. If information is missing, say so
explicitly rather than guessing.

ALERT:
{alert_json}

THREAT INTEL ENRICHMENT:
{enrichment_json}

RELATED EVENT TIMELINE:
{timeline_json}

DETERMINISTIC COMPOSITE SCORE (computed by code, cite it, do not change it):
{score}/100

Write a structured investigation report with these sections:
1. Summary (2-3 sentences, plain language)
2. What happened (chronological, based ONLY on the timeline provided)
3. Indicators of Compromise observed
4. Threat intelligence context (what the enrichment suggests, and how confident
   to be given the source; if enrichment is empty/offline, say so)
5. MITRE ATT&CK technique(s) involved
6. Recommended next steps (containment, hunting, escalation criteria)
7. Confidence level -- state explicitly this is a machine-generated first draft
   requiring human review before any action.
"""


def _render_prompt(alert, enrichment, timeline, score) -> str:
    return REPORT_PROMPT_TEMPLATE.format(
        alert_json=alert.model_dump_json(indent=2),
        enrichment_json=enrichment.model_dump_json(indent=2),
        timeline_json=json.dumps([t.model_dump() for t in timeline], indent=2),
        score=score,
    )


def _generate_anthropic(prompt: str) -> str:
    import anthropic  # pip install anthropic
    client = anthropic.Anthropic(api_key=os.environ["LLM_API_KEY"])
    resp = client.messages.create(
        model=os.environ.get("LLM_MODEL", "claude-sonnet-5"),
        max_tokens=1500,
        temperature=0,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def _generate_ollama(prompt: str) -> str:
    import requests
    url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
    resp = requests.post(
        f"{url}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0}},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["response"]


def _generate_deterministic(alert, enrichment, timeline, score) -> str:
    """No-LLM fallback: compose a structured report directly from the facts."""
    iocs = [f"- {k}: `{v}`" for k, v in {
        "Source IP": alert.source_ip,
        "Destination IP": alert.destination_ip,
        "Username": alert.username,
        "Host": alert.hostname,
        "File hash": alert.file_hash,
    }.items() if v]
    timeline_lines = [
        f"- `{t.timestamp}` {'**[TRIGGER]** ' if t.is_trigger else ''}{t.event}"
        for t in timeline
    ]
    intel_line = (
        "Threat-intel enrichment was **offline** (no API keys configured); "
        "reputation data is unavailable."
        if not enrichment.sources_available
        else f"Sources queried: {', '.join(enrichment.sources_available)}. "
             f"IP reputation: {enrichment.ip_reputation}. "
             f"File reputation: {enrichment.file_reputation}."
    )
    return f"""# Investigation Report (automated first draft)

> Machine-generated. Requires analyst review before any action.

## 1. Summary
Alert **{alert.rule_name}** (severity `{alert.severity}`, technique
`{alert.mitre_technique or 'n/a'}`) fired on host `{alert.hostname or 'unknown'}`
at `{alert.timestamp.isoformat()}`. Deterministic composite score: **{score}/100**.

## 2. What happened
{chr(10).join(timeline_lines) if timeline_lines else '- No correlated events found in the window.'}

## 3. Indicators of Compromise
{chr(10).join(iocs) if iocs else '- None extracted from the alert.'}

## 4. Threat intelligence context
{intel_line}

## 5. MITRE ATT&CK
- {alert.mitre_technique or 'Not mapped in the source alert.'}

## 6. Recommended next steps
- Validate the trigger event against endpoint telemetry on `{alert.hostname or 'the host'}`.
- {'Contain the source IP `' + alert.source_ip + '` and check for lateral movement.' if alert.source_ip else 'Identify the initiating account/host.'}
- Escalate to Tier-2 if score >= {70}.

## 7. Confidence
This is an automated first draft assembled deterministically from computed facts
(score {score}/100). Human review is required before any containment action.
"""


def generate_report(
    alert: NormalizedAlert,
    enrichment: Enrichment,
    timeline: list[TimelineEvent],
    score: int,
) -> tuple[str, str]:
    """Return (markdown_report, generated_by)."""
    provider = os.environ.get("LLM_PROVIDER", "").lower()
    prompt = _render_prompt(alert, enrichment, timeline, score)
    try:
        if provider == "anthropic" and os.environ.get("LLM_API_KEY"):
            text = _generate_anthropic(prompt)
            return _guard(text, alert, enrichment, timeline, score), "anthropic"
        if provider == "ollama":
            text = _generate_ollama(prompt)
            return _guard(text, alert, enrichment, timeline, score), "ollama"
    except Exception as exc:  # noqa: BLE001 - fall back rather than crash a triage
        fallback = _generate_deterministic(alert, enrichment, timeline, score)
        return fallback + f"\n\n> (LLM path failed: {type(exc).__name__}; used deterministic fallback.)", "deterministic-fallback"
    return _generate_deterministic(alert, enrichment, timeline, score), "deterministic-fallback"


def _guard(text: str, alert, enrichment, timeline, score) -> str:
    """
    Anti-hallucination check (brief Section 12): every IPv4 the LLM mentions must
    appear in the input facts, else we distrust the narrative and fall back.
    """
    allowed = set()
    for v in (alert.source_ip, alert.destination_ip):
        if v:
            allowed.add(v)
    allowed.update(re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", enrichment.model_dump_json()))
    mentioned = set(re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", text))
    invented = mentioned - allowed
    if invented:
        return _generate_deterministic(alert, enrichment, timeline, score) + (
            f"\n\n> (LLM output mentioned IPs not in the input data: {sorted(invented)}; "
            f"discarded and replaced with the deterministic report.)"
        )
    return text
