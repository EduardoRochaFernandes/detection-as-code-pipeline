"""Normalize alerts (Wazuh JSON or a manual sample) into NormalizedAlert
(brief Section 7.2)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models import NormalizedAlert


def _map_level_to_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 6:
        return "medium"
    return "low"


def _extract_mitre(raw: dict) -> str | None:
    ids = raw.get("rule", {}).get("mitre", {}).get("id", [])
    return ids[0] if ids else None


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if value is None:
        return datetime.now(UTC)
    # Wazuh timestamps look like 2026-07-04T09:15:19.123+0000; be forgiving.
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(UTC)


def from_wazuh_alert(raw: dict) -> NormalizedAlert:
    data = raw.get("data", {})
    return NormalizedAlert(
        alert_id=str(raw.get("id", "unknown")),
        source_system="wazuh",
        rule_name=raw.get("rule", {}).get("description", "unknown rule"),
        mitre_technique=_extract_mitre(raw),
        severity=_map_level_to_severity(int(raw.get("rule", {}).get("level", 0))),
        timestamp=_parse_ts(raw.get("timestamp")),
        source_ip=data.get("srcip"),
        destination_ip=data.get("dstip"),
        username=data.get("dstuser") or data.get("srcuser"),
        hostname=raw.get("agent", {}).get("name"),
        file_hash=data.get("sha256"),
        raw_log=raw,
    )


def from_manual_alert(raw: dict) -> NormalizedAlert:
    """Accept an already-normalized-ish dict (our sample_alerts format)."""
    return NormalizedAlert(**{**{"source_system": "manual", "raw_log": raw}, **raw})


def normalize(raw: dict) -> NormalizedAlert:
    """Dispatch on shape: Wazuh alerts carry a nested `rule` dict."""
    if isinstance(raw.get("rule"), dict):
        return from_wazuh_alert(raw)
    return from_manual_alert(raw)
