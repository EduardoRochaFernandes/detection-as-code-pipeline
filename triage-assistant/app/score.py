"""
Deterministic composite severity score, 0-100 (brief Section 7.6).

This is a *computed fact* the LLM report cites -- the LLM never guesses severity.
Weights are simple, transparent, and unit-tested (tests/test_enrich.py) so the
score changes predictably as inputs change. Keeping scoring in code (not the
model) is a deliberate anti-hallucination design choice.
"""

from __future__ import annotations

from typing import Any

# Base contribution from the SIEM's own severity label.
_SEVERITY_BASE = {"low": 10, "medium": 35, "high": 60, "critical": 80}

# Caps keep any single signal from dominating.
_VT_IP_CAP = 20
_ABUSE_CAP = 20
_VT_FILE_CAP = 20
_OTX_BONUS = 5
_LATERAL_BONUS = 15

REVIEW_THRESHOLD = 70  # >= this flags requires_immediate_review (Section 7.7)


def _lateral_movement_seen(related_events: list[dict]) -> bool:
    for e in related_events:
        desc = str(e.get("rule", {}).get("description", "")).lower()
        techniques = str(e.get("rule", {}).get("mitre", {}).get("id", "")).lower()
        if "lateral" in desc or "t1021" in techniques or "smb" in desc:
            return True
    return False


def score_alert(
    severity: str,
    ip_reputation: dict[str, Any] | None = None,
    file_reputation: dict[str, Any] | None = None,
    related_events: list[dict] | None = None,
) -> tuple[int, dict[str, int]]:
    """Return (score 0-100, breakdown of each contribution)."""
    ip_reputation = ip_reputation or {}
    file_reputation = file_reputation or {}
    related_events = related_events or []

    breakdown: dict[str, int] = {}
    breakdown["severity_base"] = _SEVERITY_BASE.get(severity.lower(), 10)

    vt_ip = int(ip_reputation.get("virustotal_malicious_votes", 0) or 0)
    breakdown["vt_ip"] = min(vt_ip * 2, _VT_IP_CAP)

    abuse = int(ip_reputation.get("abuseipdb_score", 0) or 0)
    breakdown["abuseipdb"] = min(abuse // 5, _ABUSE_CAP)

    breakdown["otx"] = _OTX_BONUS if int(ip_reputation.get("otx_pulse_count", 0) or 0) > 0 else 0

    vt_file = int(file_reputation.get("virustotal_malicious_votes", 0) or 0)
    breakdown["vt_file"] = min(vt_file * 2, _VT_FILE_CAP)

    breakdown["lateral_movement"] = _LATERAL_BONUS if _lateral_movement_seen(related_events) else 0

    score = min(sum(breakdown.values()), 100)
    return score, breakdown
