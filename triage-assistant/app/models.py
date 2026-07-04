"""Pydantic schemas shared across the triage pipeline (brief Section 7.2)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class NormalizedAlert(BaseModel):
    alert_id: str
    source_system: str                       # "wazuh" | "elastic" | "manual"
    rule_name: str
    mitre_technique: Optional[str] = None
    severity: str                            # low | medium | high | critical
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    file_hash: Optional[str] = None
    raw_log: dict = Field(default_factory=dict)


class Enrichment(BaseModel):
    """Threat-intel results for the IOCs found in an alert."""
    ip_reputation: dict[str, Any] = Field(default_factory=dict)
    file_reputation: dict[str, Any] = Field(default_factory=dict)
    sources_available: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    timestamp: str
    event: str
    is_trigger: bool = False


class TriageReport(BaseModel):
    alert: NormalizedAlert
    enrichment: Enrichment
    timeline: list[TimelineEvent]
    composite_score: int                     # 0-100, deterministic (see score.py)
    requires_immediate_review: bool
    narrative_markdown: str
    generated_by: str                        # "anthropic" | "ollama" | "deterministic-fallback"
