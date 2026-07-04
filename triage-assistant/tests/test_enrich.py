"""
Unit tests for the deterministic scoring and ingest logic (brief Section 7.6).
These run fully offline -- no API keys, no network.
"""

from app import ingest, score


def test_score_rises_with_threat_intel():
    low, _ = score.score_alert("medium", ip_reputation={})
    high, _ = score.score_alert("medium", ip_reputation={
        "virustotal_malicious_votes": 10,
        "abuseipdb_score": 100,
        "otx_pulse_count": 3,
    })
    assert high > low, "malicious IP reputation must increase the score"


def test_score_caps_at_100():
    s, _ = score.score_alert("critical", ip_reputation={
        "virustotal_malicious_votes": 99,
        "abuseipdb_score": 100,
        "otx_pulse_count": 5,
    }, file_reputation={"virustotal_malicious_votes": 99})
    assert s == 100


def test_lateral_movement_adds_points():
    base, _ = score.score_alert("low")
    with_lateral, breakdown = score.score_alert(
        "low", related_events=[{"rule": {"description": "Lateral Movement via SMB"}}]
    )
    assert breakdown["lateral_movement"] == 15
    assert with_lateral == base + 15


def test_review_threshold_flag():
    s, _ = score.score_alert("critical", ip_reputation={"abuseipdb_score": 100})
    assert s >= score.REVIEW_THRESHOLD


def test_severity_base_is_deterministic():
    assert score.score_alert("low")[0] == 10
    assert score.score_alert("critical")[0] == 80


def test_ingest_wazuh_maps_level_to_severity():
    raw = {
        "id": "1",
        "timestamp": "2026-07-04T09:15:19.000+00:00",
        "rule": {"level": 12, "description": "test", "mitre": {"id": ["T1110.001"]}},
        "agent": {"name": "WIN-EP-01"},
        "data": {"srcip": "45.83.90.12", "dstuser": "administrator"},
    }
    alert = ingest.normalize(raw)
    assert alert.severity == "critical"
    assert alert.source_ip == "45.83.90.12"
    assert alert.mitre_technique == "T1110.001"
    assert alert.hostname == "WIN-EP-01"
