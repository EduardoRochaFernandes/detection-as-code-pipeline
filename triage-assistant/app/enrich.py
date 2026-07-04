"""
Threat-intel enrichment of alert IOCs against free-tier sources: VirusTotal,
AbuseIPDB, AlienVault OTX (brief Section 7.3).

Robustness features the brief calls for:
* An in-memory cache keyed by IOC so repeated lookups in one run don't re-hit the
  API (VirusTotal free tier = 4 req/min).
* A simple rate-limit sleep between VirusTotal calls.
* Graceful OFFLINE mode: if an API key is missing, that source is skipped and a
  note is recorded, so the rest of the pipeline (correlate/score/report) still
  runs end-to-end without keys. This is what lets the sample-alert demo work with
  no secrets configured.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests

from app.models import Enrichment

_CACHE: dict[str, dict] = {}
_VT_MIN_INTERVAL = 15.0  # seconds between VT calls (4/min free tier)
_last_vt_call = 0.0


def _vt_ratelimit() -> None:
    global _last_vt_call
    wait = _VT_MIN_INTERVAL - (time.monotonic() - _last_vt_call)
    if wait > 0:
        time.sleep(wait)
    _last_vt_call = time.monotonic()


def check_ip_reputation(ip: str) -> dict:
    cache_key = f"ip:{ip}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    result: dict[str, Any] = {"ip": ip}
    vt_key = os.environ.get("VT_API_KEY")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    otx_key = os.environ.get("OTX_API_KEY")

    if vt_key:
        _vt_ratelimit()
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": vt_key}, timeout=10,
            )
            if r.ok:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                result["virustotal_malicious_votes"] = stats.get("malicious", 0)
        except requests.RequestException as e:
            result["virustotal_error"] = str(e)[:80]

    if abuse_key:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10,
            )
            if r.ok:
                d = r.json()["data"]
                result["abuseipdb_score"] = d.get("abuseConfidenceScore")
                result["abuseipdb_reports"] = d.get("totalReports")
        except requests.RequestException as e:
            result["abuseipdb_error"] = str(e)[:80]

    if otx_key:
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": otx_key}, timeout=10,
            )
            if r.ok:
                result["otx_pulse_count"] = r.json().get("pulse_info", {}).get("count", 0)
        except requests.RequestException as e:
            result["otx_error"] = str(e)[:80]

    _CACHE[cache_key] = result
    return result


def check_file_hash(sha256: str) -> dict:
    cache_key = f"hash:{sha256}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    result: dict[str, Any] = {"sha256": sha256}
    vt_key = os.environ.get("VT_API_KEY")
    if vt_key:
        _vt_ratelimit()
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": vt_key}, timeout=10,
            )
            if r.ok:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                result["virustotal_malicious_votes"] = stats.get("malicious", 0)
                result["virustotal_total_engines"] = sum(stats.values())
            else:
                result["virustotal_status"] = "not_found_or_error"
        except requests.RequestException as e:
            result["virustotal_error"] = str(e)[:80]
    _CACHE[cache_key] = result
    return result


def enrich_alert(source_ip: str | None, file_hash: str | None) -> Enrichment:
    """Enrich whatever IOCs are present; record which sources were usable."""
    available = [name for name, env in (
        ("virustotal", "VT_API_KEY"),
        ("abuseipdb", "ABUSEIPDB_API_KEY"),
        ("otx", "OTX_API_KEY"),
    ) if os.environ.get(env)]

    enr = Enrichment(sources_available=available)
    if not available:
        enr.notes.append(
            "No threat-intel API keys configured -> running OFFLINE; reputation "
            "unavailable. Set VT_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY to enable."
        )
    if source_ip:
        enr.ip_reputation = check_ip_reputation(source_ip)
    if file_hash:
        enr.file_reputation = check_file_hash(file_hash)
    return enr
