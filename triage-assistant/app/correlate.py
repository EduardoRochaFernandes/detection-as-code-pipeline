"""
Correlate an alert against the log store and build a timeline (brief 7.4).

Two backends:
* `find_related_events(alert, es_client, ...)` queries the live Wazuh/Elastic
  indexer -- READY TO RUN once the lab is up and an ES client is passed.
* `find_related_events_local(alert, events, ...)` correlates against an in-memory
  list of events loaded from a JSON file, so the assistant is demoable end-to-end
  with no SIEM (used by the sample-alert path in main.py).

Both feed the same `build_timeline`, so the report code doesn't care which was
used.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models import NormalizedAlert, TimelineEvent


def find_related_events(alert: NormalizedAlert, es_client, window_minutes: int = 60) -> list[dict]:
    start = alert.timestamp - timedelta(minutes=window_minutes)
    end = alert.timestamp + timedelta(minutes=window_minutes)
    should = []
    if alert.source_ip:
        should.append({"term": {"data.srcip": alert.source_ip}})
    if alert.username:
        should.append({"term": {"data.dstuser": alert.username}})
    if alert.hostname:
        should.append({"term": {"agent.name": alert.hostname}})
    query = {
        "query": {"bool": {
            "must": [{"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}],
            "should": should,
            "minimum_should_match": 1,
        }},
        "sort": [{"@timestamp": "asc"}],
        "size": 200,
    }
    response = es_client.search(index="wazuh-alerts-*", body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def _event_ts(event: dict) -> datetime:
    text = str(event.get("timestamp", "")).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(UTC)


def find_related_events_local(
    alert: NormalizedAlert,
    events: list[dict],
    window_minutes: int = 60,
) -> list[dict]:
    """Offline correlation: keep events within the window that share the alert's
    source IP, username, or hostname."""
    start = alert.timestamp - timedelta(minutes=window_minutes)
    end = alert.timestamp + timedelta(minutes=window_minutes)
    related = []
    for e in events:
        ts = _event_ts(e)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        a_start = start if start.tzinfo else start.replace(tzinfo=UTC)
        a_end = end if end.tzinfo else end.replace(tzinfo=UTC)
        if not (a_start <= ts <= a_end):
            continue
        if (
            (alert.source_ip and alert.source_ip in (e.get("IpAddress"), e.get("src_ip"), e.get("data", {}).get("srcip")))
            or (alert.username and alert.username == e.get("TargetUserName"))
            or (alert.hostname and alert.hostname == e.get("Computer"))
        ):
            related.append(e)
    return related


def build_timeline(alert: NormalizedAlert, related_events: list[dict]) -> list[TimelineEvent]:
    timeline = [TimelineEvent(
        timestamp=alert.timestamp.isoformat(),
        event=alert.rule_name,
        is_trigger=True,
    )]
    for e in related_events:
        desc = (
            e.get("rule", {}).get("description")
            if isinstance(e.get("rule"), dict)
            else None
        ) or f"EventID {e.get('EventID', '?')} on {e.get('Computer', 'host')}"
        timeline.append(TimelineEvent(
            timestamp=str(e.get("timestamp", "")),
            event=desc,
            is_trigger=False,
        ))
    return sorted(timeline, key=lambda t: t.timestamp)
