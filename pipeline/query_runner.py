"""
Thin adapter the test suite imports (brief Section 6.6).

`run_query_against_fixture` is the single seam between the tests and *how*
detection is evaluated. Today it uses the in-memory Sigma matcher
(strategy 1). To upgrade to strategy 2 (a live ephemeral OpenSearch/Elastic
container in CI, see docs/architecture.md and the roadmap), only this function
needs to change -- the tests stay identical. That is the payoff of putting the
seam here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pipeline.sigma_matcher import rule_fires


def _normalize_events(logs: Any) -> list[dict]:
    """
    Accept the several shapes a fixture might take and return a flat list of
    event dicts:

    * a JSON list of events                      -> used as-is
    * {"events": [...]}                          -> the inner list
    * a single event dict                        -> wrapped in a list
    """
    if isinstance(logs, list):
        return logs
    if isinstance(logs, dict):
        if isinstance(logs.get("events"), list):
            return logs["events"]
        return [logs]
    raise TypeError(f"Unsupported fixture shape: {type(logs)!r}")


def load_rule(rule_path: Path) -> dict:
    """Parse a Sigma rule file into a dict."""
    return yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))


def run_query_against_fixture(rule_path: Path, logs: Any) -> bool:
    """
    Return True if the detection defined by `rule_path` fires against `logs`.

    `logs` is whatever was loaded from a fixture JSON file (list or dict).
    """
    rule = load_rule(rule_path)
    events = _normalize_events(logs)
    return rule_fires(rule, events)
