"""
Tier 2 (integration): the "does it actually work" test.

For each mapped Sigma rule + Atomic Red Team fixture, replay the captured
malicious telemetry through the detection and assert an alert is produced. A
rule that does NOT fire on the very attack it claims to detect is broken and
must not be trusted -- this test fails the pipeline before such a rule can be
deployed (brief Section 6.6).
"""

import json
from pathlib import Path

import pytest
import yaml

from pipeline.query_runner import run_query_against_fixture

ROOT = Path(__file__).resolve().parents[1]
ATOMICS_MAP = yaml.safe_load((ROOT / "tests" / "atomics_map.yml").read_text(encoding="utf-8"))
MALICIOUS_DIR = ROOT / "tests" / "fixtures" / "sample_logs_malicious"
RULES_DIR = ROOT / "rules" / "sigma"


@pytest.mark.parametrize("entry", ATOMICS_MAP, ids=lambda e: e["sigma_rule"])
def test_detection_fires_on_malicious_logs(entry):
    if not entry.get("expects_alert", True):
        pytest.skip("Rule not expected to fire on this fixture")

    fixture_path = MALICIOUS_DIR / entry["sigma_rule"].replace(".yml", ".json")
    assert fixture_path.exists(), (
        f"Missing captured fixture for {entry['sigma_rule']} at {fixture_path}"
    )

    logs = json.loads(fixture_path.read_text(encoding="utf-8"))
    rule_path = RULES_DIR / entry["sigma_rule"]

    fired = run_query_against_fixture(rule_path, logs)
    assert fired, (
        f"Rule {entry['sigma_rule']} did NOT fire against captured logs from "
        f"Atomic Red Team {entry['atomic_technique']} "
        f"(tests {entry['atomic_test_numbers']}). Detection failed validation."
    )
