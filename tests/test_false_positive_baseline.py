"""
Tier 2 (integration): the false-positive guardrail.

Replays a baseline of *normal* activity (legitimate RDP failures under
threshold, benign PowerShell, normal file writes, normal web traffic, etc.)
through EVERY detection rule and asserts none of them fire. A rule that trips on
the clean baseline is noisy and is not ready to deploy -- this test forces it to
be tuned first (brief Section 6.6).
"""

import json
from pathlib import Path

import pytest

from pipeline.query_runner import run_query_against_fixture

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules" / "sigma"
BASELINE_DIR = ROOT / "tests" / "fixtures" / "sample_logs_clean"

RULE_FILES = sorted(RULES_DIR.glob("*.yml"))
BASELINE_FILES = sorted(BASELINE_DIR.glob("*.json"))


def test_baseline_fixtures_exist():
    assert BASELINE_FILES, f"No clean baseline fixtures found in {BASELINE_DIR}"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.name)
def test_rule_does_not_fire_on_clean_baseline(rule_path: Path):
    offenders = []
    for baseline_file in BASELINE_FILES:
        logs = json.loads(baseline_file.read_text(encoding="utf-8"))
        if run_query_against_fixture(rule_path, logs):
            offenders.append(baseline_file.name)
    assert not offenders, (
        f"{rule_path.name} produced a false positive against clean baseline "
        f"file(s) {offenders}. Tune the rule before deploying."
    )
