"""
Generate metrics.json summarising detection coverage (brief Section 6.9).

Surfaces the numbers that make good interview talking points:
* number of ATT&CK techniques and tactics covered
* number of rules with a captured true-positive fixture
* whether every rule is exercised by the false-positive baseline

Run: python pipeline/compute_metrics.py
Writes: metrics.json at the repo root.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules" / "sigma"
MALICIOUS_DIR = ROOT / "tests" / "fixtures" / "sample_logs_malicious"
CLEAN_DIR = ROOT / "tests" / "fixtures" / "sample_logs_clean"


def main() -> None:
    rules = sorted(RULES_DIR.glob("*.yml"))
    techniques: set[str] = set()
    tactics: set[str] = set()
    rules_with_fixture = 0

    for rule_path in rules:
        raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        for tag in raw.get("tags", []):
            if tag.startswith("attack.t"):
                techniques.add(tag.replace("attack.", "").upper())
            elif tag.startswith("attack."):
                tactics.add(tag.replace("attack.", ""))
        fixture = MALICIOUS_DIR / (rule_path.stem + ".json")
        if fixture.exists():
            rules_with_fixture += 1

    metrics = {
        "rules_total": len(rules),
        "attack_techniques_covered": sorted(techniques),
        "attack_techniques_count": len(techniques),
        "attack_tactics_covered": sorted(tactics),
        "attack_tactics_count": len(tactics),
        "rules_with_truepositive_fixture": rules_with_fixture,
        "clean_baseline_fixtures": len(list(CLEAN_DIR.glob("*.json"))),
    }

    (ROOT / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
