"""
Tier 1 (unit): validate that every Sigma rule file is well-formed and carries
all required metadata. Fast; runs on every push.

If pySigma is installed we additionally parse each rule with the real
SigmaCollection to catch Sigma-spec errors the structural check would miss.
pySigma is optional so that the core test suite stays dependency-light -- the
detection-fires and false-positive tests do NOT need it (they use the in-memory
matcher). CI installs it for the stricter check; local runs degrade gracefully.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules" / "sigma"

REQUIRED_FIELDS = [
    "title", "id", "description", "references", "tags",
    "logsource", "detection", "falsepositives", "level",
]

RULE_FILES = sorted(RULES_DIR.glob("*.yml"))

try:
    from sigma.collection import SigmaCollection  # type: ignore
    HAVE_PYSIGMA = True
except Exception:  # pragma: no cover - depends on the environment
    HAVE_PYSIGMA = False


def test_rules_directory_is_not_empty():
    assert RULE_FILES, f"No Sigma rules found in {RULES_DIR}"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.name)
def test_rule_has_required_metadata(rule_path: Path):
    raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict), f"{rule_path.name} did not parse to a mapping"
    for field in REQUIRED_FIELDS:
        assert field in raw, f"{rule_path.name} is missing required field '{field}'"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.name)
def test_rule_has_nonempty_falsepositives(rule_path: Path):
    raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    assert raw["falsepositives"], (
        f"{rule_path.name} must document at least one false-positive scenario"
    )


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.name)
def test_rule_id_is_uuid(rule_path: Path):
    import uuid
    raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    uuid.UUID(str(raw["id"]))  # raises ValueError if not a valid UUID


@pytest.mark.skipif(not HAVE_PYSIGMA, reason="pySigma not installed")
@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.name)
def test_rule_parses_with_pysigma(rule_path: Path):
    # Raises if the Sigma syntax itself is invalid.
    SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
