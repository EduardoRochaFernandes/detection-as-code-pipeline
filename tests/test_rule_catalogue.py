"""The generated rule catalogue (docs + README table) must match the real rules."""

from pipeline import rule_catalogue


def test_catalogue_covers_every_rule_file():
    rules = rule_catalogue.load_rules()
    assert len(rules) == len(list(rule_catalogue.RULES_DIR.glob("*.yml")))
    assert all(r["technique"] and r["tactics"] for r in rules), "every rule needs ATT&CK tags"


def test_generated_docs_are_up_to_date():
    assert not rule_catalogue.stale_files(), "run: python pipeline/rule_catalogue.py"
