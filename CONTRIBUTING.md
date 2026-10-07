# Contributing

Issues and pull requests are welcome. This is a portfolio project, so please keep changes small and focused.

## Setup

```bash
pip install -r pipeline/requirements.txt -r triage-assistant/requirements.txt
make test    # or: python -m pytest
make lint    # ruff
```

## Adding or changing a detection

1. Add or edit a Sigma rule in `rules/sigma/` (required: `title`, `id` (UUID), `description`, `references`,
   `tags` with ATT&CK tactic and technique, `logsource`, `detection`, `falsepositives`, `level`).
2. Add a true-positive fixture in `tests/fixtures/sample_logs_malicious/<rule-file-stem>.json` and an entry in
   `tests/atomics_map.yml`. Make sure the clean baseline in `tests/fixtures/sample_logs_clean/` stays silent.
3. Run `make catalogue` to regenerate `docs/rule-catalogue.md` and the README table (CI checks they are in sync).
4. Run the tests. A rule that does not fire on its attack fixture, or fires on the clean baseline, must not be merged.

Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `test:`). Do not commit real API keys
or credentials; `.env` is gitignored.
