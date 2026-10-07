# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `ci.yml` workflow (lint, tests on Python 3.11 and 3.12, catalogue sync check, offline triage demo).
- Rule catalogue with MITRE ATT&CK mapping generated from the Sigma rules (`pipeline/rule_catalogue.py`).
- Dev container for GitHub Codespaces, `Makefile`, `pyproject.toml` (ruff and pytest config).
- Offline-mode tests for the triage assistant; contributing, security and issue/PR templates.

### Changed
- README rewritten with architecture diagrams, one-click run path and an honest limitations section.
- Lint fixes (unused imports and variables, import ordering) with no behaviour change.
- The separate `validate-rules.yml` workflow was folded into `ci.yml`.

## [0.1.0] - 2026-07-04

### Added
- 13 Sigma detections mapped to MITRE ATT&CK, in-memory Sigma matcher and three-tier test suite
  (86 checks across the detection and triage suites).
- Fail-closed `test-and-deploy` workflow, Gitleaks secret scan, Wazuh lab `docker-compose.yml`.
- AI alert triage assistant (ingest, enrich, correlate, score, report) with offline fallback.
