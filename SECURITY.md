# Security policy

This is a portfolio/learning project, not a production security product. Detection rules are samples and
must be tuned before use in any real environment.

To report a vulnerability in the code or a leaked secret, please use GitHub's private reporting
("Security" tab, "Report a vulnerability") rather than a public issue. There is no SLA, but reports are
appreciated and will be handled on a best-effort basis.

Notes:
- No real credentials belong in this repository; `.env.example` contains placeholders only, and CI runs
  Gitleaks over the full git history.
- Some Atomic Red Team tests are disruptive. Run `pipeline/run_atomics.py` only inside an isolated lab VM.
