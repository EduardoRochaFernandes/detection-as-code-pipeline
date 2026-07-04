# Converted Wazuh rules

Native Wazuh (OSSEC XML) detection artifacts, kept in sync with the Sigma source
in [`rules/sigma/`](../../sigma/). See `local_rules.sample.xml` for the format
and `docs/architecture.md` for why we maintain XML alongside Sigma rather than
auto-converting to Lucene.

`pipeline/deploy_rules.py --source rules/converted/wazuh` pushes these to the
running Wazuh manager. Generated `*.xml` beyond the committed sample are
gitignored.
