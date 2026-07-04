# Converted Elastic rules

Auto-generated Elasticsearch/Lucene queries produced by
`pipeline/convert_rules.py --backend elasticsearch --out rules/converted/elastic`.

These are **build artifacts** (gitignored except this README): CI regenerates
them on every run and uploads them as the `validated-detections` artifact. Rules
that use inline aggregation (`count() by ...`) are reported as skipped by the
converter because most stateless query backends cannot express them — those are
deployed as native Wazuh/correlation artifacts instead. See
`docs/architecture.md`.
