"""
Convert every Sigma rule in rules/sigma/ into a target backend query language
using pySigma (brief Section 6.5).

Design notes:
* Conversion is resilient: a rule that a given backend cannot express (e.g. the
  inline-aggregation rules, which most stateless query backends cannot render)
  is reported and skipped rather than aborting the whole run. Those detections
  are deployed as native/correlation artifacts instead -- see
  docs/architecture.md. The CI detection tests do NOT depend on this converted
  output (they use the in-memory matcher), so a soft-skip here is safe.
* Exit code is non-zero only if EVERY rule failed to convert, which would signal
  a genuinely broken toolchain rather than an unsupported single rule.

Usage:
    python pipeline/convert_rules.py --backend elasticsearch --out rules/converted/elastic
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma.collection import SigmaCollection


def _load_backend(name: str):
    """Import the requested pySigma backend lazily so the script only needs the
    backend the user actually asked for."""
    if name == "elasticsearch":
        from sigma.backends.elasticsearch import LuceneBackend
        return LuceneBackend()
    raise SystemExit(
        f"Unknown backend '{name}'. Install the matching pySigma backend and "
        f"add it to _load_backend() (e.g. 'splunk', 'opensearch')."
    )


def convert_all(rules_dir: Path, out_dir: Path, backend_name: str) -> tuple[int, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    backend = _load_backend(backend_name)

    converted, skipped = 0, 0
    for rule_file in sorted(rules_dir.glob("*.yml")):
        try:
            collection = SigmaCollection.from_yaml(rule_file.read_text(encoding="utf-8"))
            queries = backend.convert(collection)
            out_file = out_dir / f"{rule_file.stem}.txt"
            out_file.write_text("\n".join(queries), encoding="utf-8")
            print(f"[+] {rule_file.name} -> {out_file.name}")
            converted += 1
        except Exception as exc:  # noqa: BLE001 - we want to keep going
            print(f"[!] {rule_file.name} could NOT be converted by "
                  f"'{backend_name}' backend ({type(exc).__name__}); "
                  f"deploy as native/correlation artifact. Detail: {str(exc)[:100]}")
            skipped += 1
    return converted, skipped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-dir", default="rules/sigma")
    parser.add_argument("--backend", default="elasticsearch")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    converted, skipped = convert_all(Path(args.rules_dir), Path(args.out), args.backend)
    print(f"\nConverted {converted} rule(s), skipped {skipped}.")
    if converted == 0:
        print("ERROR: no rules converted -- check the backend installation.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
