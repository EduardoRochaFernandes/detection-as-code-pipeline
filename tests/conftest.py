"""Shared pytest configuration: put the repo root on sys.path so tests can
`import pipeline...` regardless of where pytest is invoked from."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
