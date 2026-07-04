import sys
from pathlib import Path

# Put the triage-assistant root on sys.path so `import app...` resolves.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
