"""
Orchestrate execution of Atomic Red Team tests against the lab endpoint(s) and
capture the resulting Sysmon/Windows Event Logs as test fixtures (brief 6.4).

READY TO RUN ONCE AVAILABLE: this driver needs a reachable Windows endpoint with
WinRM enabled and invoke-atomicredteam installed. It is intentionally NOT run in
CI (CI replays the already-captured fixtures under tests/fixtures/). Run it on
the isolated lab host to (re)generate those fixtures:

    python pipeline/run_atomics.py --map tests/atomics_map.yml \
        --target win-endpoint-01 --winrm-pass '<password>'

Safety: several atomics (LSASS access, log clearing, ransomware file impact) are
genuinely disruptive. Run ONLY inside an isolated lab VM -- never on a host with
real data (brief Section 14).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

try:
    import winrm  # pip install pywinrm
except ImportError:  # pragma: no cover
    winrm = None

FIXTURE_DIR = Path("tests/fixtures/sample_logs_malicious")


def load_map(map_path: str) -> list[dict]:
    with open(map_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_atomic(session, technique: str, test_numbers: list[int]) -> None:
    test_arg = ",".join(str(n) for n in test_numbers)
    # Always fetch prerequisites first (brief Section 12 pitfall).
    ps_command = (
        f"Invoke-AtomicTest {technique} -TestNumbers {test_arg} -GetPrereqs; "
        f"Invoke-AtomicTest {technique} -TestNumbers {test_arg}"
    )
    result = session.run_ps(ps_command)
    print(f"[+] Ran {technique} tests {test_numbers} -> exit {result.status_code}")
    if result.status_code != 0:
        print(result.std_err.decode(errors="replace"))


def collect_logs(session, since_minutes: int, out_path: Path) -> None:
    """Pull recent Sysmon events and write them out. NOTE: the raw Get-WinEvent
    JSON is nested; a normalization pass (documented in docs/architecture.md)
    flattens it into the field shape the matcher/fixtures use before commit."""
    ps_command = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';"
        f"StartTime=(Get-Date).AddMinutes(-{since_minutes})}} | ConvertTo-Json -Depth 5"
    )
    result = session.run_ps(ps_command)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(result.std_out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--winrm-user", default="labadmin")
    parser.add_argument("--winrm-pass", required=True)
    parser.add_argument("--since-minutes", type=int, default=5)
    args = parser.parse_args()

    if winrm is None:
        raise SystemExit("pywinrm is not installed. `pip install pywinrm` on the control host.")

    session = winrm.Session(
        args.target, auth=(args.winrm_user, args.winrm_pass), transport="ntlm"
    )

    for entry in load_map(args.map):
        if entry["target_host"] != args.target:
            continue
        run_atomic(session, entry["atomic_technique"], entry["atomic_test_numbers"])
        out_file = FIXTURE_DIR / entry["sigma_rule"].replace(".yml", ".raw.json")
        collect_logs(session, args.since_minutes, out_file)
        print(f"[+] Captured raw logs to {out_file} (normalize before committing)")


if __name__ == "__main__":
    main()
