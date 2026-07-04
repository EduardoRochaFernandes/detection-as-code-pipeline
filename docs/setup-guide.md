# Setup Guide

## 0. Prerequisites
- Docker + Docker Compose v2, 8 GB RAM (16 GB comfortable), 60 GB disk.
- Python 3.11+ (for the pipeline scripts and tests).
- (Optional, for live attack simulation) a Windows VM with Sysmon + WinRM.

## 1. Run the detection pipeline locally (no lab needed)
The core of Phase 1 runs with zero infrastructure — this is the fast path a
reviewer can reproduce in a minute:

```bash
git clone <repo-url> && cd detection-as-code-pipeline
python -m pip install -r pipeline/requirements.txt
python -m pytest tests/ -v          # 80 checks: syntax, true-positive, false-positive
python pipeline/compute_metrics.py  # writes metrics.json
```

## 2. Bring up the Wazuh lab
```bash
cp .env.example .env      # then edit INDEXER_PASSWORD etc.
# Linux/WSL2 host: OpenSearch needs a higher map count
sudo sysctl -w vm.max_map_count=262144
docker compose up -d
```
Dashboard: <https://localhost> (self-signed cert; log in with `admin` / your
`INDEXER_PASSWORD`). Give the indexer ~2 minutes on first boot.

## 3. Instrument a Windows endpoint
1. Install **Sysmon** with a good baseline config:
   ```powershell
   Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
2. Install the **Wazuh agent** and point it at the manager IP; enrol it, then
   confirm it appears in the dashboard.
3. Enable **WinRM** (`Enable-PSRemoting -Force`) so `run_atomics.py` can drive it.

## 4. Install Atomic Red Team (isolated lab VM only!)
```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```
Disable real-time AV **inside the lab VM only** (some atomics are quarantined).

## 5. Generate fixtures from real attacks
```bash
python pipeline/run_atomics.py --map tests/atomics_map.yml \
    --target win-endpoint-01 --winrm-pass '<password>'
# normalize the captured *.raw.json, then commit the normalized fixtures
```

## 6. Deploy validated rules
GitHub-hosted runners can't reach a home lab. Either:
- run a **self-hosted GitHub Actions runner** on the lab host, or
- download the CI `validated-detections` artifact and deploy locally:
  ```bash
  python pipeline/deploy_rules.py --source rules/converted/wazuh
  ```

## 7. Run the triage assistant (Phase 2)
```bash
python -m pip install -r triage-assistant/requirements.txt
cp .env.example .env   # optional: VT/AbuseIPDB/OTX + LLM keys (or set LLM_PROVIDER=ollama)
cd triage-assistant
python -m app.main --alert sample_alerts/example_rdp_bruteforce_alert.json  # runs offline with no keys
```
See [triage-assistant/README.md](../triage-assistant/README.md) for details.
