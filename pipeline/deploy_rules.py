"""
Deploy validated, converted detection rules to the running Wazuh manager via its
REST API, then reload the ruleset (brief Section 6.8).

READY TO RUN ONCE AVAILABLE: needs a reachable Wazuh manager and API creds in
the environment. GitHub-hosted runners cannot reach a laptop lab, so in this
portfolio the CI `deploy` job publishes the converted rules as a downloadable
build artifact and this script is run locally (or from a self-hosted runner) to
push them -- an honest, documented trade-off, not a faked deploy (brief 6.7).

`verify=False` is used because the lab uses a self-signed cert; in a real
deployment pin the CA instead.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _env(name: str) -> str:
    try:
        return os.environ[name]
    except KeyError:
        raise SystemExit(f"Missing required environment variable: {name}")


def get_token(api_url: str, user: str, password: str) -> str:
    resp = requests.post(
        f"{api_url}/security/user/authenticate",
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def upload_rule_file(api_url: str, token: str, rule_path: Path) -> None:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}
    resp = requests.post(
        f"{api_url}/rules/files/{rule_path.name}",
        headers=headers,
        data=rule_path.read_bytes(),
        params={"overwrite": "true"},
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    print(f"[+] Deployed {rule_path.name}")


def restart_manager(api_url: str, token: str) -> None:
    resp = requests.put(
        f"{api_url}/manager/restart",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=60,
    )
    resp.raise_for_status()
    print("[+] Triggered Wazuh manager restart to load the new ruleset")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="Directory of converted rule files to deploy")
    parser.add_argument("--pattern", default="*.xml", help="Glob for rule files (Wazuh native XML)")
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args()

    api_url = _env("WAZUH_API_URL")
    user = _env("WAZUH_API_USER")
    password = _env("WAZUH_API_PASSWORD")

    files = sorted(Path(args.source).glob(args.pattern))
    if not files:
        print(f"No rule files matching {args.pattern} in {args.source}; nothing to deploy.")
        return 0

    token = get_token(api_url, user, password)
    for rule_file in files:
        upload_rule_file(api_url, token, rule_file)
    if not args.no_restart:
        restart_manager(api_url, token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
