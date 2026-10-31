#!/usr/bin/env python3
"""Automated redaction verification script for CodePulse AI logs in Docker Compose and Grafana Loki.

Verifies that sensitive data (customer source code fragments, eval statements, unified diff patches,
webhook secrets, and admin API keys) are completely redacted (count = 0) in both Docker Compose logs
and Grafana Loki, while verifying a positive control ("orchestrate_pr_analysis") returns > 0.
"""

import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def load_env() -> dict[str, str]:
    env_vars: dict[str, str] = {}
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip("'\"")
    return env_vars


def main() -> int:
    env = load_env()
    webhook_secret = env.get("GITHUB_WEBHOOK_SECRET", os.environ.get("GITHUB_WEBHOOK_SECRET", "dev_webhook_secret_not_for_production"))
    admin_key = env.get("ADMIN_API_KEY", os.environ.get("ADMIN_API_KEY", "dev_admin_key_not_for_production"))

    print("================================================================================")
    print("CODEPULSE LOG REDACTION & INTEGRITY AUDIT")
    print("================================================================================")

    # 1. Docker Compose logs audit
    print("\n[1] Auditing Docker Compose application logs (web, worker, beat)...")
    try:
        proc = subprocess.run(
            ["docker", "compose", "logs", "web", "worker", "beat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        compose_logs = proc.stdout
    except Exception as exc:
        print(f"ERROR: Failed to fetch compose logs: {exc}")
        return 1

    # Positive control in compose logs
    pos_control_str = "orchestrate_pr_analysis"
    compose_pos_count = compose_logs.count(pos_control_str)
    print(f"  Positive Control ('{pos_control_str}'): {compose_pos_count} (must be > 0)")
    if compose_pos_count == 0:
        print("  FAIL: Positive control not found in compose logs!")
        return 1

    # Redaction checks in compose logs
    patterns = [
        ("user_input", "user_input"),
        ("eval(", "eval("),
        ("diff --git", "diff --git"),
        ("[WEBHOOK_SECRET]", webhook_secret),
        ("[ADMIN_API_KEY]", admin_key),
        ("BEGIN RSA PRIVATE KEY", "BEGIN RSA PRIVATE KEY"),
        ("BEGIN PRIVATE KEY", "BEGIN PRIVATE KEY"),
        ("ghs_", "ghs_"),
        ("AIza", "AIza"),
    ]

    compose_failures = 0
    for label, pattern in patterns:
        if not pattern:
            continue
        cnt = compose_logs.count(pattern)
        status = "PASS (0)" if cnt == 0 else f"FAIL ({cnt})"
        print(f"  Redaction '{label}': {status}")
        if cnt != 0:
            compose_failures += 1

    # 2. Loki log stream audit
    print("\n[2] Auditing Grafana Loki application streams ({service=~'codepulse-(web|worker|beat)'})...")
    loki_url = "http://127.0.0.1:3100/loki/api/v1/query_range"

    def query_loki(pattern: str) -> int:
        selector = '{service=~"codepulse-(web|worker|beat)"} |= ' + json.dumps(pattern)
        params = urllib.parse.urlencode({"query": selector, "limit": 100, "since": "24h"})
        req = urllib.request.Request(f"{loki_url}?{params}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("data", {}).get("result", [])
            return sum(len(r.get("values", [])) for r in results)

    try:
        loki_pos_count = query_loki(pos_control_str)
        print(f"  Positive Control ('{pos_control_str}'): {loki_pos_count} (must be > 0)")
        if loki_pos_count == 0:
            print("  FAIL: Positive control not found in Loki streams!")
            return 1
    except Exception as exc:
        print(f"ERROR: Failed to query Loki: {exc}")
        return 1

    loki_failures = 0
    for label, pattern in patterns:
        if not pattern:
            continue
        try:
            cnt = query_loki(pattern)
            status = "PASS (0)" if cnt == 0 else f"FAIL ({cnt})"
            print(f"  Redaction '{label}': {status}")
            if cnt != 0:
                loki_failures += 1
        except Exception as exc:
            print(f"  Redaction '{label}': ERROR ({exc})")
            loki_failures += 1

    print("\n--------------------------------------------------------------------------------")
    if compose_failures == 0 and loki_failures == 0:
        print("RESULT: ALL REDACTION CHECKS PASSED (Zero occurrences found, positive controls verified)")
        return 0
    else:
        print(f"RESULT: REDACTION FAILED (Compose failures: {compose_failures}, Loki failures: {loki_failures})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
