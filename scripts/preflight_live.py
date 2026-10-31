#!/usr/bin/env python3
"""Preflight validation script for live smoke-test readiness.

Performs offline dry-run verification:
- Verifies required environment variables are set and meet security constraints.
- Verifies GitHub App private key exists and parses as a valid RSA private key.
- Verifies ENVIRONMENT and secrets adhere to production safety validation rules.
- Identifies and prints which live test stage (Stage 1 or Stage 2) the environment is configured for.
- NEVER prints secret values or private key contents.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def load_env_file() -> dict[str, str]:
    """Parse .env file if present in repo root without leaking values."""
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
    env_file = load_env_file()
    # Merge file into process environment for lookup
    cfg = {**env_file, **os.environ}

    print("================================================================================")
    print("CODEPULSE AI — LIVE SMOKE TEST PREFLIGHT CHECK (DRY-RUN)")
    print("================================================================================")

    errors: list[str] = []
    warnings: list[str] = []

    # 1. Environment & Mode Selection
    environment = cfg.get("ENVIRONMENT", "development")
    mock_github = cfg.get("MOCK_GITHUB", "true").lower() in ("true", "1", "yes")
    mock_llm = cfg.get("MOCK_LLM", "true").lower() in ("true", "1", "yes")

    print(f"[*] Environment mode: {environment}")
    print(f"[*] MOCK_GITHUB: {mock_github}")
    print(f"[*] MOCK_LLM: {mock_llm}")

    # Stage determination
    if not mock_github and mock_llm:
        stage_desc = "STAGE 1 — Live GitHub App Integration (Mock LLM Client)"
    elif not mock_github and not mock_llm:
        stage_desc = "STAGE 2 — Full Live Integration (Live GitHub + Live Gemini API)"
    else:
        stage_desc = "STAGE 0 — Mock Mode (MOCK_GITHUB=true, MOCK_LLM=true)"

    print(f"\n[+] Target Execution Profile: {stage_desc}\n")

    # 2. Database & Broker Validation
    db_url = cfg.get("DATABASE_URL", "")
    if not db_url:
        errors.append("DATABASE_URL is not set.")
    elif ":codepulse_dev@" in db_url and (not mock_github or environment != "development"):
        errors.append("Default PostgreSQL password ('codepulse_dev') detected in DATABASE_URL during live integration.")
    else:
        print("  [OK] DATABASE_URL is configured.")

    redis_url = cfg.get("REDIS_URL", "")
    if not redis_url:
        errors.append("REDIS_URL is not set.")
    else:
        print("  [OK] REDIS_URL is configured.")

    # 3. GitHub App Configuration (Required if MOCK_GITHUB=false)
    if not mock_github:
        print("\n[*] Validating Live GitHub App Configuration...")

        # Webhook Secret
        webhook_secret = cfg.get("GITHUB_WEBHOOK_SECRET", "")
        if not webhook_secret:
            errors.append("GITHUB_WEBHOOK_SECRET is empty.")
        elif webhook_secret == "dev_webhook_secret_not_for_production":
            errors.append("Default GITHUB_WEBHOOK_SECRET cannot be used when MOCK_GITHUB=false.")
        else:
            print(f"  [OK] GITHUB_WEBHOOK_SECRET is set (length={len(webhook_secret)}).")

        # Admin Key
        admin_key = cfg.get("ADMIN_API_KEY", "")
        if not admin_key:
            errors.append("ADMIN_API_KEY is empty.")
        elif admin_key == "dev_admin_key_not_for_production":
            errors.append("Default ADMIN_API_KEY cannot be used when MOCK_GITHUB=false.")
        else:
            print(f"  [OK] ADMIN_API_KEY is set (length={len(admin_key)}).")

        # GitHub App ID
        raw_app_id = cfg.get("GITHUB_APP_ID", "0")
        try:
            app_id = int(raw_app_id)
            if app_id <= 0:
                errors.append(f"GITHUB_APP_ID must be a positive integer, got: {raw_app_id}")
            else:
                print(f"  [OK] GITHUB_APP_ID is configured: {app_id}")
        except ValueError:
            errors.append(f"GITHUB_APP_ID is not a valid integer: {raw_app_id}")

        # GitHub App Private Key File
        key_path_str = cfg.get("GITHUB_APP_PRIVATE_KEY_PATH", "")
        if not key_path_str:
            errors.append("GITHUB_APP_PRIVATE_KEY_PATH is not configured.")
        else:
            key_path = Path(key_path_str)
            if not key_path.is_file():
                errors.append(f"GITHUB_APP_PRIVATE_KEY_PATH file does not exist: {key_path_str}")
            else:
                try:
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.primitives.asymmetric import rsa

                    key_bytes = key_path.read_bytes()
                    private_key = serialization.load_pem_private_key(key_bytes, password=None)
                    if not isinstance(private_key, rsa.RSAPrivateKey):
                        errors.append("Private key file is not an RSA private key.")
                    else:
                        print(f"  [OK] GITHUB_APP_PRIVATE_KEY_PATH exists and parses as valid RSA key ({private_key.key_size}-bit).")
                except Exception as exc:
                    errors.append(f"Failed to load RSA private key from {key_path_str}: {exc}")
    else:
        print("  [INFO] MOCK_GITHUB=true: GitHub App credentials validation skipped.")

    # 4. Gemini API Configuration (Required if MOCK_LLM=false)
    if not mock_llm:
        print("\n[*] Validating Live Gemini API Configuration...")
        gemini_key = cfg.get("GEMINI_API_KEY", "")
        if not gemini_key or gemini_key.strip() in ("", "placeholder", "your_gemini_api_key_here"):
            errors.append("GEMINI_API_KEY is required and must not be empty or placeholder when MOCK_LLM=false.")
        elif not gemini_key.startswith("AIza"):
            warnings.append("GEMINI_API_KEY does not start with standard prefix 'AIza'.")
        else:
            print(f"  [OK] GEMINI_API_KEY is configured (prefix 'AIza...', length={len(gemini_key)}).")
    else:
        print("  [INFO] MOCK_LLM=true: Gemini API key validation skipped.")

    # 5. Injection Flags Check (Must all be false for healthy run)
    print("\n[*] Auditing failure-injection variables (must be false)...")
    injection_flags = [
        "MOCK_LLM_FAILURE",
        "MOCK_RATE_LIMIT",
        "MOCK_GITHUB_RATE_LIMIT",
        "MOCK_POSTING_FAILURE",
        "MOCK_QUICK_RETRIES",
    ]
    for flag in injection_flags:
        val = cfg.get(flag, "false").lower() in ("true", "1", "yes")
        if val:
            warnings.append(f"Injection flag {flag}=true is currently enabled.")
        else:
            print(f"  [OK] {flag}=false")

    # Summary
    print("\n--------------------------------------------------------------------------------")
    if warnings:
        print(f"WARNINGS ({len(warnings)}):")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print(f"PREFLIGHT CHECK FAILED ({len(errors)} errors):")
        for err in errors:
            print(f"  [!] {err}")
        return 1

    print("PREFLIGHT CHECK PASSED: Configuration is valid for deployment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
