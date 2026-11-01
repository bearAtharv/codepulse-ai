#!/usr/bin/env python3
"""CLI utility to send a validly signed GitHub pull_request webhook to CodePulse AI.

Reads GITHUB_WEBHOOK_SECRET from the local .env file or environment variables.
Builds and signs the payload with HMAC-SHA256 (X-Hub-Signature-256).
Never prints or leaks the secret value.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def load_webhook_secret() -> str:
    """Load GITHUB_WEBHOOK_SECRET from environment or .env without leaking."""
    if "GITHUB_WEBHOOK_SECRET" in os.environ and os.environ["GITHUB_WEBHOOK_SECRET"].strip():
        return os.environ["GITHUB_WEBHOOK_SECRET"].strip()

    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if k.strip() == "GITHUB_WEBHOOK_SECRET":
                    val = v.strip().strip("'\"")
                    if val:
                        return val

    # Fallback default used in local development compose stack
    return "dev_webhook_secret_not_for_production"


def sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Compute X-Hub-Signature-256 HMAC-SHA256 signature."""
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def build_pr_payload(
    repo_name: str,
    pr_number: int,
    action: str,
    head_sha: str,
    base_sha: str,
    author: str,
    installation_id: int,
    repo_id: int,
) -> dict:
    """Build GitHub-compliant pull_request webhook payload."""
    return {
        "action": action,
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "head": {"sha": head_sha},
            "base": {"sha": base_sha},
            "user": {"login": author},
        },
        "repository": {
            "id": repo_id,
            "full_name": repo_name,
            "default_branch": "main",
            "language": "Python",
        },
        "installation": {"id": installation_id},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send a signed GitHub pull_request webhook event to CodePulse AI."
    )
    parser.add_argument(
        "--repo",
        default="corp-demo/repo-sample",
        help="Repository full name (owner/repo). Default: corp-demo/repo-sample",
    )
    parser.add_argument(
        "--pr",
        type=int,
        default=101,
        help="Pull request number. Default: 101",
    )
    parser.add_argument(
        "--action",
        choices=["opened", "synchronize", "reopened"],
        default="opened",
        help="PR action. Default: opened",
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/webhooks",
        help="Target CodePulse webhook endpoint URL. Default: http://127.0.0.1:8000/webhooks",
    )
    parser.add_argument(
        "--head-sha",
        default="a" * 40,
        help="PR head commit SHA-1. Default: 40 'a's",
    )
    parser.add_argument(
        "--base-sha",
        default="b" * 40,
        help="PR base commit SHA-1. Default: 40 'b's",
    )
    parser.add_argument(
        "--author",
        default="dev-test",
        help="PR author username. Default: dev-test",
    )
    parser.add_argument(
        "--installation-id",
        type=int,
        default=12345,
        help="GitHub App Installation ID. Default: 12345",
    )
    parser.add_argument(
        "--repo-id",
        type=int,
        default=99991,
        help="GitHub numerical Repository ID. Default: 99991",
    )

    args = parser.parse_args()

    secret = load_webhook_secret()
    payload = build_pr_payload(
        repo_name=args.repo,
        pr_number=args.pr,
        action=args.action,
        head_sha=args.head_sha,
        base_sha=args.base_sha,
        author=args.author,
        installation_id=args.installation_id,
        repo_id=args.repo_id,
    )

    payload_bytes = json.dumps(payload).encode("utf-8")
    signature = sign_payload(payload_bytes, secret)
    delivery_id = str(uuid.uuid4())

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id,
        "X-Hub-Signature-256": signature,
        "User-Agent": "GitHub-Hookshot/CodePulse-Test",
    }

    print(f"[*] Target URL: {args.url}")
    print(f"[*] Event: pull_request ({args.action})")
    print(f"[*] Repository: {args.repo} | PR: #{args.pr}")
    print(f"[*] Head SHA: {args.head_sha[:10]}... | Base SHA: {args.base_sha[:10]}...")
    print(f"[*] Delivery ID: {delivery_id}")
    print(f"[*] Signature: {signature[:17]}... [REDACTED]")

    req = urllib.request.Request(
        args.url,
        data=payload_bytes,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_body = resp.read().decode("utf-8")
            print(f"[+] Response Status: {resp.status} {resp.reason}")
            print(f"[+] Response Body: {resp_body}")
            return 0
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8")
        print(f"[-] HTTP Error {exc.code}: {exc.reason}", file=sys.stderr)
        print(f"[-] Error Body: {err_body}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] Request failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
