"""Log sanitization and sensitive data redaction filter (§9.4, DEC-018)."""

from __future__ import annotations

import logging
import re
from typing import Any

# Sensitive pattern definitions matching secrets, tokens, and diff contents
SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Google / Gemini API keys (AIza prefix)
    (re.compile(r"AIza[0-9A-Za-z\-_]{15,60}"), "[REDACTED_GEMINI_KEY]"),
    # GitHub App Installation Tokens (server-to-server)
    (re.compile(r"ghs_[A-Za-z0-9_]{10,255}"), "[REDACTED_GITHUB_INSTALLATION_TOKEN]"),
    # GitHub Personal Access Tokens (classic and fine-grained)
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{28,255}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,255}"), "[REDACTED_GITHUB_PAT]"),
    # Bearer authentication headers and JWTs
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "Bearer [REDACTED_BEARER_TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"), "[REDACTED_JWT]"),
    # Database and service connection string passwords (e.g. postgresql://user:password@host)
    (re.compile(r"://([^:/@\s]+):([^@\s]+)@"), r"://\1:[REDACTED_PASSWORD]@"),
    # AWS access key IDs
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    # Private keys (full block or standalone header)
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|BEGIN [A-Z ]*PRIVATE KEY"), "[REDACTED_PRIVATE_KEY_HEADER]"),
    # Raw diff patches and customer source chunks
    (re.compile(r"diff --git a/.*?(?=(\ndiff --git|\Z))", re.DOTALL), "[REDACTED_DIFF]"),
    (re.compile(r"@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@.*?(?=(\n@@|\Z))", re.DOTALL), "[REDACTED_DIFF_HUNK]"),
)


def sanitize_text(text: str) -> str:
    """Apply all redaction rules to input text."""
    if not isinstance(text, str) or not text:
        return text
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_value(val: Any) -> Any:
    """Recursively sanitize strings, lists, or dicts."""
    if isinstance(val, str):
        return sanitize_text(val)
    elif isinstance(val, dict):
        return {k: sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple)):
        return [sanitize_value(v) for v in val]
    return val


class SecretAndCodeSanitizer(logging.Filter):
    """Logging filter that sanitizes messages and arguments in place."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Sanitize msg
        if isinstance(record.msg, str):
            record.msg = sanitize_text(record.msg)

        # Sanitize args
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(sanitize_value(arg) for arg in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: sanitize_value(v) for k, v in record.args.items()}

        return True
