"""Authentication, session management, CSRF protection, and security headers for CodePulse UI."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from codepulse.config import Settings, get_settings

SESSION_COOKIE_NAME = "codepulse_session"
CSRF_COOKIE_NAME = "codepulse_csrf"
SESSION_MAX_AGE = 28800  # 8 hours

# In-memory fallback for login rate limiting (when Redis not reachable)
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, taking x-forwarded-for into account."""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


def is_auth_required(settings: Settings | None = None) -> bool:
    """Determine whether UI requires authentication."""
    if settings is None:
        settings = get_settings()
    is_non_dev = settings.environment.lower() != "development"
    is_live_github = not settings.mock_github
    # Required in production or live github; or in dev if ui_password is explicitly configured
    return is_non_dev or is_live_github or (settings.ui_password is not None and len(settings.ui_password.strip()) > 0)


def check_login_rate_limit(ip: str) -> bool:
    """Check if IP has exceeded login attempt threshold (5 attempts per 60s)."""
    now = time.time()
    cutoff = now - 60.0
    attempts = _LOGIN_ATTEMPTS.get(ip, [])
    # Filter attempts within window
    valid_attempts = [t for t in attempts if t > cutoff]
    _LOGIN_ATTEMPTS[ip] = valid_attempts
    return len(valid_attempts) < 5


def record_login_attempt(ip: str, success: bool) -> None:
    """Record a login attempt."""
    if success:
        _LOGIN_ATTEMPTS.pop(ip, None)
    else:
        now = time.time()
        attempts = _LOGIN_ATTEMPTS.setdefault(ip, [])
        attempts.append(now)


def create_session_token(settings: Settings | None = None) -> str:
    """Generate a tamper-proof session token."""
    if settings is None:
        settings = get_settings()
    secret = settings.ui_session_secret.encode("utf-8")
    now = int(time.time())
    rand = secrets.token_hex(16)
    payload = f"{now}:{rand}"
    sig = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: str | None, settings: Settings | None = None) -> bool:
    """Verify session token signature and validity window."""
    if not token or ":" not in token:
        return False
    parts = token.split(":")
    if len(parts) != 3:
        return False
    timestamp_str, rand, sig = parts
    try:
        created_at = int(timestamp_str)
    except ValueError:
        return False

    now = int(time.time())
    if now - created_at > SESSION_MAX_AGE or created_at > now + 60:
        return False

    if settings is None:
        settings = get_settings()
    secret = settings.ui_session_secret.encode("utf-8")
    expected_payload = f"{created_at}:{rand}".encode("utf-8")
    expected_sig = hmac.new(secret, expected_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected_sig)


def generate_csrf_token(session_token: str, settings: Settings | None = None) -> str:
    """Generate a CSRF token bound to the current session."""
    if settings is None:
        settings = get_settings()
    secret = settings.ui_session_secret.encode("utf-8")
    return hmac.new(secret, f"csrf:{session_token}".encode("utf-8"), hashlib.sha256).hexdigest()


def verify_csrf_token(csrf_token: str | None, session_token: str | None, settings: Settings | None = None) -> bool:
    """Verify that CSRF token matches the session."""
    if not csrf_token or not session_token:
        return False
    expected = generate_csrf_token(session_token, settings)
    return hmac.compare_digest(csrf_token, expected)


def apply_ui_security_headers(response: Response) -> None:
    """Attach standard security headers conforming to §3.2 and prompt requirements."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"


async def require_ui_auth(request: Request) -> str | None:
    """Dependency enforcing UI session authentication if required."""
    settings = get_settings()
    if not settings.ui_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Web UI is disabled")

    if not is_auth_required(settings):
        # In dev mode without password, return dummy session
        return "dev-session"

    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if verify_session_token(session_token, settings):
        return session_token

    # Unauthorized: API routes return 401, pages redirect to login
    if request.url.path.startswith("/ui/api"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    raise HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Location": f"/ui/login?next={request.url.path}"},
    )
