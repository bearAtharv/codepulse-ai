"""FastAPI Router for CodePulse Web UI and Operator Portal."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, joinedload

from codepulse.aggregation.dedup import deduplicate_and_sort
from codepulse.aggregation.models import Finding
from codepulse.analysis.ast_engine import analyze_chunk
from codepulse.analysis.llm_engine import DiffChunk, analyze_llm
from codepulse.config import Settings, get_settings
from codepulse.ingestion.admin import execute_retry_posting
from codepulse.models.tables import AnalysisRun, DeadLetterLog, Finding as DBFinding, Repository
from codepulse.observability import generate_trace_id, get_trace_id
from codepulse.persistence.database import get_db_session, get_payload_ref, get_redis_client
from codepulse.ui.auth import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE,
    apply_ui_security_headers,
    check_login_rate_limit,
    create_session_token,
    generate_csrf_token,
    get_client_ip,
    is_auth_required,
    record_login_attempt,
    require_ui_auth,
    verify_csrf_token,
    verify_session_token,
)

logger = logging.getLogger(__name__)

UI_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = UI_DIR / "templates"
STATIC_DIR = UI_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(prefix="/ui", tags=["Web UI"])

# In-memory sliding window rate limiter for /ui/analyze (30 req/min per IP)
_ANALYZE_REQUESTS: dict[str, list[float]] = {}
MAX_ANALYZE_SIZE_BYTES = 200 * 1024  # 200 KB
ALLOWED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}


def check_analyze_rate_limit(ip: str) -> bool:
    """Enforce maximum 30 requests/min per IP for /ui/analyze."""
    now = time.time()
    cutoff = now - 60.0
    reqs = _ANALYZE_REQUESTS.get(ip, [])
    valid = [t for t in reqs if t > cutoff]
    if len(valid) >= 30:
        _ANALYZE_REQUESTS[ip] = valid
        return False
    valid.append(now)
    _ANALYZE_REQUESTS[ip] = valid
    return True


def detect_source_language(code: str, filename: str | None = None, selected: str | None = None) -> str:
    """Detect language from extension, explicit dropdown, or code keywords."""
    if selected and selected.lower() in ("python", "javascript", "typescript"):
        return selected.lower()

    if filename:
        ext = Path(filename).suffix.lower()
        if ext == ".py":
            return "python"
        if ext in (".js", ".jsx"):
            return "javascript"
        if ext in (".ts", ".tsx"):
            return "typescript"

    # Heuristic fallback based on code content
    if "def " in code or "import " in code or "print(" in code:
        return "python"
    if "function" in code or "const " in code or "let " in code or "console.log" in code:
        return "javascript"
    return "python"


def get_template_context(
    request: Request,
    active_tab: str = "",
    error: str | None = None,
    message: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build shared Jinja2 template context."""
    settings = get_settings()
    session_token = request.cookies.get(SESSION_COOKIE_NAME) or "dev-session"
    csrf_token = generate_csrf_token(session_token, settings)

    ctx: dict[str, Any] = {
        "request": request,
        "settings": settings,
        "active_tab": active_tab,
        "csrf_token": csrf_token,
        "error": error,
        "message": message,
    }
    if extra:
        ctx.update(extra)
    return ctx


# ── Global UI Security & Pre-Check ──────────────────────────────────────────


@router.get("", include_in_schema=False)
async def ui_root() -> RedirectResponse:
    """Redirect root /ui to /ui/analyze."""
    return RedirectResponse(url="/ui/analyze", status_code=status.HTTP_302_FOUND)


# ── Authentication Routes ───────────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/ui/analyze") -> Response:
    """Render operator login page."""
    settings = get_settings()
    if not settings.ui_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Web UI is disabled")

    # If auth is not required, redirect directly to requested page
    if not is_auth_required(settings):
        return RedirectResponse(url=next, status_code=status.HTTP_302_FOUND)

    # If user already holds valid session, redirect
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if verify_session_token(session_token, settings):
        return RedirectResponse(url=next, status_code=status.HTTP_302_FOUND)

    ctx = get_template_context(request, active_tab="login", extra={"next_url": next})
    resp = templates.TemplateResponse(request=request, name="login.html", context=ctx)
    apply_ui_security_headers(resp)
    return resp


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    password: str = Form(...),
    next: str = Form("/ui/analyze"),
    csrf_token: str = Form(""),
) -> Response:
    """Process operator login with rate limiting and constant-time password comparison."""
    settings = get_settings()
    if not settings.ui_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Web UI is disabled")

    client_ip = get_client_ip(request)
    if not check_login_rate_limit(client_ip):
        ctx = get_template_context(
            request,
            active_tab="login",
            error="Too many login attempts. Please wait 1 minute before trying again.",
            extra={"next_url": next},
        )
        resp = templates.TemplateResponse(request=request, name="login.html", context=ctx, status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        apply_ui_security_headers(resp)
        return resp

    expected_password = settings.ui_password or ""
    # Constant-time comparison
    is_valid = bool(expected_password and hmac.compare_digest(password, expected_password))

    if not is_valid:
        record_login_attempt(client_ip, success=False)
        ctx = get_template_context(
            request,
            active_tab="login",
            error="Invalid password. Please check your credentials.",
            extra={"next_url": next},
        )
        resp = templates.TemplateResponse(request=request, name="login.html", context=ctx, status_code=status.HTTP_401_UNAUTHORIZED)
        apply_ui_security_headers(resp)
        return resp

    record_login_attempt(client_ip, success=True)
    session_token = create_session_token(settings)

    # Sanitize redirect target to prevent open redirect
    redirect_target = next if next.startswith("/ui") else "/ui/analyze"
    resp = RedirectResponse(url=redirect_target, status_code=status.HTTP_303_SEE_OTHER)

    is_secure = settings.environment.lower() != "development"
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=is_secure,
    )
    apply_ui_security_headers(resp)
    return resp


@router.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    """Log out operator by invalidating session cookie."""
    resp = RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    apply_ui_security_headers(resp)
    return resp


# ── Page 1: /ui/analyze ─────────────────────────────────────────────────────


def _run_in_memory_analysis(
    code: str,
    language: str,
    use_ai: bool,
    settings: Settings,
) -> tuple[list[Finding], dict[str, int]]:
    """Execute in-memory static AST and optional mock/real LLM analysis.

    Zero persistence guarantee: submitted code is never stored to disk, database, or Redis.
    """
    ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts"}
    filename = f"snippet{ext_map.get(language, '.py')}"

    # 1. AST Analysis
    ast_raw = analyze_chunk(code, filename, language=language)
    unified_findings: list[Finding] = [Finding.from_ast_finding(f) for f in ast_raw]

    # 2. LLM Analysis (if requested)
    if use_ai:
        try:
            num_lines = max(1, len(code.splitlines()))
            # Convert raw code into diff hunk with added lines (+)
            diff_lines = ["+" + line for line in code.splitlines()]
            diff_content = f"@@ -0,0 +1,{num_lines} @@\n" + "\n".join(diff_lines) + "\n"
            chunk = DiffChunk(file_path=filename, hunk_header=f"@@ -0,0 +1,{num_lines} @@", content=diff_content)

            llm_result = analyze_llm(
                chunks=[chunk],
                repo_name="interactive/code-analysis",
                language=language,
                mock_llm=settings.mock_llm,
                api_key=settings.gemini_api_key or "",
            )
            for item in llm_result.findings:
                unified_findings.append(Finding.from_llm_finding(item))
        except Exception as exc:
            logger.warning("Interactive AI analysis error: %s", exc)

    # 3. Deduplication and ranking
    dedup_result = deduplicate_and_sort(unified_findings)
    findings = dedup_result.findings

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    return findings, sev_counts


@router.get("/analyze", response_class=HTMLResponse)
async def analyze_get(
    request: Request,
    _: str | None = Depends(require_ui_auth),
) -> Response:
    """Render interactive code analyzer page."""
    ctx = get_template_context(
        request,
        active_tab="analyze",
        extra={
            "analyzed": False,
            "submitted_code": "",
            "selected_language": "auto",
            "use_ai": False,
        },
    )
    resp = templates.TemplateResponse(request=request, name="analyze.html", context=ctx)
    apply_ui_security_headers(resp)
    return resp


@router.post("/analyze", response_class=HTMLResponse)
async def analyze_post(
    request: Request,
    code: str = Form(""),
    file: UploadFile | None = File(None),
    language: str = Form("auto"),
    use_ai: bool = Form(False),
    csrf_token: str = Form(""),
    _: str | None = Depends(require_ui_auth),
) -> Response:
    """Execute immediate in-process static & LLM security analysis."""
    settings = get_settings()

    # Rate limiting: 30 requests/min per IP
    client_ip = get_client_ip(request)
    if not check_analyze_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: maximum 30 requests per minute.",
        )

    # CSRF check
    session_token = request.cookies.get(SESSION_COOKIE_NAME) or "dev-session"
    if is_auth_required(settings) and not verify_csrf_token(csrf_token, session_token, settings):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or missing CSRF token")

    source_code = code or ""
    detected_filename: str | None = None

    # Handle file upload if provided
    if file and file.filename:
        ext = Path(file.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            ctx = get_template_context(
                request,
                active_tab="analyze",
                error=f"Unsupported file extension '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
                extra={"submitted_code": code, "selected_language": language, "use_ai": use_ai},
            )
            resp = templates.TemplateResponse(request=request, name="analyze.html", context=ctx, status_code=status.HTTP_400_BAD_REQUEST)
            apply_ui_security_headers(resp)
            return resp

        content_bytes = await file.read()
        if len(content_bytes) > MAX_ANALYZE_SIZE_BYTES:
            ctx = get_template_context(
                request,
                active_tab="analyze",
                error="Uploaded file exceeds maximum size limit of 200 KB.",
                extra={"submitted_code": code, "selected_language": language, "use_ai": use_ai},
            )
            resp = templates.TemplateResponse(request=request, name="analyze.html", context=ctx, status_code=413)
            apply_ui_security_headers(resp)
            return resp

        source_code = content_bytes.decode("utf-8", errors="replace")
        detected_filename = file.filename

    # Validate size of raw input
    code_bytes = source_code.encode("utf-8")
    if len(code_bytes) > MAX_ANALYZE_SIZE_BYTES:
        ctx = get_template_context(
            request,
            active_tab="analyze",
            error="Source code exceeds maximum size limit of 200 KB.",
            extra={"submitted_code": source_code[:1000], "selected_language": language, "use_ai": use_ai},
        )
        resp = templates.TemplateResponse(request=request, name="analyze.html", context=ctx, status_code=413)
        apply_ui_security_headers(resp)
        return resp

    if not source_code.strip():
        ctx = get_template_context(
            request,
            active_tab="analyze",
            error="Please paste source code or select a file to analyze.",
            extra={"submitted_code": "", "selected_language": language, "use_ai": use_ai},
        )
        resp = templates.TemplateResponse(request=request, name="analyze.html", context=ctx, status_code=status.HTTP_400_BAD_REQUEST)
        apply_ui_security_headers(resp)
        return resp

    resolved_lang = detect_source_language(source_code, filename=detected_filename, selected=language)
    findings, sev_counts = _run_in_memory_analysis(source_code, resolved_lang, use_ai, settings)

    code_lines = source_code.splitlines()
    flagged_lines = {f.line_start for f in findings if f.line_start is not None}

    ctx = get_template_context(
        request,
        active_tab="analyze",
        extra={
            "analyzed": True,
            "submitted_code": source_code,
            "code_lines": code_lines,
            "flagged_lines": flagged_lines,
            "selected_language": language,
            "detected_lang": resolved_lang,
            "use_ai": use_ai,
            "findings": findings,
            "sev_counts": sev_counts,
        },
    )
    resp = templates.TemplateResponse(request=request, name="analyze.html", context=ctx)
    apply_ui_security_headers(resp)
    return resp


@router.post("/api/analyze")
async def analyze_api(
    request: Request,
    payload: dict[str, Any],
    _: str | None = Depends(require_ui_auth),
) -> JSONResponse:
    """JSON API endpoint for code analysis."""
    settings = get_settings()
    client_ip = get_client_ip(request)
    if not check_analyze_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: maximum 30 requests per minute.",
        )

    code = payload.get("code", "")
    code_bytes = code.encode("utf-8")
    if len(code_bytes) > MAX_ANALYZE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Source code exceeds maximum size limit of 200 KB.",
        )

    if not code.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty code snippet provided.")

    language = payload.get("language", "auto")
    use_ai = bool(payload.get("use_ai", False))

    resolved_lang = detect_source_language(code, selected=language)
    findings, sev_counts = _run_in_memory_analysis(code, resolved_lang, use_ai, settings)

    findings_data = [
        {
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "explanation": f.explanation,
            "remediation": f.remediation,
            "source": f.source,
        }
        for f in findings
    ]

    return JSONResponse(
        content={
            "status": "success",
            "detected_language": resolved_lang,
            "total_findings": len(findings),
            "severity_counts": sev_counts,
            "findings": findings_data,
        }
    )


# ── Page 2: /ui/simulate ───────────────────────────────────────────────────


@router.get("/simulate", response_class=HTMLResponse)
async def simulate_get(
    request: Request,
    _: str | None = Depends(require_ui_auth),
) -> Response:
    """Render PR simulation page."""
    ctx = get_template_context(
        request,
        active_tab="simulate",
        extra={
            "repo_name": "corp-demo/repo-sample",
            "pr_number": 101,
            "run_id": None,
        },
    )
    resp = templates.TemplateResponse(request=request, name="simulate.html", context=ctx)
    apply_ui_security_headers(resp)
    return resp


@router.post("/simulate", response_class=HTMLResponse)
async def simulate_post(
    request: Request,
    repo_name: str = Form("corp-demo/repo-sample"),
    pr_number: int = Form(101),
    diff_text: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db_session),
    _: str | None = Depends(require_ui_auth),
) -> Response:
    """Submit HMAC-signed webhook to real /webhooks pipeline and return live monitor."""
    settings = get_settings()

    # CSRF check
    session_token = request.cookies.get(SESSION_COOKIE_NAME) or "dev-session"
    if is_auth_required(settings) and not verify_csrf_token(csrf_token, session_token, settings):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or missing CSRF token")

    delivery_id = str(uuid.uuid4())
    head_sha = secrets.token_hex(20)  # Unique 40-char SHA
    base_sha = "0" * 40

    webhook_payload = {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "head": {"sha": head_sha},
            "base": {"sha": base_sha},
            "user": {"login": "simulation-user"},
        },
        "repository": {
            "id": 99990,
            "full_name": repo_name,
            "default_branch": "main",
            "language": "Python",
        },
        "installation": {"id": 12345},
    }

    payload_bytes = json.dumps(webhook_payload).encode("utf-8")
    secret = settings.github_webhook_secret or "dev_webhook_secret_not_for_production"
    signature = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id,
        "X-Hub-Signature-256": signature,
        "User-Agent": "CodePulse-WebUI-Simulate/1.0",
    }

    # Dispatch to webhook endpoint directly through app ASGI pipeline
    try:
        transport = httpx.ASGITransport(app=request.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http_client:
            resp = await http_client.post("/webhooks", content=payload_bytes, headers=headers)
            if resp.status_code not in (200, 202):
                raise RuntimeError(f"Webhook rejected with HTTP {resp.status_code}: {resp.text}")
    except Exception as exc:
        logger.error("Simulation webhook dispatch failed: %s", exc)
        ctx = get_template_context(
            request,
            active_tab="simulate",
            error=f"Simulation failed to dispatch webhook: {exc}",
            extra={"repo_name": repo_name, "pr_number": pr_number, "diff_text": diff_text},
        )
        out_resp = templates.TemplateResponse(request=request, name="simulate.html", context=ctx, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        apply_ui_security_headers(out_resp)
        return out_resp

    # Locate the created analysis run
    run = db.execute(
        select(AnalysisRun).where(AnalysisRun.head_sha == head_sha).limit(1)
    ).scalar_one_or_none()

    run_id = str(run.id) if run else None
    initial_status = run.status if run else "pending"

    ctx = get_template_context(
        request,
        active_tab="simulate",
        extra={
            "repo_name": repo_name,
            "pr_number": pr_number,
            "diff_text": diff_text,
            "delivery_id": delivery_id,
            "run_id": run_id,
            "initial_status": initial_status,
            "initial_review_summary": "",
            "initial_comments": [],
        },
    )
    out_resp = templates.TemplateResponse(request=request, name="simulate.html", context=ctx)
    apply_ui_security_headers(out_resp)
    return out_resp


@router.post("/api/simulate")
async def simulate_api(
    request: Request,
    payload: dict[str, Any],
    db: Session = Depends(get_db_session),
    _: str | None = Depends(require_ui_auth),
) -> JSONResponse:
    """JSON endpoint for automated simulation triggers."""
    settings = get_settings()
    repo_name = payload.get("repo_name", "corp-demo/repo-sample")
    pr_number = int(payload.get("pr_number", 101))

    delivery_id = str(uuid.uuid4())
    head_sha = secrets.token_hex(20)
    base_sha = "0" * 40

    webhook_payload = {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "head": {"sha": head_sha},
            "base": {"sha": base_sha},
            "user": {"login": "simulation-user"},
        },
        "repository": {
            "id": 99990,
            "full_name": repo_name,
            "default_branch": "main",
            "language": "Python",
        },
        "installation": {"id": 12345},
    }

    payload_bytes = json.dumps(webhook_payload).encode("utf-8")
    secret = settings.github_webhook_secret or "dev_webhook_secret_not_for_production"
    signature = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id,
        "X-Hub-Signature-256": signature,
        "User-Agent": "CodePulse-WebUI-Simulate/1.0",
    }

    try:
        transport = httpx.ASGITransport(app=request.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post("/webhooks", content=payload_bytes, headers=headers)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    run = db.execute(
        select(AnalysisRun).where(AnalysisRun.head_sha == head_sha).limit(1)
    ).scalar_one_or_none()

    return JSONResponse(
        content={
            "status": "success",
            "delivery_id": delivery_id,
            "run_id": str(run.id) if run else None,
            "head_sha": head_sha,
        }
    )


# ── Page 3: /ui/runs ────────────────────────────────────────────────────────


@router.get("/runs", response_class=HTMLResponse)
async def runs_list(
    request: Request,
    page: int = Query(1, ge=1),
    status: str | None = Query(None),
    db: Session = Depends(get_db_session),
    _: str | None = Depends(require_ui_auth),
) -> Response:
    """Render paginated recent analysis runs table (50 runs per page)."""
    limit = 50
    offset = (page - 1) * limit

    base_query = select(AnalysisRun).options(joinedload(AnalysisRun.repository))
    count_query = select(func.count(AnalysisRun.id))

    if status and status.strip():
        base_query = base_query.where(AnalysisRun.status == status.strip().lower())
        count_query = count_query.where(AnalysisRun.status == status.strip().lower())

    total_count = db.execute(count_query).scalar() or 0
    total_pages = max(1, (total_count + limit - 1) // limit)

    stmt = base_query.order_by(desc(AnalysisRun.created_at)).offset(offset).limit(limit)
    runs_records = db.execute(stmt).scalars().all()

    formatted_runs = []
    for r in runs_records:
        duration_formatted = f"{r.analysis_duration_ms} ms" if r.analysis_duration_ms is not None else "-"
        received_formatted = r.webhook_received_at.strftime("%Y-%m-%d %H:%M:%S UTC") if r.webhook_received_at else "-"
        formatted_runs.append({
            "id": str(r.id),
            "repository_name": r.repository.full_name if r.repository else "unknown",
            "pull_request_number": r.pull_request_number,
            "status": r.status,
            "total_findings": r.total_findings or 0,
            "sev_counts": {
                "critical": r.critical_count or 0,
                "high": r.high_count or 0,
                "medium": r.medium_count or 0,
                "low": r.low_count or 0,
            },
            "duration_formatted": duration_formatted,
            "received_at_formatted": received_formatted,
        })

    ctx = get_template_context(
        request,
        active_tab="runs",
        extra={
            "runs": formatted_runs,
            "page": page,
            "total_pages": total_pages,
            "total_count": total_count,
            "current_status": status or "",
        },
    )
    resp = templates.TemplateResponse(request=request, name="runs.html", context=ctx)
    apply_ui_security_headers(resp)
    return resp


# ── Page 4: /ui/runs/{id} ───────────────────────────────────────────────────


@router.get("/runs/{run_id}", response_class=HTMLResponse)
async def run_details(
    request: Request,
    run_id: str,
    db: Session = Depends(get_db_session),
    _: str | None = Depends(require_ui_auth),
) -> Response:
    """Render detailed run view, deduplicated findings, review payload, and trace link."""
    try:
        run_uuid = uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid run ID")

    run = db.execute(
        select(AnalysisRun)
        .options(joinedload(AnalysisRun.repository), joinedload(AnalysisRun.findings))
        .where(AnalysisRun.id == run_uuid)
    ).unique().scalar_one_or_none()

    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    # Fetch review payload from Redis or DeadLetterLog
    review_body: str | None = None
    try:
        cached_payload = get_payload_ref(f"review_payload:{run_id}")
        if cached_payload and isinstance(cached_payload, dict):
            review_body = cached_payload.get("body")
    except Exception as exc:
        logger.debug("Could not read review payload from Redis: %s", exc)

    if not review_body:
        try:
            dl_entry = db.execute(
                select(DeadLetterLog)
                .where(DeadLetterLog.task_name == "tasks.post_review_to_github")
                .order_by(desc(DeadLetterLog.created_at))
            ).scalars().first()
            if dl_entry and hasattr(dl_entry, "task_args") and dl_entry.task_args and dl_entry.task_args.get("analysis_run_id") == str(run_id):
                pl = dl_entry.task_args.get("review_payload")
                if pl and isinstance(pl, dict):
                    review_body = pl.get("body")
        except Exception as exc:
            logger.debug("Could not read review body from DeadLetterLog: %s", exc)

    # Check for trace ID
    trace_id: str | None = None
    try:
        redis_client = get_redis_client()
        stored_trace = redis_client.get(f"trace_id:{run_id}")
        if stored_trace:
            trace_id = stored_trace.decode("utf-8") if isinstance(stored_trace, bytes) else str(stored_trace)
    except Exception:
        pass
    if not trace_id:
        trace_id = generate_trace_id()

    duration_formatted = f"{run.analysis_duration_ms} ms" if run.analysis_duration_ms is not None else "-"
    received_formatted = run.webhook_received_at.strftime("%Y-%m-%d %H:%M:%S UTC") if run.webhook_received_at else "-"

    ctx = get_template_context(
        request,
        active_tab="runs",
        extra={
            "run": run,
            "repo": run.repository,
            "findings": run.findings,
            "review_body": review_body,
            "trace_id": trace_id,
            "duration_formatted": duration_formatted,
            "received_at_formatted": received_formatted,
        },
    )
    resp = templates.TemplateResponse(request=request, name="run_details.html", context=ctx)
    apply_ui_security_headers(resp)
    return resp


@router.get("/api/runs/{run_id}")
async def run_status_api(
    run_id: str,
    db: Session = Depends(get_db_session),
    _: str | None = Depends(require_ui_auth),
) -> JSONResponse:
    """Polling API for PR simulation and run status."""
    try:
        run_uuid = uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid run ID")

    run = db.execute(
        select(AnalysisRun).where(AnalysisRun.id == run_uuid)
    ).scalar_one_or_none()

    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    review_summary = ""
    inline_comments: list[dict[str, Any]] = []

    try:
        cached_payload = get_payload_ref(f"review_payload:{run_id}")
        if cached_payload and isinstance(cached_payload, dict):
            review_summary = cached_payload.get("body", "")
            inline_comments = cached_payload.get("comments", [])
    except Exception:
        pass

    return JSONResponse(
        content={
            "run_id": str(run.id),
            "status": run.status,
            "total_findings": run.total_findings or 0,
            "review_posted_at": run.review_posted_at.isoformat() if run.review_posted_at else None,
            "github_review_id": run.github_review_id,
            "review_summary": review_summary,
            "inline_comments": inline_comments,
        }
    )


@router.post("/api/runs/{run_id}/retry")
async def run_retry_api(
    request: Request,
    run_id: str,
    db: Session = Depends(get_db_session),
    _: str | None = Depends(require_ui_auth),
) -> JSONResponse:
    """Trigger server-side retry of unposted review."""
    settings = get_settings()

    # CSRF validation
    csrf_token = request.headers.get("X-CSRF-Token")
    session_token = request.cookies.get(SESSION_COOKIE_NAME) or "dev-session"
    if is_auth_required(settings) and not verify_csrf_token(csrf_token, session_token, settings):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or missing CSRF token")

    try:
        result = execute_retry_posting(run_id, db)
        return JSONResponse(content={"success": True, "result": result})
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"success": False, "error": exc.detail})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"success": False, "error": str(exc)})
