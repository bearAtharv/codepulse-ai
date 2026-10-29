"""PR diff and file content fetching from GitHub REST API (or mock fixtures).

Implements Section 3.2.1 of the architecture document:
- Fetches PR modified files via GET /repos/{owner}/{repo}/pulls/{pull_number}/files
  with pagination (100 files per page).
- Authenticates via GitHub App RS256 JWT exchanged for an installation access token
  (POST /app/installations/{installation_id}/access_tokens), cached in Redis for 55m.
- Fetches full file contents for AST context via
  GET /repos/{owner}/{repo}/contents/{path}?ref={head_sha}, cached in Redis for 24h.
- Provides a deterministic fixture-backed MockDiffFetcher when MOCK_GITHUB=true.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from codepulse.config import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass
class PRFile:
    """Represents a single file entry from a Pull Request diff."""

    filename: str
    status: str = "modified"  # "added" | "modified" | "removed" | "renamed"
    additions: int = 0
    deletions: int = 0
    changes: int = 0
    patch: str | None = None
    raw_content: str | None = None


# ── GitHub App RS256 JWT Helper (Section 3.2.1) ────────────────────────


def create_github_app_jwt(app_id: int | str, private_key_pem: bytes | str) -> str:
    """Sign an RS256 JWT for GitHub App authentication.

    Args:
        app_id: GitHub App numeric or string identifier.
        private_key_pem: PEM-encoded RSA private key.

    Returns:
        Encoded RS256 JWT string valid for 9 minutes (with 60s clock-skew leeway).
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": str(app_id),
    }

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"

    key_bytes = (
        private_key_pem.encode("utf-8")
        if isinstance(private_key_pem, str)
        else private_key_pem
    )
    private_key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("GitHub App private key must be an RSA private key")

    signature = private_key.sign(
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{signing_input}.{_b64url(signature)}"


# ── Base Interface ─────────────────────────────────────────────────────


class BaseDiffFetcher(ABC):
    """Abstract interface for fetching PR diffs and file contents."""

    @abstractmethod
    def fetch_pr_files(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_id: int | None = None,
    ) -> list[PRFile]:
        """Fetch list of files and unified diff patches for a pull request."""
        ...

    @abstractmethod
    def fetch_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str,
        installation_id: int | None = None,
    ) -> str | None:
        """Fetch full file content at a specific commit SHA."""
        ...

    def fetch_pr_head_sha(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_id: int | None = None,
    ) -> str | None:
        """Fetch the current head SHA of a pull request."""
        return None


# ── Mock Diff Fetcher (MOCK_GITHUB=true) ───────────────────────────────


_MOCK_APP_PY_CONTENT = (
    "data = eval(user_input)\n"
    'cursor.execute(f"SELECT * FROM users WHERE name = \'{data}\'")\n'
)

_MOCK_APP_PY_PATCH = (
    "@@ -0,0 +1,2 @@\n"
    "+data = eval(user_input)\n"
    '+cursor.execute(f"SELECT * FROM users WHERE name = \'{data}\'")\n'
)

_MOCK_INDEX_JS_CONTENT = (
    "function renderWidget(userInput) {\n"
    '    document.getElementById("app").innerHTML = userInput;\n'
    "}\n"
)

_MOCK_INDEX_JS_PATCH = (
    "@@ -1,3 +1,3 @@\n"
    " function renderWidget(userInput) {\n"
    '-    document.getElementById("app").textContent = userInput;\n'
    '+    document.getElementById("app").innerHTML = userInput;\n'
    " }\n"
)

_MOCK_CLEAN_PY_CONTENT = (
    "def add_numbers(a: int, b: int) -> int:\n"
    "    return a + b\n"
)

_MOCK_CLEAN_PY_PATCH = (
    "@@ -0,0 +1,2 @@\n"
    "+def add_numbers(a: int, b: int) -> int:\n"
    "+    return a + b\n"
)


class MockDiffFetcher(BaseDiffFetcher):
    """Deterministic fixture-based diff source for MOCK_GITHUB=true.

    Provides:
    - src/app.py: Vulnerable Python (eval on line 1 + SQLi on line 2) so AST
      and LLM findings collide on line 1 and merge into source='merged'.
    - src/index.js: Vulnerable JS (DOM XSS via innerHTML on line 2).
    - src/clean.py: Clean Python code producing zero findings.
    - poetry.lock: Lockfile (filtered out by preprocessor).
    - node_modules/pkg/index.js: Vendored file (filtered out by preprocessor).
    """

    def __init__(self, custom_files: list[PRFile] | None = None) -> None:
        self._custom_files = custom_files
        self._mock_head_sha = "1" * 40
        self._content_map: dict[str, str] = {
            "src/app.py": _MOCK_APP_PY_CONTENT,
            "src/index.js": _MOCK_INDEX_JS_CONTENT,
            "src/clean.py": _MOCK_CLEAN_PY_CONTENT,
        }

    def fetch_pr_head_sha(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_id: int | None = None,
    ) -> str | None:
        if os.environ.get("MOCK_CURRENT_HEAD_SHA"):
            return os.environ.get("MOCK_CURRENT_HEAD_SHA")
        return getattr(self, "_mock_head_sha", "1" * 40)

    def fetch_pr_files(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_id: int | None = None,
    ) -> list[PRFile]:
        if self._custom_files is not None:
            return list(self._custom_files)

        logger.info(
            "[MOCK GITHUB] Fetching PR files for %s/%s#%d",
            owner,
            repo,
            pull_number,
        )
        return [
            PRFile(
                filename="src/app.py",
                status="added",
                additions=2,
                deletions=0,
                changes=2,
                patch=_MOCK_APP_PY_PATCH,
                raw_content=_MOCK_APP_PY_CONTENT,
            ),
            PRFile(
                filename="src/index.js",
                status="modified",
                additions=1,
                deletions=1,
                changes=2,
                patch=_MOCK_INDEX_JS_PATCH,
                raw_content=_MOCK_INDEX_JS_CONTENT,
            ),
            PRFile(
                filename="src/clean.py",
                status="added",
                additions=2,
                deletions=0,
                changes=2,
                patch=_MOCK_CLEAN_PY_PATCH,
                raw_content=_MOCK_CLEAN_PY_CONTENT,
            ),
            PRFile(
                filename="poetry.lock",
                status="modified",
                additions=1,
                deletions=1,
                changes=2,
                patch='@@ -1,2 +1,2 @@\n-version = "1.0"\n+version = "1.1"\n',
            ),
            PRFile(
                filename="node_modules/pkg/index.js",
                status="added",
                additions=1,
                deletions=0,
                changes=1,
                patch="@@ -0,0 +1,1 @@\n+module.exports = {};\n",
            ),
        ]

    def fetch_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str,
        installation_id: int | None = None,
    ) -> str | None:
        return self._content_map.get(path)


# ── Real GitHub Diff Fetcher (Section 3.2.1) ───────────────────────────


class GitHubDiffFetcher(BaseDiffFetcher):
    """Production GitHub REST API client using synchronous httpx.Client.

    Handles GitHub App JWT signing, installation token exchange with Redis
    caching, paginated PR file listing, and full file content retrieval.
    """

    def __init__(
        self,
        *,
        app_id: int = 0,
        private_key_path: str = "",
        private_key_pem: str | bytes | None = None,
        token: str | None = None,
        redis_client: Any = None,
        base_url: str = "https://api.github.com",
        token_ttl: int = 3300,
        file_cache_ttl: int = 86400,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.app_id = app_id
        self.private_key_path = private_key_path
        self.private_key_pem = private_key_pem
        self.token = token
        self.redis_client = redis_client
        self.base_url = base_url.rstrip("/")
        self.token_ttl = token_ttl
        self.file_cache_ttl = file_cache_ttl
        self.timeout = timeout
        self.transport = transport
        self.last_rate_limit_remaining: int | None = None
        self.last_rate_limit_reset: int | None = None

    def _get_client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, transport=self.transport)

    def _update_rate_limit(self, response: httpx.Response) -> None:
        if "x-ratelimit-remaining" in response.headers:
            try:
                self.last_rate_limit_remaining = int(response.headers["x-ratelimit-remaining"])
            except ValueError:
                pass
        if "x-ratelimit-reset" in response.headers:
            try:
                self.last_rate_limit_reset = int(response.headers["x-ratelimit-reset"])
            except ValueError:
                pass

    def _load_private_key(self) -> bytes:
        if self.private_key_pem is not None:
            return (
                self.private_key_pem.encode("utf-8")
                if isinstance(self.private_key_pem, str)
                else self.private_key_pem
            )
        if not self.private_key_path:
            raise ValueError("GitHub App private key path or PEM must be configured")
        return Path(self.private_key_path).read_bytes()

    def get_installation_token(self, installation_id: int) -> str:
        """Obtain or retrieve cached GitHub App installation access token (§3.2.1)."""
        if self.token:
            return self.token

        cache_key = f"gh_token:{installation_id}"
        if self.redis_client is not None:
            try:
                cached = self.redis_client.get(cache_key)
                if cached:
                    return cached.decode("utf-8") if isinstance(cached, bytes) else str(cached)
            except Exception as exc:
                logger.warning("Redis error reading %s: %s", cache_key, exc)

        key_bytes = self._load_private_key()
        app_jwt = create_github_app_jwt(self.app_id, key_bytes)

        url = f"{self.base_url}/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        with self._get_client() as client:
            response = client.post(url, headers=headers)
            self._update_rate_limit(response)
            response.raise_for_status()
            token: str = response.json()["token"]

        if self.redis_client is not None:
            try:
                self.redis_client.set(cache_key, token, ex=self.token_ttl)
            except Exception as exc:
                logger.warning("Redis error caching %s: %s", cache_key, exc)

        return token

    def _build_headers(self, installation_id: int | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        auth_token = self.token
        if not auth_token and installation_id is not None:
            auth_token = self.get_installation_token(installation_id)
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        return headers

    def fetch_pr_files(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_id: int | None = None,
    ) -> list[PRFile]:
        headers = self._build_headers(installation_id)
        files: list[PRFile] = []
        page = 1
        per_page = 100

        with self._get_client() as client:
            while True:
                url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}/files"
                response = client.get(
                    url,
                    headers=headers,
                    params={"per_page": per_page, "page": page},
                )
                self._update_rate_limit(response)
                response.raise_for_status()
                items = response.json()
                if not items:
                    break

                for item in items:
                    files.append(
                        PRFile(
                            filename=item["filename"],
                            status=item.get("status", "modified"),
                            additions=item.get("additions", 0),
                            deletions=item.get("deletions", 0),
                            changes=item.get("changes", 0),
                            patch=item.get("patch"),
                        )
                    )

                if len(items) < per_page:
                    break
                page += 1

        return files

    def fetch_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str,
        installation_id: int | None = None,
    ) -> str | None:
        path_hash = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
        cache_key = f"file_content:{owner}/{repo}:{ref}:{path_hash}"

        if self.redis_client is not None:
            try:
                cached = self.redis_client.get(cache_key)
                if cached:
                    return cached.decode("utf-8") if isinstance(cached, bytes) else str(cached)
            except Exception as exc:
                logger.warning("Redis error reading %s: %s", cache_key, exc)

        headers = self._build_headers(installation_id)
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"

        with self._get_client() as client:
            response = client.get(url, headers=headers, params={"ref": ref})
            self._update_rate_limit(response)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()

        content_b64 = data.get("content", "")
        if not content_b64:
            return None

        decoded = base64.b64decode(content_b64).decode("utf-8", errors="replace")

        if self.redis_client is not None:
            try:
                self.redis_client.set(cache_key, decoded, ex=self.file_cache_ttl)
            except Exception as exc:
                logger.warning("Redis error caching %s: %s", cache_key, exc)

        return decoded

    def fetch_pr_head_sha(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_id: int | None = None,
    ) -> str | None:
        headers = self._build_headers(installation_id)
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}"
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data.get("head", {}).get("sha")


# ── Factory ────────────────────────────────────────────────────────────


def get_diff_fetcher(
    settings: Settings | None = None,
    *,
    mock_github: bool | None = None,
    redis_client: Any = None,
) -> BaseDiffFetcher:
    """Return MockDiffFetcher or GitHubDiffFetcher based on settings."""
    if settings is None:
        settings = get_settings()

    is_mock = mock_github if mock_github is not None else settings.mock_github
    if is_mock:
        return MockDiffFetcher()

    return GitHubDiffFetcher(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        redis_client=redis_client,
        token_ttl=settings.github_token_ttl,
        file_cache_ttl=settings.file_content_cache_ttl,
    )
