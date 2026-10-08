"""GitHub Pull Request Review posting client and mock implementation.

Implements Section 3.6 of the architecture document:
- PR Review API interaction: POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews
- Single atomic review with top-level summary body and inline comments array.
- Event is always "COMMENT" (§3.6.2).
- MOCK_GITHUB=true mode that validates payload shape and records reviews in memory.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx
from pydantic import BaseModel, Field

from codepulse.config import Settings, get_settings

logger = logging.getLogger(__name__)


# ── Schemas for GitHub Review API (Section 3.6.1) ──────────────────────


class ReviewCommentPayload(BaseModel):
    """Schema for an inline comment within a pull request review."""

    path: str = Field(..., description="Relative file path in repository")
    line: int = Field(..., description="Line in diff hunk for comment")
    side: str = Field(default="RIGHT", description="Diff side: RIGHT (added) or LEFT (deleted)")
    body: str = Field(..., description="Markdown comment body")
    start_line: int | None = Field(default=None, description="Starting line for multi-line comment")
    start_side: str | None = Field(default=None, description="Side of starting line for multi-line comment")


class GitHubReviewPayload(BaseModel):
    """Schema for POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews payload."""

    event: str = Field(default="COMMENT", description="Review event action (always COMMENT per §3.6.2)")
    body: str = Field(..., description="Top-level markdown review summary")
    comments: list[ReviewCommentPayload] = Field(
        default_factory=list,
        description="Inline comments placed on modified diff lines (max 256 per §3.6.4)",
    )
    commit_id: str | None = Field(default=None, description="SHA of commit to review")


# ── Poster Interface ───────────────────────────────────────────────────


class BaseGitHubPoster(ABC):
    """Abstract base class for posting PR reviews to GitHub."""

    @abstractmethod
    def post_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        payload: dict[str, Any] | GitHubReviewPayload,
    ) -> dict[str, Any]:
        """Post a pull request review.

        Args:
            owner: Repository owner/organization.
            repo: Repository name.
            pull_number: Pull request number.
            payload: Review payload conforming to GitHub Review API schema.

        Returns:
            Dictionary response from GitHub API or mock response.
        """
        ...


# ── Mock GitHub Poster ─────────────────────────────────────────────────


class MockGitHubPoster(BaseGitHubPoster):
    """In-memory mock poster for tests and local development (MOCK_GITHUB=true).

    Strictly validates the payload against the GitHub Review API structure and
    records posted reviews for inspection in test assertions.
    """

    def __init__(self) -> None:
        self.posted_reviews: list[dict[str, Any]] = []

    def post_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        payload: dict[str, Any] | GitHubReviewPayload,
    ) -> dict[str, Any]:
        # Validate payload structure
        if isinstance(payload, GitHubReviewPayload):
            validated_model = payload
        elif isinstance(payload, dict):
            # Check required top-level keys before validation for explicit error reporting
            for required_key in ("event", "body", "comments"):
                if required_key not in payload:
                    raise ValueError(f"GitHub review payload missing required key: {required_key!r}")

            # Check required keys for each comment
            comments = payload.get("comments", [])
            if not isinstance(comments, list):
                raise ValueError("GitHub review payload 'comments' must be a list")

            for i, comment in enumerate(comments):
                if not isinstance(comment, dict):
                    raise ValueError(f"Comment at index {i} must be a dictionary")
                for c_key in ("path", "line", "side", "body"):
                    if c_key not in comment:
                        raise ValueError(f"Comment at index {i} missing required key: {c_key!r}")

            validated_model = GitHubReviewPayload.model_validate(payload)
        else:
            raise ValueError(f"Expected dict or GitHubReviewPayload, got {type(payload).__name__}")

        data = validated_model.model_dump(exclude_none=True)

        record = {
            "owner": owner,
            "repo": repo,
            "pull_number": pull_number,
            "payload": data,
        }
        self.posted_reviews.append(record)

        review_id = 123456789 + len(self.posted_reviews)
        logger.info(
            "[MOCK GITHUB] Posted review #%d on %s/%s#%d with %d comments (event=%s)",
            review_id,
            owner,
            repo,
            pull_number,
            len(data.get("comments", [])),
            data.get("event"),
        )

        return {
            "id": review_id,
            "node_id": f"MDE3OlB1bGxSZXF1ZXN0UmV2aWV3{review_id}",
            "html_url": f"https://github.com/{owner}/{repo}/pull/{pull_number}#pullrequestreview-{review_id}",
            "user": {"login": "codepulse-ai[bot]", "id": 98765432},
            "body": data.get("body", ""),
            "state": data.get("event", "COMMENT"),
            "commit_id": data.get("commit_id", "mock_head_sha"),
            "submitted_at": "2026-10-08T16:00:00Z",
        }

    @property
    def last_payload(self) -> dict[str, Any] | None:
        """Return the payload of the most recently posted review."""
        if not self.posted_reviews:
            return None
        return self.posted_reviews[-1]["payload"]

    def clear(self) -> None:
        """Clear recorded reviews."""
        self.posted_reviews.clear()


# ── Real GitHub Poster ─────────────────────────────────────────────────


class GitHubPoster(BaseGitHubPoster):
    """Production GitHub client using httpx to call the Review API.

    Authenticates using a GitHub App installation token.
    """

    def __init__(
        self,
        token: str | None = None,
        base_url: str = "https://api.github.com",
        timeout: float = 30.0,
    ) -> None:
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def post_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        payload: dict[str, Any] | GitHubReviewPayload,
    ) -> dict[str, Any]:
        if isinstance(payload, GitHubReviewPayload):
            data = payload.model_dump(exclude_none=True)
        elif isinstance(payload, dict):
            validated = GitHubReviewPayload.model_validate(payload)
            data = validated.model_dump(exclude_none=True)
        else:
            raise ValueError(f"Expected dict or GitHubReviewPayload, got {type(payload).__name__}")

        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}/reviews"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        logger.info(
            "Posting review to %s with %d inline comments",
            url,
            len(data.get("comments", [])),
        )

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, json=data, headers=headers)
            response.raise_for_status()
            return response.json()


# ── Factory ────────────────────────────────────────────────────────────


def get_github_poster(
    settings: Settings | None = None,
    *,
    mock_github: bool | None = None,
    token: str | None = None,
    base_url: str = "https://api.github.com",
) -> BaseGitHubPoster:
    """Return configured GitHub review poster based on settings or parameters."""
    if settings is None:
        settings = get_settings()

    is_mock = mock_github if mock_github is not None else settings.mock_github

    if is_mock:
        logger.info("Using MockGitHubPoster (MOCK_GITHUB=true)")
        return MockGitHubPoster()

    return GitHubPoster(token=token, base_url=base_url)
