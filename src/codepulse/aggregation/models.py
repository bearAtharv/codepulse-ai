"""Unified models for finding aggregation, deduplication, and review delivery.

Normalizes findings from both the AST analysis engine (ASTFinding) and the
LLM analysis engine (LLMFindingItem) into a common dataclass shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from codepulse.analysis.heuristics.base import ASTFinding
from codepulse.analysis.llm_schemas import LLMFindingItem, VALID_CATEGORIES, remap_category


SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

CONFIDENCE_ORDER: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


def normalize_category(raw_category: str) -> str:
    """Normalize a category string to canonical OWASP code (A01-A10) or memory_leak.

    Guarantees output is <= 20 chars and within VALID_CATEGORIES.
    Unknown categories fall back safely via keyword remapping or default to A04.
    """
    raw = raw_category.strip()
    if ":" in raw:
        prefix = raw.split(":", 1)[0].strip()
        if prefix in VALID_CATEGORIES:
            return prefix
    if raw.lower() in ("memory leak", "memory_leak"):
        return "memory_leak"
    if raw in VALID_CATEGORIES:
        return raw
    canonical, _ = remap_category(raw)
    return canonical


@dataclass
class Finding:
    """Unified finding representation across AST and LLM engines."""

    file_path: str
    line_start: int
    line_end: int
    severity: str
    category: str
    title: str
    explanation: str
    remediation: str
    confidence: str
    source: str  # "ast" | "llm" | "merged"
    raw_category: str | None = None
    suggested_fix: str | None = None
    # Line mapping fields (computed against unified diff)
    diff_line: int | None = None
    diff_start_line: int | None = None
    diff_side: str = "RIGHT"
    is_in_diff: bool = True

    @classmethod
    def from_ast_finding(cls, ast_f: ASTFinding) -> Finding:
        """Adapter from Phase 3 ASTFinding to unified Finding."""
        canonical_cat = normalize_category(ast_f.category)

        return cls(
            file_path=ast_f.file_path,
            line_start=ast_f.line_start,
            line_end=ast_f.line_end,
            severity=ast_f.severity.lower(),
            category=canonical_cat,
            title=ast_f.title,
            explanation=ast_f.explanation,
            remediation=ast_f.remediation,
            confidence=ast_f.confidence.lower(),
            source="ast",
            raw_category=None,
            suggested_fix=None,
        )

    @classmethod
    def from_llm_finding(cls, llm_f: LLMFindingItem) -> Finding:
        """Adapter from Phase 4 LLMFindingItem to unified Finding."""
        return cls(
            file_path=llm_f.file_path,
            line_start=llm_f.line_start,
            line_end=llm_f.line_end,
            severity=llm_f.severity.value.lower() if hasattr(llm_f.severity, "value") else str(llm_f.severity).lower(),
            category=llm_f.category,
            title=llm_f.title,
            explanation=llm_f.explanation,
            remediation=llm_f.remediation,
            confidence=llm_f.confidence.value.lower() if hasattr(llm_f.confidence, "value") else str(llm_f.confidence).lower(),
            source="llm",
            raw_category=getattr(llm_f, "raw_category", None),
            suggested_fix=getattr(llm_f, "suggested_fix", None),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict for Celery task chains."""
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "source": self.source,
            "raw_category": self.raw_category,
            "suggested_fix": self.suggested_fix,
            "diff_line": self.diff_line,
            "diff_start_line": self.diff_start_line,
            "diff_side": self.diff_side,
            "is_in_diff": self.is_in_diff,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize from JSON-compatible dict."""
        return cls(
            file_path=data["file_path"],
            line_start=int(data["line_start"]),
            line_end=int(data["line_end"]),
            severity=data["severity"],
            category=data["category"],
            title=data["title"],
            explanation=data["explanation"],
            remediation=data["remediation"],
            confidence=data["confidence"],
            source=data["source"],
            raw_category=data.get("raw_category"),
            suggested_fix=data.get("suggested_fix"),
            diff_line=data.get("diff_line"),
            diff_start_line=data.get("diff_start_line"),
            diff_side=data.get("diff_side", "RIGHT"),
            is_in_diff=bool(data.get("is_in_diff", True)),
        )


@dataclass
class RepoContext:
    """Contextual metadata about the repository and PR being analyzed."""

    repository_full_name: str  # e.g. "owner/repo"
    pull_request_number: int
    head_sha: str = ""
    base_sha: str = ""
    pr_author: str = ""
    files_analyzed: int = 1
    analysis_duration_ms: int = 0
    model_version: str = "gemini-3.7-flash"

    @property
    def owner(self) -> str:
        if "/" in self.repository_full_name:
            return self.repository_full_name.split("/", 1)[0]
        return ""

    @property
    def repo(self) -> str:
        if "/" in self.repository_full_name:
            return self.repository_full_name.split("/", 1)[1]
        return self.repository_full_name


@dataclass
class DeduplicationResult:
    """Result of finding deduplication, sorting, and truncation."""

    findings: list[Finding]
    total_raw: int
    merged_count: int
    truncated_count: int
    dropped_findings: list[Finding] = field(default_factory=list)


@dataclass
class AggregationResult:
    """Complete outcome of the aggregation and GitHub posting pipeline."""

    review_id: int | str | None
    review_body: str
    comments_payload: list[dict[str, Any]]
    posted_findings: list[Finding]
    summary_stats: dict[str, Any]
    escalation_needed: bool = False
    raw_response: dict[str, Any] = field(default_factory=dict)

