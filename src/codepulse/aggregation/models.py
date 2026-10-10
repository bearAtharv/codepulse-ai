"""Unified models for finding aggregation, deduplication, and review delivery.

Normalizes findings from both the AST analysis engine (ASTFinding) and the
LLM analysis engine (LLMFindingItem) into a common dataclass shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from codepulse.analysis.heuristics.base import ASTFinding
from codepulse.analysis.llm_schemas import LLMFindingItem


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
        return cls(
            file_path=ast_f.file_path,
            line_start=ast_f.line_start,
            line_end=ast_f.line_end,
            severity=ast_f.severity.lower(),
            category=ast_f.category,
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

