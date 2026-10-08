"""Finding aggregation, deduplication, and GitHub review posting (Phase 5).

Provides:
- Deduplication and confidence-weighted merging of AST and LLM findings.
- Severity sorting and safe truncation at GitHub's 256-comment cap.
- Line mapping against unified diff hunks with context-line remapping.
- Comment formatting with severity badges and remediation suggestions.
- Review summary composition with methodology disclosure.
- GitHub Review API posting client and in-memory mock poster.
"""

from __future__ import annotations

from codepulse.aggregation.comments import format_finding_comment
from codepulse.aggregation.dedup import (
    MAX_REVIEW_COMMENTS,
    deduplicate_and_sort,
)
from codepulse.aggregation.engine import (
    aggregate_and_post,
    check_tier2_escalation,
    persist_findings_stub,
)
from codepulse.aggregation.github_poster import (
    BaseGitHubPoster,
    GitHubPoster,
    GitHubReviewPayload,
    MockGitHubPoster,
    ReviewCommentPayload,
    get_github_poster,
)
from codepulse.aggregation.line_mapping import (
    map_findings_to_diff_positions,
    parse_unified_diff,
)
from codepulse.aggregation.models import (
    AggregationResult,
    DeduplicationResult,
    Finding,
    RepoContext,
)
from codepulse.aggregation.summary import compose_review_summary

__all__ = [
    "AggregationResult",
    "BaseGitHubPoster",
    "DeduplicationResult",
    "Finding",
    "GitHubPoster",
    "GitHubReviewPayload",
    "MAX_REVIEW_COMMENTS",
    "MockGitHubPoster",
    "RepoContext",
    "ReviewCommentPayload",
    "aggregate_and_post",
    "check_tier2_escalation",
    "compose_review_summary",
    "deduplicate_and_sort",
    "format_finding_comment",
    "get_github_poster",
    "map_findings_to_diff_positions",
    "parse_unified_diff",
    "persist_findings_stub",
]
