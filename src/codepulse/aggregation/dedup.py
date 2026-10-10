"""Deduplication, sorting, and truncation of analysis findings.

Implements Section 3.6.4 and Step 14 of the architecture document:
- Deduplicates on (file_path, line_start, category, title).
- Merges colliding findings: highest confidence wins, other source attributed.
- Sorts by severity (critical first), file_path, and line_start.
- Truncates to GitHub Review API limit of 256 comments, ensuring critical
  findings are never dropped in favor of lower-severity findings.
"""

from __future__ import annotations

import logging
from typing import Sequence

from codepulse.aggregation.models import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    DeduplicationResult,
    Finding,
)

logger = logging.getLogger(__name__)

MAX_REVIEW_COMMENTS: int = 256


def deduplicate_and_sort(
    findings: Sequence[Finding],
    max_findings: int = MAX_REVIEW_COMMENTS,
) -> DeduplicationResult:
    """Deduplicate, sort, and truncate findings.

    Args:
        findings: Sequence of unified Finding instances.
        max_findings: Maximum number of findings to retain (defaults to 256).

    Returns:
        DeduplicationResult containing retained findings and truncation metadata.
    """
    total_raw = len(findings)
    dedup_map: dict[tuple[str, int, str, str], Finding] = {}
    merged_count = 0

    for f in findings:
        key = (f.file_path, f.line_start, f.category, f.title)
        if key not in dedup_map:
            # Create a copy so we do not mutate callers original objects
            dedup_map[key] = Finding(
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                severity=f.severity,
                category=f.category,
                title=f.title,
                explanation=f.explanation,
                remediation=f.remediation,
                confidence=f.confidence,
                source=f.source,
                raw_category=f.raw_category,
                suggested_fix=f.suggested_fix,
            )
        else:
            existing = dedup_map[key]
            merged_count += 1
            # Confidence comparison
            existing_conf_val = CONFIDENCE_ORDER.get(existing.confidence.lower(), 0)
            new_conf_val = CONFIDENCE_ORDER.get(f.confidence.lower(), 0)

            if new_conf_val > existing_conf_val:
                # New finding has higher confidence; keep its explanation and attributes
                winner = f
                loser_source = existing.source
            else:
                winner = existing
                loser_source = f.source

            # Build merged explanation
            attribution = f"Also detected by {loser_source}."
            if attribution not in winner.explanation:
                merged_explanation = f"{winner.explanation}\n\n{attribution}"
            else:
                merged_explanation = winner.explanation

            # Update existing with winning metadata and merged status
            existing.severity = winner.severity
            existing.confidence = winner.confidence
            existing.explanation = merged_explanation
            existing.remediation = winner.remediation or existing.remediation
            existing.source = "merged"
            existing.suggested_fix = winner.suggested_fix or existing.suggested_fix
            existing.raw_category = winner.raw_category or existing.raw_category

    # Sort: Severity (critical -> high -> medium -> low), then file_path, then line_start
    sorted_findings = sorted(
        dedup_map.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity.lower(), 99),
            item.file_path,
            item.line_start,
        ),
    )

    # Truncate to max_findings
    if len(sorted_findings) > max_findings:
        kept = sorted_findings[:max_findings]
        dropped = sorted_findings[max_findings:]
        truncated_count = len(dropped)

        # Invariant: Critical findings must never be dropped while non-critical are kept.
        # Check if any dropped finding is critical while non-critical findings exist in kept.
        critical_dropped = [d for d in dropped if d.severity.lower() == "critical"]
        non_critical_kept = [k for k in kept if k.severity.lower() != "critical"]
        if critical_dropped and non_critical_kept:
            # Rebalance to ensure critical findings are never sacrificed
            logger.warning(
                "Truncation rebalanced to prioritize %d critical findings over non-critical ones.",
                len(critical_dropped),
            )
            # Re-sort strictly prioritizing critical
            reordered = sorted(
                sorted_findings,
                key=lambda item: (
                    0 if item.severity.lower() == "critical" else 1,
                    SEVERITY_ORDER.get(item.severity.lower(), 99),
                    item.file_path,
                    item.line_start,
                ),
            )
            kept = reordered[:max_findings]
            dropped = reordered[max_findings:]
            truncated_count = len(dropped)
    else:
        kept = sorted_findings
        dropped = []
        truncated_count = 0

    return DeduplicationResult(
        findings=kept,
        total_raw=total_raw,
        merged_count=merged_count,
        truncated_count=truncated_count,
        dropped_findings=dropped,
    )
