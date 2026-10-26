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


def get_vulnerability_family(f: Finding) -> str:
    """Derive coarse-grained vulnerability family for cross-source dedup matching.

    Ensures AST and LLM findings on the same line only merge if they describe
    the same vulnerability type (e.g. eval vs eval, not eval vs sql injection).
    """
    rule = (getattr(f, "rule_id", None) or "").upper()
    text = f"{f.title} {f.explanation} {f.category}".lower()

    # 1. Rule ID prefixes (AST heuristics)
    if "SQL" in rule:
        return "sql"
    if "EVAL" in rule:
        return "eval"
    if "CMD" in rule:
        return "command"
    if "XSS" in rule:
        return "xss"
    if "SECRET" in rule or "HARDCODED" in rule:
        return "secret"
    if "CRYPTO" in rule or "HASH" in rule:
        return "crypto"
    if "DESERIALIZ" in rule or "PICKLE" in rule or "YAML" in rule:
        return "deserialization"
    if "UNCLOSED" in rule or "LEAK" in rule:
        return "memory_leak"
    if "EXCEPT" in rule or "CATCH" in rule:
        return "empty_except"
    if "LOG" in rule:
        return "sensitive_log"
    if "SSRF" in rule:
        return "ssrf"
    if "JWT" in rule:
        return "jwt"
    if "DEBUG" in rule:
        return "debug"
    if "BIND" in rule:
        return "bind"

    # 2. Text-based detection from title and explanation
    if any(k in text for k in ("sql injection", "sqli", "sql query", "raw sql")):
        return "sql"
    if any(k in text for k in ("eval(", "exec(", "eval/exec", "dynamic code execution", "eval ")):
        return "eval"
    if "command injection" in text or "shell injection" in text or "os.system" in text:
        return "command"
    if "xss" in text or "cross-site scripting" in text or "innerhtml" in text:
        return "xss"
    if any(k in text for k in ("hardcoded secret", "api key", "private key", "hardcoded password", "hardcoded credential", "hardcoded token")):
        return "secret"
    if any(k in text for k in ("weak hash", "weak crypto", "md5", "sha1", "weak cipher")):
        return "crypto"
    if any(k in text for k in ("deserialization", "pickle", "yaml.load")):
        return "deserialization"
    if any(k in text for k in ("memory leak", "eventlistener", "unclosed file")):
        return "memory_leak"
    if any(k in text for k in ("empty except", "empty catch", "suppressed exception")):
        return "empty_except"
    if any(k in text for k in ("sensitive data in log", "logging sensitive", "sensitive information in log")):
        return "sensitive_log"
    if "ssrf" in text or "server-side request forgery" in text:
        return "ssrf"
    if "jwt" in text:
        return "jwt"
    if "debug mode" in text or "debug=true" in text:
        return "debug"
    if "bind" in text and "0.0.0.0" in text:
        return "bind"

    # Secondary word checks in title
    title_lower = f.title.lower()
    if "sql" in title_lower:
        return "sql"
    if "eval" in title_lower or "exec" in title_lower:
        return "eval"
    if "command" in title_lower:
        return "command"
    if "xss" in title_lower:
        return "xss"
    if "secret" in title_lower or "key" in title_lower:
        return "secret"
    if "crypto" in title_lower or "hash" in title_lower:
        return "crypto"
    if "pickle" in title_lower or "deserializ" in title_lower:
        return "deserialization"
    if "leak" in title_lower:
        return "memory_leak"

    # Fallback to category
    return f.category.lower()


def higher_severity(sev1: str, sev2: str) -> str:
    """Return the higher severity between sev1 and sev2."""
    order1 = SEVERITY_ORDER.get(sev1.lower(), 99)
    order2 = SEVERITY_ORDER.get(sev2.lower(), 99)
    return sev1 if order1 <= order2 else sev2


def higher_confidence(conf1: str, conf2: str) -> str:
    """Return the higher confidence between conf1 and conf2."""
    order1 = CONFIDENCE_ORDER.get(conf1.lower(), 0)
    order2 = CONFIDENCE_ORDER.get(conf2.lower(), 0)
    return conf1 if order1 >= order2 else conf2


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
        existing = dedup_map.get(key)
        if existing is None:
            # Per §3.6.4 & DEC-011: Cross-source dedup
            # Only match if same file, line, category, AND same vulnerability family.
            f_family = get_vulnerability_family(f)
            for candidate in dedup_map.values():
                if (
                    candidate.file_path == f.file_path
                    and candidate.line_start == f.line_start
                    and candidate.category == f.category
                    and candidate.source != f.source
                    and candidate.source != "merged"
                    and get_vulnerability_family(candidate) == f_family
                ):
                    existing = candidate
                    break

        if existing is None:
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
                rule_id=f.rule_id,
                raw_category=f.raw_category,
                suggested_fix=f.suggested_fix,
            )
        else:
            merged_count += 1
            # Severity & Confidence: always keep the higher of the two
            merged_severity = higher_severity(existing.severity, f.severity)
            merged_confidence = higher_confidence(existing.confidence, f.confidence)

            # Determine winner for primary text (title, explanation, remediation)
            existing_conf_val = CONFIDENCE_ORDER.get(existing.confidence.lower(), 0)
            new_conf_val = CONFIDENCE_ORDER.get(f.confidence.lower(), 0)

            if new_conf_val > existing_conf_val:
                # New finding has higher confidence
                winner = f
                loser_source = existing.source
            elif new_conf_val < existing_conf_val:
                # Existing finding has higher confidence
                winner = existing
                loser_source = f.source
            else:
                # Confidence tied: check severity (lower number in SEVERITY_ORDER is higher severity)
                existing_sev_val = SEVERITY_ORDER.get(existing.severity.lower(), 99)
                new_sev_val = SEVERITY_ORDER.get(f.severity.lower(), 99)
                if new_sev_val < existing_sev_val:
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

            # Update existing with winning metadata, merged severity/confidence, and merged source
            existing.title = winner.title
            existing.severity = merged_severity
            existing.confidence = merged_confidence
            existing.explanation = merged_explanation
            existing.remediation = winner.remediation or existing.remediation
            existing.source = "merged"
            existing.suggested_fix = winner.suggested_fix or existing.suggested_fix
            existing.raw_category = winner.raw_category or existing.raw_category
            if winner.rule_id:
                existing.rule_id = winner.rule_id

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
