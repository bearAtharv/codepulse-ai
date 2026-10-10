"""Formatting for GitHub inline review comment bodies.

Implements Section 3.6.2 of the architecture document:
- Severity emoji badges (🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low, ℹ️ Info).
- OWASP category label.
- Finding title and explanation.
- Suggested fix in markdown ```suggestion block when applicable.
- Confidence level and source attribution.
"""

from __future__ import annotations

from codepulse.aggregation.models import Finding

SEVERITY_BADGES: dict[str, str] = {
    "critical": "🔴 **Critical**",
    "high": "🟠 **High**",
    "medium": "🟡 **Medium**",
    "low": "🔵 **Low**",
}


def format_finding_comment(finding: Finding) -> str:
    """Format a Finding into a markdown inline comment body.

    Args:
        finding: Unified Finding instance.

    Returns:
        Markdown string formatted for GitHub PR review comment.
    """
    badge = SEVERITY_BADGES.get(finding.severity.lower(), f"**{finding.severity.capitalize()}**")
    category_label = f"`{finding.category}`"

    parts = [
        f"{badge} | {category_label} — **{finding.title}**",
        "",
        finding.explanation,
    ]

    # Remediation / Suggestion
    if finding.suggested_fix and finding.suggested_fix.strip():
        parts.extend([
            "",
            "**Suggested Fix:**",
            "```suggestion",
            finding.suggested_fix.strip(),
            "```",
        ])
    elif finding.remediation and finding.remediation.strip():
        parts.extend([
            "",
            f"**Remediation:** {finding.remediation.strip()}",
        ])

    # Metadata footer
    source_label = finding.source.upper()
    confidence_label = finding.confidence.capitalize()
    footer = f"---\n*Confidence:* {confidence_label} | *Source:* {source_label}"
    if finding.raw_category:
        footer += f" | *Original Category:* `{finding.raw_category}`"

    parts.extend(["", footer])
    return "\n".join(parts)
