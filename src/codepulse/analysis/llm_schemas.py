"""Pydantic schemas for LLM analysis responses and OWASP category handling.

Mirrors the response schema from architecture doc Section 3.4.3, plus the
canonical OWASP Top 10 mapping from Section 3.4.4.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Severity / Confidence enums (shared with AST findings) ─────────────


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


# ── OWASP Top 10 2021 canonical categories (Section 3.4.4) ────────────

VALID_CATEGORIES: frozenset[str] = frozenset(
    {
        "A01",
        "A02",
        "A03",
        "A04",
        "A05",
        "A06",
        "A07",
        "A08",
        "A09",
        "A10",
        "memory_leak",
    }
)

# Keyword → canonical category for remapping non-standard LLM output.
_CATEGORY_KEYWORDS: dict[str, str] = {
    "access control": "A01",
    "broken access": "A01",
    "authorization": "A01",
    "cryptographic": "A02",
    "crypto": "A02",
    "encryption": "A02",
    "hashing": "A02",
    "hash": "A02",
    "secret": "A02",
    "injection": "A03",
    "sql injection": "A03",
    "command injection": "A03",
    "xss": "A03",
    "cross-site scripting": "A03",
    "insecure design": "A04",
    "misconfiguration": "A05",
    "security misconfiguration": "A05",
    "outdated": "A06",
    "vulnerable component": "A06",
    "authentication": "A07",
    "identification": "A07",
    "integrity": "A08",
    "deserialization": "A08",
    "logging": "A09",
    "monitoring": "A09",
    "ssrf": "A10",
    "server-side request": "A10",
    "memory leak": "memory_leak",
    "memory": "memory_leak",
    "resource leak": "memory_leak",
}


def remap_category(raw_category: str) -> tuple[str, str | None]:
    """Validate and remap an LLM-returned category to a canonical OWASP code.

    Returns ``(canonical_category, raw_category_or_none)``.
    If the category is already valid, ``raw_category`` is ``None``.
    If remapped, ``raw_category`` preserves the original for auditing (§3.4.4).
    """
    if raw_category in VALID_CATEGORIES:
        return raw_category, None
    lower = raw_category.lower()
    for keyword, canonical in _CATEGORY_KEYWORDS.items():
        if keyword in lower:
            return canonical, raw_category
    # Fallback: can't remap — keep original as raw, default to A04 (Insecure Design)
    return "A04", raw_category


# ── LLM Response Schema (Section 3.4.3) ───────────────────────────────


class LLMFindingItem(BaseModel):
    """A single finding from the LLM response."""

    file_path: str
    line_start: int
    line_end: int
    severity: Severity
    category: str  # Raw from LLM; remapped after validation
    title: str = Field(max_length=200)
    explanation: str = Field(max_length=1000)
    remediation: str = Field(max_length=1000)
    confidence: Confidence

    # Set after remap; not part of the LLM response itself.
    raw_category: Optional[str] = None


class LLMTokenUsage(BaseModel):
    """Token usage metadata from the LLM response."""

    input: int = 0
    output: int = 0


class LLMResponseMetadata(BaseModel):
    """Metadata from the LLM response."""

    model_version: str = ""
    token_usage: LLMTokenUsage = Field(default_factory=LLMTokenUsage)


class LLMResponse(BaseModel):
    """Top-level LLM response matching the schema in §3.4.3.

    Pydantic's default is to ignore extra fields, which gives forward
    compatibility if the model returns additional metadata.
    """

    findings: list[LLMFindingItem] = Field(default_factory=list)
    metadata: LLMResponseMetadata = Field(default_factory=LLMResponseMetadata)

    model_config = {"extra": "ignore"}


# ── Gemini structured output schema dict ───────────────────────────────
# This is the JSON Schema passed to the Gemini API via response_schema.

GEMINI_RESPONSE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "line_start": {"type": "integer"},
                    "line_end": {"type": "integer"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "category": {"type": "string"},
                    "title": {"type": "string"},
                    "explanation": {"type": "string"},
                    "remediation": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                },
                "required": [
                    "file_path",
                    "line_start",
                    "line_end",
                    "severity",
                    "category",
                    "title",
                    "explanation",
                    "remediation",
                    "confidence",
                ],
            },
        },
        "metadata": {
            "type": "object",
            "properties": {
                "model_version": {"type": "string"},
                "token_usage": {
                    "type": "object",
                    "properties": {
                        "input": {"type": "integer"},
                        "output": {"type": "integer"},
                    },
                },
            },
        },
    },
    "required": ["findings", "metadata"],
}
