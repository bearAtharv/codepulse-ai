"""LLM client abstraction — real Gemini API and mock implementations.

§3.4.7 defenses built into the real client:
- System instruction set once at init (defense #1: input/instruction separation)
- No function declarations (defense #5: no tool use)
- Structured output mode (defense #2: output schema enforcement)

The mock client returns pattern-aware canned responses for testing.
"""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from codepulse.analysis.llm_schemas import (
    Confidence,
    LLMFindingItem,
    LLMResponse,
    LLMResponseMetadata,
    LLMTokenUsage,
    Severity,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    """Abstract base for LLM clients."""

    @abstractmethod
    def analyze(
        self,
        system_instruction: str,
        user_message: str,
        *,
        model: str = "gemini-3.7-flash",
    ) -> LLMResponse:
        """Send a prompt and return a structured LLM response."""
        ...


# ═══════════════════════════════════════════════════════════════════════
# Real Gemini Client
# ═══════════════════════════════════════════════════════════════════════


class GeminiClient(BaseLLMClient):
    """Real Gemini API client using the ``google-genai`` SDK (§11).

    Configured with structured output mode (§3.4.3) and no tool use (§3.4.7).
    """

    def __init__(self, api_key: str, default_model: str = "gemini-3.7-flash") -> None:
        from google import genai

        self._genai_client = genai.Client(api_key=api_key)
        self._default_model = default_model

    def analyze(
        self,
        system_instruction: str,
        user_message: str,
        *,
        model: str | None = None,
    ) -> LLMResponse:
        from google.genai import types

        use_model = model or self._default_model

        response = self._genai_client.models.generate_content(
            model=use_model,
            contents=user_message,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                response_schema=LLMResponse,
                temperature=0.1,  # Low temperature for deterministic analysis
            ),
        )

        # Parse the structured JSON response
        raw_text = response.text
        data = json.loads(raw_text)
        parsed = LLMResponse.model_validate(data)

        # Populate token usage from the API response if available
        if response.usage_metadata:
            parsed.metadata.token_usage = LLMTokenUsage(
                input=response.usage_metadata.prompt_token_count or 0,
                output=response.usage_metadata.candidates_token_count or 0,
            )
        parsed.metadata.model_version = use_model

        return parsed


# ═══════════════════════════════════════════════════════════════════════
# Mock LLM Client
# ═══════════════════════════════════════════════════════════════════════

# Patterns the mock client detects in prompt content, along with the
# canned finding it returns for each.  This covers multiple OWASP
# categories so that mock-mode tests exercise category remapping and
# the full schema.

_MOCK_PATTERNS: list[tuple[re.Pattern[str], LLMFindingItem]] = [
    # ── A03: SQL Injection ──
    (
        re.compile(r"(execute|query)\s*\(.*[\+f\"\`].*(?:SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
        LLMFindingItem(
            file_path="__PLACEHOLDER__",
            line_start=1,
            line_end=1,
            severity=Severity.critical,
            category="A03",
            title="SQL injection via string interpolation",
            explanation=(
                "Building SQL queries with string concatenation or interpolation "
                "allows attackers to inject arbitrary SQL commands."
            ),
            remediation="Use parameterised queries with bound parameters.",
            confidence=Confidence.high,
        ),
    ),
    # ── A03: eval / exec ──
    (
        re.compile(r"\beval\s*\(|\bexec\s*\("),
        LLMFindingItem(
            file_path="__PLACEHOLDER__",
            line_start=1,
            line_end=1,
            severity=Severity.high,
            category="A03",
            title="Code injection via eval/exec",
            explanation=(
                "eval() or exec() executes arbitrary code. If user input reaches "
                "this call, an attacker can run arbitrary code on the server."
            ),
            remediation="Use ast.literal_eval() or a whitelist-based dispatcher.",
            confidence=Confidence.high,
        ),
    ),
    # ── A02: Hardcoded secrets ──
    (
        re.compile(
            r"(?:password|api_key|secret|token|private_key)\s*[=:]\s*[\"'][^\"']+[\"']",
            re.IGNORECASE,
        ),
        LLMFindingItem(
            file_path="__PLACEHOLDER__",
            line_start=1,
            line_end=1,
            severity=Severity.high,
            category="A02",
            title="Hard-coded secret detected",
            explanation=(
                "Secrets embedded in source code can be extracted from version "
                "control history and cannot be rotated without a code change."
            ),
            remediation="Load secrets from environment variables or a secrets manager.",
            confidence=Confidence.medium,
        ),
    ),
    # ── A02: Weak hashing ──
    (
        re.compile(r"hashlib\.(md5|sha1)\b|crypto\.createHash\s*\(\s*[\"'](md5|sha1)[\"']"),
        LLMFindingItem(
            file_path="__PLACEHOLDER__",
            line_start=1,
            line_end=1,
            severity=Severity.medium,
            category="Weak Hashing",  # Non-standard — exercises remapping to A02
            title="Use of weak hash algorithm",
            explanation=(
                "MD5 and SHA-1 are cryptographically broken. They must not be "
                "used for password hashing, integrity verification, or signatures."
            ),
            remediation="Use SHA-256 or bcrypt/argon2 for password hashing.",
            confidence=Confidence.medium,
        ),
    ),
    # ── A08: Dangerous deserialization ──
    (
        re.compile(r"pickle\.(loads?|dump)\b|yaml\.load\s*\("),
        LLMFindingItem(
            file_path="__PLACEHOLDER__",
            line_start=1,
            line_end=1,
            severity=Severity.critical,
            category="Deserialization",  # Non-standard — exercises remapping to A08
            title="Unsafe deserialization detected",
            explanation=(
                "pickle.loads() and yaml.load() without SafeLoader can execute "
                "arbitrary code embedded in the serialised data."
            ),
            remediation="Use json.loads() or yaml.safe_load().",
            confidence=Confidence.high,
        ),
    ),
    # ── A04: Empty exception handling ──
    (
        re.compile(r"except\s*:\s*\n\s*pass|catch\s*\([^)]*\)\s*\{\s*\}"),
        LLMFindingItem(
            file_path="__PLACEHOLDER__",
            line_start=1,
            line_end=1,
            severity=Severity.medium,
            category="A04",
            title="Empty exception handler silences errors",
            explanation=(
                "Catching exceptions with an empty handler hides bugs and makes "
                "debugging extremely difficult in production."
            ),
            remediation="Log the exception at minimum: logger.exception(e)",
            confidence=Confidence.high,
        ),
    ),
    # ── memory_leak: unclosed resources ──
    (
        re.compile(r"(?<!\bwith\s)open\s*\(|addEventListener\s*\("),
        LLMFindingItem(
            file_path="__PLACEHOLDER__",
            line_start=1,
            line_end=1,
            severity=Severity.medium,
            category="memory_leak",
            title="Potential resource leak",
            explanation=(
                "Resources opened without proper cleanup (context managers, "
                "removeEventListener) may cause leaks."
            ),
            remediation="Use a context manager (with statement) or register cleanup handlers.",
            confidence=Confidence.medium,
        ),
    ),
]


class MockLLMClient(BaseLLMClient):
    """Pattern-aware mock that returns realistic canned responses.

    Inspects the user message for known vulnerability patterns and builds
    an ``LLMResponse`` with plausible findings.  Clean code gets empty
    findings.  This makes mock-mode tests exercise category remapping,
    schema parsing, and the full validation pipeline.
    """

    def analyze(
        self,
        system_instruction: str,
        user_message: str,
        *,
        model: str = "gemini-3.7-flash",
    ) -> LLMResponse:
        findings: list[LLMFindingItem] = []

        # Extract file paths from CODE_DIFF blocks
        file_paths = re.findall(
            r"### Chunk \d+: (\S+)", user_message
        )
        default_file = file_paths[0] if file_paths else "unknown.py"

        for pattern, template in _MOCK_PATTERNS:
            if pattern.search(user_message):
                # Clone the template with the actual file path
                finding = template.model_copy(
                    update={"file_path": default_file}
                )
                findings.append(finding)

        # Estimate token counts (rough: 4 chars ≈ 1 token)
        input_tokens = len(user_message) // 4
        output_text = json.dumps(
            {"findings": [f.model_dump() for f in findings]}, default=str
        )
        output_tokens = len(output_text) // 4

        return LLMResponse(
            findings=findings,
            metadata=LLMResponseMetadata(
                model_version=f"mock-{model}",
                token_usage=LLMTokenUsage(
                    input=input_tokens,
                    output=output_tokens,
                ),
            ),
        )


# ── Factory ────────────────────────────────────────────────────────────


def get_llm_client(
    *,
    mock_llm: bool = True,
    api_key: str = "",
    default_model: str = "gemini-3.7-flash",
) -> BaseLLMClient:
    """Return the appropriate LLM client based on configuration."""
    if mock_llm:
        logger.info("Using MockLLMClient (MOCK_LLM=true)")
        return MockLLMClient()
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY must be set when MOCK_LLM=false. "
            "Set the GEMINI_API_KEY environment variable."
        )
    logger.info("Using GeminiClient with model %s", default_model)
    return GeminiClient(api_key=api_key, default_model=default_model)
