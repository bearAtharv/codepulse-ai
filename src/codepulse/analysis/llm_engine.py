"""LLM analysis engine — main entry point (architecture doc §3.4).

Usage::

    from codepulse.analysis.llm_engine import analyze_llm
    from codepulse.analysis.llm_prompt import DiffChunk

    result = analyze_llm(
        chunks=[DiffChunk(file_path="app.py", hunk_header="@@ ...", content="...")],
        repo_name="org/repo",
        language="python",
    )
    for finding in result.findings:
        print(finding.title, finding.category)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from pydantic import ValidationError

from codepulse.analysis.llm_client import BaseLLMClient, MockLLMClient, get_llm_client
from codepulse.analysis.llm_prompt import DiffChunk, build_prompt, compute_prompt_hash
from codepulse.analysis.llm_schemas import (
    LLMFindingItem,
    LLMResponse,
    LLMResponseMetadata,
    LLMTokenUsage,
    remap_category,
)

logger = logging.getLogger(__name__)


@dataclass
class LLMAnalysisResult:
    """Result of LLM analysis for a batch of diff chunks."""

    findings: list[LLMFindingItem] = field(default_factory=list)
    metadata: LLMResponseMetadata = field(default_factory=LLMResponseMetadata)
    prompt_hash: str = ""
    analysis_status: str = "ok"  # "ok" | "llm_error"
    error_message: str = ""


def analyze_llm(
    chunks: list[DiffChunk],
    repo_name: str,
    language: str,
    *,
    client: BaseLLMClient | None = None,
    model: str = "gemini-3.7-flash",
    mock_llm: bool = True,
    api_key: str = "",
    directives: list[str] | None = None,
) -> LLMAnalysisResult:
    """Run LLM analysis on a batch of diff chunks (§3.4, Step 13).

    Args:
        chunks: Diff chunks to analyse.
        repo_name: Repository full name (e.g. "org/repo").
        language: Primary language of the code.
        client: Optional pre-configured LLM client. If not provided,
            one is created based on ``mock_llm`` and ``api_key``.
        model: Gemini model to use.
        mock_llm: Whether to use the mock client.
        api_key: Gemini API key (required when ``mock_llm=False``).
        directives: OWASP categories to focus on (default: all 10).

    Returns:
        An ``LLMAnalysisResult`` with validated findings and metadata.
    """
    if not chunks:
        return LLMAnalysisResult(analysis_status="ok")

    # Build prompt
    system_instruction, user_message = build_prompt(
        repo_name=repo_name,
        language=language,
        chunks=chunks,
        directives=directives,
    )
    prompt_hash = compute_prompt_hash(user_message)

    # Get or create client
    if client is None:
        client = get_llm_client(
            mock_llm=mock_llm,
            api_key=api_key,
            default_model=model,
        )

    # Collect file paths from chunks for output validation (§3.4.7 defense #4)
    valid_file_paths = {chunk.file_path for chunk in chunks}

    # Call LLM with retry-once on schema validation failure (§3.4.3 / Branch E)
    response: LLMResponse | None = None
    last_error = ""
    for attempt in range(2):  # retry once
        try:
            response = client.analyze(
                system_instruction=system_instruction,
                user_message=user_message,
                model=model,
            )
            break
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            last_error = f"Attempt {attempt + 1}: {type(exc).__name__}: {exc}"
            logger.warning("LLM response validation failed: %s", last_error)
            continue
        except Exception as exc:
            last_error = f"Attempt {attempt + 1}: {type(exc).__name__}: {exc}"
            logger.error("LLM API call failed: %s", last_error)
            break  # Don't retry non-validation errors

    if response is None:
        logger.error(
            "LLM analysis failed after retries: %s — falling back to AST-only",
            last_error,
        )
        return LLMAnalysisResult(
            prompt_hash=prompt_hash,
            analysis_status="llm_error",
            error_message=last_error,
        )

    # Post-process findings
    validated_findings: list[LLMFindingItem] = []
    for finding in response.findings:
        # §3.4.7 defense #4: discard findings referencing files not in the prompt
        if finding.file_path not in valid_file_paths:
            logger.warning(
                "Discarded finding referencing unknown file '%s' "
                "(possible prompt injection). Valid files: %s",
                finding.file_path,
                valid_file_paths,
            )
            continue

        # §3.4.4: remap non-standard categories
        canonical, raw = remap_category(finding.category)
        finding.category = canonical
        finding.raw_category = raw

        validated_findings.append(finding)

    return LLMAnalysisResult(
        findings=validated_findings,
        metadata=response.metadata,
        prompt_hash=prompt_hash,
        analysis_status="ok",
    )
