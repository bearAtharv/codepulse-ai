"""AST analysis engine — main entry point (architecture doc §3.3).

Usage::

    from codepulse.analysis.ast_engine import analyze_chunk

    findings = analyze_chunk(
        source='eval(user_input)',
        filename='app.py',
        modified_lines={1},          # optional diff-aware filtering
    )
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

from codepulse.analysis.languages import detect_language, get_parser
from codepulse.analysis.heuristics.base import ASTFinding

# ── Heuristic imports ──────────────────────────────────────────────────

from codepulse.analysis.heuristics.python import PYTHON_HEURISTICS
from codepulse.analysis.heuristics.javascript import JS_HEURISTICS

if TYPE_CHECKING:
    from tree_sitter import Tree

HeuristicFn = Callable[["Tree", str], list[ASTFinding]]

# Language → list of heuristic functions
_HEURISTIC_REGISTRY: dict[str, list[HeuristicFn]] = {
    "python": PYTHON_HEURISTICS,
    "javascript": JS_HEURISTICS,
    "typescript": JS_HEURISTICS,
    "tsx": JS_HEURISTICS,
}


def analyze_chunk(
    source: str,
    filename: str,
    *,
    language: str | None = None,
    modified_lines: set[int] | None = None,
) -> list[ASTFinding]:
    """Run all applicable AST heuristics on a source-code chunk.

    Args:
        source: The source code string to analyse.
        filename: File path (used for language detection and in findings).
        language: Override automatic language detection.
        modified_lines: If provided, only return findings whose line range
            overlaps these 1-indexed line numbers (Section 3.3.2 diff-aware
            filtering).

    Returns:
        A list of :class:`ASTFinding` objects.  May be empty for clean code
        or unsupported languages.
    """
    lang = language or detect_language(filename)
    if lang is None or lang not in _HEURISTIC_REGISTRY:
        return []

    parser = get_parser(lang)
    tree = parser.parse(source.encode("utf-8"))

    heuristics = _HEURISTIC_REGISTRY[lang]
    findings: list[ASTFinding] = []
    for heuristic in heuristics:
        findings.extend(heuristic(tree, filename))

    # Diff-aware filtering (Section 3.3.2)
    if modified_lines is not None:
        findings = [
            f
            for f in findings
            if any(
                line in modified_lines
                for line in range(f.line_start, f.line_end + 1)
            )
        ]

    return findings
