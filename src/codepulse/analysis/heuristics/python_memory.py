"""Python memory-leak AST heuristics (architecture doc §3.3.4).

Detects resource handles (``open()``, DB connections) used outside
a ``with`` statement, which may lead to unclosed file/connection leaks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from codepulse.analysis.heuristics.base import (
    ASTFinding,
    find_ancestor,
    find_nodes,
    get_call_name,
)

if TYPE_CHECKING:
    from tree_sitter import Tree

# Resource-opening functions whose result must be managed via ``with``.
_RESOURCE_OPENERS = frozenset({"open"})


def check_unclosed_resources(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """Detect ``open()`` calls whose result is *not* managed by a ``with`` statement.

    Section 3.3.4:  "File/DB connection opened without ``with`` statement or
    explicit ``close()`` in the same scope"
    """
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        _, name = get_call_name(call)
        if name not in _RESOURCE_OPENERS:
            continue
        # Safe if the call IS the resource expression of a ``with_item``
        if find_ancestor(call, "with_item"):
            continue
        findings.append(
            ASTFinding(
                rule_id="MEM-PYTHON-UNCLOSED-RESOURCE",
                category="Memory Leak",
                title="Resource opened without context manager",
                severity="medium",
                confidence="medium",
                file_path=filename,
                line_start=call.start_point[0] + 1,
                line_end=call.end_point[0] + 1,
                explanation=(
                    "Calling open() without a ``with`` statement risks leaving "
                    "the file handle open if an exception occurs before .close()."
                ),
                remediation="with open('file') as f: …",
            )
        )
    return findings


PYTHON_MEMORY_HEURISTICS = [
    check_unclosed_resources,
]
