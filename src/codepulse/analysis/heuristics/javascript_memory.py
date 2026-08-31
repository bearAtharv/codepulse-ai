"""JavaScript / TypeScript memory-leak AST heuristics (§3.3.4).

Detects ``addEventListener`` without a corresponding ``removeEventListener``
in the same file — a common source of DOM event listener leaks, especially
in Single-Page Applications.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from codepulse.analysis.heuristics.base import (
    ASTFinding,
    find_nodes,
    get_call_name,
    get_call_args,
    string_literal_value,
)

if TYPE_CHECKING:
    from tree_sitter import Tree


def check_event_listener_leak(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """Detect addEventListener calls with no matching removeEventListener.

    Section 3.3.4: "addEventListener without corresponding
    removeEventListener in cleanup/unmount paths"
    """
    add_calls: list[tuple[str, "..."]] = []  # (event_name, node)
    remove_events: set[str] = set()

    for call in find_nodes(tree.root_node, "call_expression"):
        _, method = get_call_name(call)
        if method == "addEventListener":
            args = get_call_args(call)
            if args and args[0].type == "string":
                event = string_literal_value(args[0])
                if event:
                    add_calls.append((event, call))
        elif method == "removeEventListener":
            args = get_call_args(call)
            if args and args[0].type == "string":
                event = string_literal_value(args[0])
                if event:
                    remove_events.add(event)

    findings: list[ASTFinding] = []
    for event_name, call in add_calls:
        if event_name not in remove_events:
            findings.append(
                ASTFinding(
                    rule_id="MEM-JS-EVENT-LISTENER-LEAK",
                    category="Memory Leak",
                    title=f"addEventListener('{event_name}') without removeEventListener",
                    severity="medium",
                    confidence="medium",
                    file_path=filename,
                    line_start=call.start_point[0] + 1,
                    line_end=call.end_point[0] + 1,
                    explanation=(
                        "Adding an event listener without a corresponding "
                        "removeEventListener in cleanup/unmount paths causes a "
                        "DOM event listener leak, preventing garbage collection."
                    ),
                    remediation=(
                        "Store the handler reference and call "
                        "removeEventListener in componentWillUnmount / useEffect "
                        "cleanup / ngOnDestroy."
                    ),
                )
            )
    return findings


JS_MEMORY_HEURISTICS = [
    check_event_listener_leak,
]
