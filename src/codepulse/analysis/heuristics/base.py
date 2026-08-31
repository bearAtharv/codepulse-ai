"""Base types and AST traversal helpers for the heuristic engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node


# ── Finding dataclass ──────────────────────────────────────────────────


@dataclass(frozen=True)
class ASTFinding:
    """A single finding produced by an AST heuristic."""

    rule_id: str
    category: str
    title: str
    severity: str  # critical|high|medium|low|info
    confidence: str  # high|medium|low
    file_path: str
    line_start: int  # 1-indexed
    line_end: int  # 1-indexed
    explanation: str
    remediation: str
    source: str = "ast"


# ── Sensitive-name detection (A02 / A09) ───────────────────────────────

SENSITIVE_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "private_key",
    "privatekey",
    "ssn",
    "credit_card",
    "creditcard",
)


def is_sensitive_name(name: str) -> bool:
    """Return *True* if *name* looks like it holds sensitive data."""
    lower = name.lower()
    return any(frag in lower for frag in SENSITIVE_FRAGMENTS)


# ── Tree-traversal helpers ─────────────────────────────────────────────


def find_nodes(node: "Node", node_type: str) -> list["Node"]:
    """Recursively collect every descendant (inclusive) with the given type."""
    results: list["Node"] = []
    _collect(node, node_type, results)
    return results


def _collect(node: "Node", node_type: str, acc: list["Node"]) -> None:
    if node.type == node_type:
        acc.append(node)
    for child in node.children:
        _collect(child, node_type, acc)


def find_ancestor(node: "Node", *node_types: str) -> "Node | None":
    """Walk up; return the first ancestor whose type is in *node_types*."""
    cur = node.parent
    while cur is not None:
        if cur.type in node_types:
            return cur
        cur = cur.parent
    return None


# ── Call-expression helpers (Python ``call`` / JS ``call_expression``) ─


def get_call_name(call_node: "Node") -> tuple[str | None, str | None]:
    """Return ``(object_name, method_name)`` for a call node.

    * ``foo.bar()``  →  ``("foo", "bar")``
    * ``bar()``      →  ``(None,  "bar")``
    * complex expr   →  ``(None,  None)``
    """
    func = call_node.child_by_field_name("function")
    if func is None:
        return None, None
    if func.type == "identifier":
        return None, func.text.decode()
    # Python: ``attribute``  |  JS: ``member_expression``
    if func.type in ("attribute", "member_expression"):
        attr_field = "attribute" if func.type == "attribute" else "property"
        attr = func.child_by_field_name(attr_field)
        obj = func.child_by_field_name("object")
        attr_name = attr.text.decode() if attr else None
        obj_name = obj.text.decode() if (obj and obj.type == "identifier") else None
        return obj_name, attr_name
    return None, None


def get_call_args(call_node: "Node") -> list["Node"]:
    """Return positional argument nodes from a call expression."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return []
    skip = {"(", ")", ",", "keyword_argument", "**", "*"}
    return [c for c in args_node.children if c.type not in skip and c.is_named]


def get_keyword_arg(call_node: "Node", keyword: str) -> "Node | None":
    """Find a Python keyword argument by name; return its *value* node."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return None
    for child in args_node.children:
        if child.type == "keyword_argument":
            name_node = child.child_by_field_name("name")
            if name_node and name_node.text.decode() == keyword:
                return child.child_by_field_name("value")
    return None


def node_text(node: "Node") -> str:
    """Return the full source text of *node* as a decoded string."""
    return node.text.decode("utf-8", errors="replace")


def string_literal_value(node: "Node") -> str | None:
    """Extract the literal content from a simple string/template node.

    Returns *None* if the node has interpolation or is not a string.
    """
    for child in node.children:
        if child.type in ("string_content", "string_fragment"):
            return child.text.decode("utf-8", errors="replace")
    return None


def has_interpolation(string_node: "Node") -> bool:
    """True if a Python string contains f-string ``{…}`` interpolation."""
    return any(c.type == "interpolation" for c in string_node.children)


def has_template_substitution(template_node: "Node") -> bool:
    """True if a JS template_string contains ``${…}`` substitutions."""
    return any(c.type == "template_substitution" for c in template_node.children)
