"""JavaScript / TypeScript OWASP Top-10 AST heuristics (§3.3.3).

Works with both JavaScript and TypeScript tree-sitter grammars since
the relevant node types are identical (``call_expression``,
``member_expression``, ``binary_expression``, ``template_string``, etc.).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from codepulse.analysis.heuristics.base import (
    ASTFinding,
    find_nodes,
    get_call_args,
    get_call_name,
    has_template_substitution,
    is_sensitive_name,
    string_literal_value,
)

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


# ── A03: Injection ─────────────────────────────────────────────────────


def check_eval(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A03 — Use of ``eval()``."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call_expression"):
        _, name = get_call_name(call)
        if name != "eval":
            continue
        findings.append(
            ASTFinding(
                rule_id="OWASP-A03-EVAL",
                category="A03: Injection",
                title="Use of eval() is a code-injection risk",
                severity="high",
                confidence="high",
                file_path=filename,
                line_start=call.start_point[0] + 1,
                line_end=call.end_point[0] + 1,
                explanation=(
                    "eval() executes arbitrary code.  If user input reaches this "
                    "call an attacker can run arbitrary JavaScript."
                ),
                remediation="Use JSON.parse() for data or a sandboxed interpreter.",
            )
        )
    return findings


_JS_SQL_METHODS = frozenset({"query", "execute", "raw"})


def check_sql_injection(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A03 — SQL injection via template literal or string concat in query()."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call_expression"):
        _, method = get_call_name(call)
        if method not in _JS_SQL_METHODS:
            continue
        args = get_call_args(call)
        if not args:
            continue
        first = args[0]
        if first.type == "binary_expression":
            left = first.child_by_field_name("left")
            if left and left.type == "string":
                findings.append(_js_sql_finding(call, filename, "string concatenation"))
        elif first.type == "template_string" and has_template_substitution(first):
            findings.append(_js_sql_finding(call, filename, "template literal interpolation"))
    return findings


def _js_sql_finding(node: "Node", filename: str, detail: str) -> ASTFinding:
    return ASTFinding(
        rule_id="OWASP-A03-SQL-INJECTION",
        category="A03: Injection",
        title=f"SQL injection risk via {detail}",
        severity="critical",
        confidence="high",
        file_path=filename,
        line_start=node.start_point[0] + 1,
        line_end=node.end_point[0] + 1,
        explanation=(
            "Building SQL queries with string concatenation or template literals "
            "allows an attacker to inject arbitrary SQL.  Use parameterised queries."
        ),
        remediation="db.query('SELECT * FROM t WHERE id = $1', [userId])",
    )


def check_inner_html(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A03 — ``element.innerHTML = variable`` (XSS vector)."""
    findings: list[ASTFinding] = []
    for assign in find_nodes(tree.root_node, "assignment_expression"):
        left = assign.child_by_field_name("left")
        right = assign.child_by_field_name("right")
        if left is None or right is None:
            continue
        if left.type != "member_expression":
            continue
        prop = left.child_by_field_name("property")
        if prop is None or prop.text.decode() != "innerHTML":
            continue
        # Safe if right side is a string literal
        if right.type == "string":
            continue
        findings.append(
            ASTFinding(
                rule_id="OWASP-A03-INNERHTML",
                category="A03: Injection",
                title="innerHTML assigned from a variable (XSS risk)",
                severity="high",
                confidence="medium",
                file_path=filename,
                line_start=assign.start_point[0] + 1,
                line_end=assign.end_point[0] + 1,
                explanation=(
                    "Setting innerHTML to a non-literal value allows attackers "
                    "to inject arbitrary HTML and JavaScript."
                ),
                remediation="Use textContent for text, or sanitize HTML with DOMPurify.",
            )
        )
    return findings


# ── A04: Insecure Design ──────────────────────────────────────────────


def check_empty_catch(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A04 — Empty ``catch`` blocks."""
    findings: list[ASTFinding] = []
    for catch in find_nodes(tree.root_node, "catch_clause"):
        body = catch.child_by_field_name("body")
        if body is None:
            continue
        stmts = [c for c in body.named_children if c.type != "comment"]
        if len(stmts) == 0:
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A04-EMPTY-CATCH",
                    category="A04: Insecure Design",
                    title="Empty catch block silently swallows errors",
                    severity="medium",
                    confidence="high",
                    file_path=filename,
                    line_start=catch.start_point[0] + 1,
                    line_end=catch.end_point[0] + 1,
                    explanation=(
                        "An empty catch block hides errors.  At minimum, log the "
                        "exception for debugging."
                    ),
                    remediation="catch(e) { console.error(e); }",
                )
            )
    return findings


# ── A02: Cryptographic Failures ────────────────────────────────────────


def check_hardcoded_secrets(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """A02 — Hard-coded secrets in ``const``/``let``/``var`` declarations."""
    findings: list[ASTFinding] = []
    for decl in find_nodes(tree.root_node, "variable_declarator"):
        name_node = decl.child_by_field_name("name")
        value_node = decl.child_by_field_name("value")
        if name_node is None or value_node is None:
            continue
        if name_node.type != "identifier":
            continue
        name = name_node.text.decode()
        if not is_sensitive_name(name):
            continue
        if value_node.type != "string":
            continue
        val = string_literal_value(value_node)
        if val and len(val) > 0:
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A02-HARDCODED-SECRET",
                    category="A02: Cryptographic Failures",
                    title=f"Hard-coded secret in variable '{name}'",
                    severity="high",
                    confidence="medium",
                    file_path=filename,
                    line_start=decl.start_point[0] + 1,
                    line_end=decl.end_point[0] + 1,
                    explanation=(
                        "Secrets in source code are easily leaked via version "
                        "control and cannot be rotated without a code change."
                    ),
                    remediation="Load secrets from environment variables: process.env.SECRET",
                )
            )
    return findings


# ── A09: Logging Failures ─────────────────────────────────────────────

_JS_LOG_METHODS = frozenset({"log", "info", "warn", "error", "debug", "trace"})


def check_logging_sensitive_data(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """A09 — Sensitive variable names passed to ``console.*`` calls."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call_expression"):
        obj, method = get_call_name(call)
        if obj != "console" or method not in _JS_LOG_METHODS:
            continue
        for arg in get_call_args(call):
            if arg.type == "identifier" and is_sensitive_name(arg.text.decode()):
                findings.append(
                    ASTFinding(
                        rule_id="OWASP-A09-LOG-SENSITIVE",
                        category="A09: Logging Failures",
                        title=f"Sensitive data '{arg.text.decode()}' passed to console.{method}()",
                        severity="medium",
                        confidence="medium",
                        file_path=filename,
                        line_start=call.start_point[0] + 1,
                        line_end=call.end_point[0] + 1,
                        explanation=(
                            "Logging sensitive values risks exposing them in "
                            "browser dev-tools, server logs, and monitoring."
                        ),
                        remediation="Mask or redact sensitive values before logging.",
                    )
                )
    return findings


# ── Registry ───────────────────────────────────────────────────────────

JS_OWASP_HEURISTICS = [
    check_eval,
    check_sql_injection,
    check_inner_html,
    check_empty_catch,
    check_hardcoded_secrets,
    check_logging_sensitive_data,
]
