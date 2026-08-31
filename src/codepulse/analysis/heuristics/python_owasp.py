"""Python OWASP Top-10 AST heuristics (architecture doc §3.3.3).

Each public ``check_*`` function receives a parsed tree-sitter ``Tree``, the
raw source ``bytes``, and the *filename*, and returns a list of ``ASTFinding``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from codepulse.analysis.heuristics.base import (
    ASTFinding,
    find_nodes,
    get_call_args,
    get_call_name,
    get_keyword_arg,
    has_interpolation,
    is_sensitive_name,
    node_text,
    string_literal_value,
)

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


# ── A03: Injection ─────────────────────────────────────────────────────

_SQL_METHODS = frozenset({"execute", "executemany", "executescript"})


def check_sql_injection(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A03 — SQL injection via string concat / f-string in execute() calls."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        _, method = get_call_name(call)
        if method not in _SQL_METHODS:
            continue
        args = get_call_args(call)
        if not args:
            continue
        first = args[0]
        if first.type == "binary_operator":
            left = first.child_by_field_name("left")
            if left and left.type == "string":
                findings.append(_sql_finding(call, filename, "string concatenation"))
        elif first.type == "string" and has_interpolation(first):
            findings.append(_sql_finding(call, filename, "f-string interpolation"))
    return findings


def _sql_finding(node: "Node", filename: str, detail: str) -> ASTFinding:
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
            "Building SQL queries with string concatenation or f-strings allows "
            "an attacker to inject arbitrary SQL.  Use parameterised queries."
        ),
        remediation='cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))',
    )


def check_eval_exec(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A03 / A08 — Use of ``eval()`` or ``exec()``."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        _, name = get_call_name(call)
        if name not in ("eval", "exec"):
            continue
        findings.append(
            ASTFinding(
                rule_id="OWASP-A03-EVAL",
                category="A03: Injection",
                title=f"Use of {name}() is a code-injection risk",
                severity="high",
                confidence="high",
                file_path=filename,
                line_start=call.start_point[0] + 1,
                line_end=call.end_point[0] + 1,
                explanation=(
                    f"{name}() executes arbitrary code.  If user input reaches "
                    "this call an attacker can run arbitrary Python on the server."
                ),
                remediation=(
                    "Use ast.literal_eval() for safe literal evaluation, or "
                    "a whitelist-based dispatcher."
                ),
            )
        )
    return findings


_CMD_PAIRS = frozenset(
    {
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
        ("os", "system"),
        ("os", "popen"),
    }
)


def check_command_injection(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """A03 — Shell command injection via subprocess / os.system with strings."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        obj, method = get_call_name(call)
        if (obj, method) not in _CMD_PAIRS:
            continue
        args = get_call_args(call)
        if not args:
            continue
        first = args[0]
        # Safe when first arg is a list literal
        if first.type == "list":
            continue
        # Flag string concat, f-strings, or bare variables
        if first.type in ("binary_operator", "identifier") or (
            first.type == "string" and has_interpolation(first)
        ):
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A03-COMMAND-INJECTION",
                    category="A03: Injection",
                    title="Potential shell command injection",
                    severity="critical",
                    confidence="medium",
                    file_path=filename,
                    line_start=call.start_point[0] + 1,
                    line_end=call.end_point[0] + 1,
                    explanation=(
                        "Constructing shell commands from dynamic values allows "
                        "attackers to inject arbitrary OS commands."
                    ),
                    remediation=(
                        "Pass a list of arguments to subprocess.run() and avoid "
                        "shell=True.  Never use os.system()."
                    ),
                )
            )
    return findings


# ── A04: Insecure Design ──────────────────────────────────────────────


def check_empty_except(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A04 — Empty ``except`` blocks (bare or broad catch with only ``pass``)."""
    findings: list[ASTFinding] = []
    for exc in find_nodes(tree.root_node, "except_clause"):
        body = _except_body(exc)
        if body is None:
            continue
        stmts = [c for c in body.named_children if c.type != "comment"]
        if len(stmts) <= 1 and all(s.type == "pass_statement" for s in stmts):
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A04-EMPTY-EXCEPT",
                    category="A04: Insecure Design",
                    title="Empty except block silently swallows errors",
                    severity="medium",
                    confidence="high",
                    file_path=filename,
                    line_start=exc.start_point[0] + 1,
                    line_end=exc.end_point[0] + 1,
                    explanation=(
                        "Catching exceptions with an empty handler hides bugs and "
                        "makes debugging impossible.  At minimum, log the exception."
                    ),
                    remediation=(
                        "except Exception as e: logger.exception(e)"
                    ),
                )
            )
    return findings


def _except_body(exc_node: "Node") -> "Node | None":
    """Return the ``block`` child of an ``except_clause``."""
    for child in exc_node.children:
        if child.type == "block":
            return child
    return None


# ── A02: Cryptographic Failures ────────────────────────────────────────


def check_hardcoded_secrets(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """A02 — Hard-coded strings assigned to sensitive variable names."""
    findings: list[ASTFinding] = []
    for assign in find_nodes(tree.root_node, "assignment"):
        left = assign.child_by_field_name("left")
        right = assign.child_by_field_name("right")
        if left is None or right is None:
            continue
        if left.type != "identifier":
            continue
        name = left.text.decode()
        if not is_sensitive_name(name):
            continue
        if right.type != "string":
            continue
        val = string_literal_value(right)
        if val and len(val) > 0:
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A02-HARDCODED-SECRET",
                    category="A02: Cryptographic Failures",
                    title=f"Hard-coded secret in variable '{name}'",
                    severity="high",
                    confidence="medium",
                    file_path=filename,
                    line_start=assign.start_point[0] + 1,
                    line_end=assign.end_point[0] + 1,
                    explanation=(
                        "Secrets committed in source code are easily leaked and "
                        "cannot be rotated without a code change."
                    ),
                    remediation=(
                        "Load secrets from environment variables or a vault "
                        "(e.g. os.environ['SECRET_KEY'])."
                    ),
                )
            )
    return findings


_WEAK_HASH_FUNCS = frozenset({"md5", "sha1"})


def check_weak_crypto(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A02 — Use of weak hash functions (MD5 / SHA1)."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        obj, method = get_call_name(call)
        if obj == "hashlib" and method in _WEAK_HASH_FUNCS:
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A02-WEAK-HASH",
                    category="A02: Cryptographic Failures",
                    title=f"Use of weak hash function hashlib.{method}()",
                    severity="medium",
                    confidence="medium",
                    file_path=filename,
                    line_start=call.start_point[0] + 1,
                    line_end=call.end_point[0] + 1,
                    explanation=(
                        f"hashlib.{method}() is cryptographically broken and must "
                        "not be used for password hashing or integrity checks."
                    ),
                    remediation="Use hashlib.sha256() or bcrypt/argon2 for passwords.",
                )
            )
    return findings


# ── A05: Security Misconfiguration ─────────────────────────────────────


def check_debug_true(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A05 — ``DEBUG = True`` or binding to ``0.0.0.0``."""
    findings: list[ASTFinding] = []
    for assign in find_nodes(tree.root_node, "assignment"):
        left = assign.child_by_field_name("left")
        right = assign.child_by_field_name("right")
        if left is None or right is None:
            continue
        lname = left.text.decode() if left.type == "identifier" else ""
        rtext = right.text.decode()
        if lname.upper() == "DEBUG" and rtext == "True":
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A05-DEBUG-TRUE",
                    category="A05: Security Misconfiguration",
                    title="DEBUG mode enabled",
                    severity="medium",
                    confidence="high",
                    file_path=filename,
                    line_start=assign.start_point[0] + 1,
                    line_end=assign.end_point[0] + 1,
                    explanation="DEBUG = True exposes stack traces and internals to users.",
                    remediation="Set DEBUG = False in production configuration.",
                )
            )
        # Binding to all interfaces
        if right.type == "string":
            val = string_literal_value(right)
            if val == "0.0.0.0":
                findings.append(
                    ASTFinding(
                        rule_id="OWASP-A05-BIND-ALL",
                        category="A05: Security Misconfiguration",
                        title="Server binding to 0.0.0.0 (all interfaces)",
                        severity="low",
                        confidence="medium",
                        file_path=filename,
                        line_start=assign.start_point[0] + 1,
                        line_end=assign.end_point[0] + 1,
                        explanation=(
                            "Binding to 0.0.0.0 exposes the service on every network "
                            "interface, including public ones."
                        ),
                        remediation="Bind to 127.0.0.1 or a specific private IP.",
                    )
                )
    return findings


# ── A08: Data Integrity Failures ───────────────────────────────────────


def check_dangerous_deserialization(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """A08 — ``pickle.loads/load``, ``yaml.load`` without SafeLoader."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        obj, method = get_call_name(call)
        # pickle.loads / pickle.load
        if obj == "pickle" and method in ("loads", "load"):
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A08-PICKLE",
                    category="A08: Data Integrity Failures",
                    title="Dangerous deserialization with pickle",
                    severity="critical",
                    confidence="high",
                    file_path=filename,
                    line_start=call.start_point[0] + 1,
                    line_end=call.end_point[0] + 1,
                    explanation=(
                        "pickle.loads() / pickle.load() can execute arbitrary code "
                        "embedded in the serialised data."
                    ),
                    remediation="Use json.loads() or a safe serialisation format.",
                )
            )
        # yaml.load without Loader=SafeLoader
        if obj == "yaml" and method == "load":
            loader_kw = get_keyword_arg(call, "Loader")
            if loader_kw is None or node_text(loader_kw) not in (
                "SafeLoader",
                "yaml.SafeLoader",
                "CSafeLoader",
                "yaml.CSafeLoader",
            ):
                findings.append(
                    ASTFinding(
                        rule_id="OWASP-A08-YAML-UNSAFE",
                        category="A08: Data Integrity Failures",
                        title="yaml.load() without SafeLoader",
                        severity="high",
                        confidence="high",
                        file_path=filename,
                        line_start=call.start_point[0] + 1,
                        line_end=call.end_point[0] + 1,
                        explanation=(
                            "yaml.load() without Loader=SafeLoader can execute "
                            "arbitrary Python code embedded in the YAML document."
                        ),
                        remediation="yaml.safe_load(data) or yaml.load(data, Loader=SafeLoader)",
                    )
                )
    return findings


# ── A09: Logging Failures ─────────────────────────────────────────────

_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "error", "critical", "exception", "log"}
)


def check_logging_sensitive_data(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """A09 — Sensitive variable names passed to logging / print calls."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        obj, method = get_call_name(call)
        is_logging = (obj in ("logging", "logger", "log") and method in _LOG_METHODS) or (
            method == "print"
        )
        if not is_logging:
            continue
        for arg in get_call_args(call):
            if arg.type == "identifier" and is_sensitive_name(arg.text.decode()):
                findings.append(
                    ASTFinding(
                        rule_id="OWASP-A09-LOG-SENSITIVE",
                        category="A09: Logging Failures",
                        title=f"Sensitive data '{arg.text.decode()}' passed to logging",
                        severity="medium",
                        confidence="medium",
                        file_path=filename,
                        line_start=call.start_point[0] + 1,
                        line_end=call.end_point[0] + 1,
                        explanation=(
                            "Logging sensitive values (passwords, tokens) risks "
                            "exposing them in log files, monitoring dashboards, and "
                            "error aggregation services."
                        ),
                        remediation="Mask or redact sensitive values before logging.",
                    )
                )
    return findings


# ── A07: Auth Failures ─────────────────────────────────────────────────


def check_jwt_verify_disabled(
    tree: Tree, source: bytes, filename: str
) -> list[ASTFinding]:
    """A07 — ``jwt.decode(…, verify=False)`` or ``options={…verify_signature: False}``."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        obj, method = get_call_name(call)
        if not (obj == "jwt" and method == "decode"):
            continue
        verify_kw = get_keyword_arg(call, "verify")
        options_kw = get_keyword_arg(call, "options")
        flagged = False
        if verify_kw and node_text(verify_kw) == "False":
            flagged = True
        if options_kw and "False" in node_text(options_kw):
            flagged = True
        if flagged:
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A07-JWT-NO-VERIFY",
                    category="A07: Auth Failures",
                    title="JWT signature verification disabled",
                    severity="critical",
                    confidence="high",
                    file_path=filename,
                    line_start=call.start_point[0] + 1,
                    line_end=call.end_point[0] + 1,
                    explanation=(
                        "Decoding a JWT without verifying the signature allows "
                        "attackers to forge tokens with arbitrary claims."
                    ),
                    remediation="Always verify JWT signatures: jwt.decode(token, key, algorithms=[…])",
                )
            )
    return findings


# ── A10: SSRF ──────────────────────────────────────────────────────────

_HTTP_PAIRS = frozenset(
    {
        ("requests", "get"),
        ("requests", "post"),
        ("requests", "put"),
        ("requests", "delete"),
        ("requests", "patch"),
        ("requests", "head"),
        ("urllib", "urlopen"),
        ("httpx", "get"),
        ("httpx", "post"),
    }
)


def check_ssrf(tree: Tree, source: bytes, filename: str) -> list[ASTFinding]:
    """A10 — User-controlled variables passed directly to HTTP clients."""
    findings: list[ASTFinding] = []
    for call in find_nodes(tree.root_node, "call"):
        obj, method = get_call_name(call)
        if (obj, method) not in _HTTP_PAIRS:
            continue
        args = get_call_args(call)
        if not args:
            continue
        first = args[0]
        # Dangerous when first arg is a bare variable (not a string literal)
        if first.type == "identifier":
            findings.append(
                ASTFinding(
                    rule_id="OWASP-A10-SSRF",
                    category="A10: SSRF",
                    title="Potential SSRF — user-controlled URL in HTTP request",
                    severity="high",
                    confidence="medium",
                    file_path=filename,
                    line_start=call.start_point[0] + 1,
                    line_end=call.end_point[0] + 1,
                    explanation=(
                        "Passing a variable directly to an HTTP client function "
                        "without URL validation can allow Server-Side Request Forgery."
                    ),
                    remediation=(
                        "Validate URLs against an allow-list of domains before making "
                        "the request."
                    ),
                )
            )
    return findings


# ── Registry ───────────────────────────────────────────────────────────

PYTHON_OWASP_HEURISTICS = [
    check_sql_injection,
    check_eval_exec,
    check_command_injection,
    check_empty_except,
    check_hardcoded_secrets,
    check_weak_crypto,
    check_debug_true,
    check_dangerous_deserialization,
    check_logging_sensitive_data,
    check_jwt_verify_disabled,
    check_ssrf,
]
