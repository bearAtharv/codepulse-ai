"""Tests for the AST analysis engine — Phase 3.

Each heuristic has a "fires on vulnerable code" and "silent on clean code" test.
Uses inline code snippets for unit tests and fixture files for integration tests.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codepulse.analysis.ast_engine import analyze_chunk
from codepulse.analysis.languages import detect_language, EXTENSION_MAP

FIXTURES = Path(__file__).parent / "fixtures"


# ═══════════════════════════════════════════════════════════════════════
# Language Detection
# ═══════════════════════════════════════════════════════════════════════


class TestLanguageDetection:
    def test_python(self):
        assert detect_language("app.py") == "python"
        assert detect_language("stubs.pyi") == "python"

    def test_javascript(self):
        assert detect_language("app.js") == "javascript"
        assert detect_language("component.jsx") == "javascript"
        assert detect_language("module.mjs") == "javascript"
        assert detect_language("module.cjs") == "javascript"

    def test_typescript(self):
        assert detect_language("app.ts") == "typescript"
        assert detect_language("component.tsx") == "tsx"

    def test_unsupported(self):
        assert detect_language("main.go") is None
        assert detect_language("App.java") is None
        assert detect_language("image.png") is None

    def test_unsupported_returns_no_findings(self):
        findings = analyze_chunk("package main", "main.go")
        assert findings == []


# ═══════════════════════════════════════════════════════════════════════
# Python OWASP Heuristics
# ═══════════════════════════════════════════════════════════════════════


class TestPythonSQLInjection:
    """A03 — SQL injection via string concat and f-strings."""

    def test_concat_detected(self):
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + user_id)'
        findings = analyze_chunk(code, "app.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "OWASP-A03-SQL-INJECTION"
        assert findings[0].severity == "critical"
        assert "concatenation" in findings[0].title

    def test_fstring_detected(self):
        code = 'cursor.execute(f"SELECT * FROM t WHERE id={uid}")'
        findings = analyze_chunk(code, "app.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "OWASP-A03-SQL-INJECTION"
        assert "f-string" in findings[0].title

    def test_parameterised_query_clean(self):
        code = 'cursor.execute("SELECT * FROM t WHERE id=%s", (user_id,))'
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A03-SQL-INJECTION"]
        assert len(findings) == 0


class TestPythonEvalExec:
    """A03 — eval() and exec() usage."""

    def test_eval_detected(self):
        code = "result = eval(user_input)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A03-EVAL" and "eval" in f.title for f in findings)

    def test_exec_detected(self):
        code = "exec(code_string)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A03-EVAL" and "exec" in f.title for f in findings)

    def test_ast_literal_eval_clean(self):
        code = "import ast\nresult = ast.literal_eval(data)"
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A03-EVAL"]
        assert len(findings) == 0


class TestPythonCommandInjection:
    """A03 — Shell command injection via subprocess/os."""

    def test_os_system_detected(self):
        code = "os.system(user_cmd)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A03-COMMAND-INJECTION" for f in findings)

    def test_subprocess_with_fstring_detected(self):
        code = 'subprocess.run(f"echo {user_input}", shell=True)'
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A03-COMMAND-INJECTION" for f in findings)

    def test_subprocess_list_clean(self):
        code = 'subprocess.run(["echo", "hello"], check=True)'
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A03-COMMAND-INJECTION"]
        assert len(findings) == 0


class TestPythonEmptyExcept:
    """A04 — Empty except blocks."""

    def test_bare_except_pass_detected(self):
        code = "try:\n    x()\nexcept:\n    pass"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A04-EMPTY-EXCEPT" for f in findings)

    def test_except_exception_pass_detected(self):
        code = "try:\n    x()\nexcept Exception:\n    pass"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A04-EMPTY-EXCEPT" for f in findings)

    def test_except_with_logging_clean(self):
        code = "try:\n    x()\nexcept Exception as e:\n    logger.error(e)\n    raise"
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A04-EMPTY-EXCEPT"]
        assert len(findings) == 0


class TestPythonHardcodedSecrets:
    """A02 — Hard-coded secrets."""

    def test_password_detected(self):
        code = 'password = "super_secret_123"'
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A02-HARDCODED-SECRET" for f in findings)

    def test_api_key_detected(self):
        code = 'api_key = "sk-live-abc123"'
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A02-HARDCODED-SECRET" for f in findings)

    def test_env_var_clean(self):
        code = 'import os\npassword = os.environ.get("PASSWORD")'
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A02-HARDCODED-SECRET"]
        assert len(findings) == 0


class TestPythonWeakCrypto:
    """A02 — Weak hash functions."""

    def test_md5_detected(self):
        code = "hashlib.md5(data)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A02-WEAK-HASH" for f in findings)

    def test_sha1_detected(self):
        code = "hashlib.sha1(data)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A02-WEAK-HASH" for f in findings)

    def test_sha256_clean(self):
        code = "hashlib.sha256(data)"
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A02-WEAK-HASH"]
        assert len(findings) == 0


class TestPythonDebugTrue:
    """A05 — DEBUG = True and binding to 0.0.0.0."""

    def test_debug_true_detected(self):
        code = "DEBUG = True"
        findings = analyze_chunk(code, "settings.py")
        assert any(f.rule_id == "OWASP-A05-DEBUG-TRUE" for f in findings)

    def test_debug_false_clean(self):
        code = "DEBUG = False"
        findings = [f for f in analyze_chunk(code, "settings.py") if f.rule_id == "OWASP-A05-DEBUG-TRUE"]
        assert len(findings) == 0

    def test_bind_all_detected(self):
        code = 'HOST = "0.0.0.0"'
        findings = analyze_chunk(code, "settings.py")
        assert any(f.rule_id == "OWASP-A05-BIND-ALL" for f in findings)

    def test_bind_localhost_clean(self):
        code = 'HOST = "127.0.0.1"'
        findings = [f for f in analyze_chunk(code, "settings.py") if f.rule_id == "OWASP-A05-BIND-ALL"]
        assert len(findings) == 0


class TestPythonDeserialization:
    """A08 — Dangerous deserialization."""

    def test_pickle_loads_detected(self):
        code = "pickle.loads(raw_bytes)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A08-PICKLE" for f in findings)

    def test_yaml_load_no_loader_detected(self):
        code = "yaml.load(text)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A08-YAML-UNSAFE" for f in findings)

    def test_yaml_safe_load_clean(self):
        code = "yaml.load(text, Loader=SafeLoader)"
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id.startswith("OWASP-A08")]
        assert len(findings) == 0

    def test_json_loads_clean(self):
        code = "json.loads(raw_bytes)"
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id.startswith("OWASP-A08")]
        assert len(findings) == 0


class TestPythonLoggingSensitive:
    """A09 — Sensitive data in logging calls."""

    def test_logging_password_detected(self):
        code = "logger.info(password)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A09-LOG-SENSITIVE" for f in findings)

    def test_print_token_detected(self):
        code = "print(access_token)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A09-LOG-SENSITIVE" for f in findings)

    def test_logging_username_clean(self):
        code = 'logger.info("User logged in: %s", username)'
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A09-LOG-SENSITIVE"]
        assert len(findings) == 0


class TestPythonJWTVerify:
    """A07 — JWT decode with verification disabled."""

    def test_verify_false_detected(self):
        code = 'jwt.decode(token, options={"verify_signature": False})'
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A07-JWT-NO-VERIFY" for f in findings)

    def test_normal_decode_clean(self):
        code = 'jwt.decode(token, key, algorithms=["HS256"])'
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A07-JWT-NO-VERIFY"]
        assert len(findings) == 0


class TestPythonSSRF:
    """A10 — SSRF via user-controlled URL."""

    def test_requests_get_variable_detected(self):
        code = "requests.get(user_url)"
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "OWASP-A10-SSRF" for f in findings)

    def test_requests_get_literal_clean(self):
        code = 'requests.get("https://api.example.com/data")'
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A10-SSRF"]
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════
# Python Memory Leak Heuristics
# ═══════════════════════════════════════════════════════════════════════


class TestPythonUnclosedResource:
    """Memory — open() without with statement."""

    def test_bare_open_detected(self):
        code = 'f = open("data.txt")\ndata = f.read()'
        findings = analyze_chunk(code, "app.py")
        assert any(f.rule_id == "MEM-PYTHON-UNCLOSED-RESOURCE" for f in findings)

    def test_with_open_clean(self):
        code = 'with open("data.txt") as f:\n    data = f.read()'
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "MEM-PYTHON-UNCLOSED-RESOURCE"]
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════
# JavaScript OWASP Heuristics
# ═══════════════════════════════════════════════════════════════════════


class TestJSEval:
    """A03 — eval() in JavaScript."""

    def test_eval_detected(self):
        code = "eval(userInput)"
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A03-EVAL" for f in findings)

    def test_json_parse_clean(self):
        code = "JSON.parse(data)"
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A03-EVAL"]
        assert len(findings) == 0


class TestJSSQLInjection:
    """A03 — SQL injection in JS."""

    def test_concat_detected(self):
        code = 'db.query("SELECT * FROM users WHERE id=" + userId)'
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A03-SQL-INJECTION" for f in findings)

    def test_template_literal_detected(self):
        code = "db.query(`SELECT * FROM users WHERE id=${userId}`)"
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A03-SQL-INJECTION" for f in findings)

    def test_parameterised_clean(self):
        code = 'db.query("SELECT * FROM users WHERE id=$1", [userId])'
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A03-SQL-INJECTION"]
        assert len(findings) == 0


class TestJSInnerHTML:
    """A03 — innerHTML XSS."""

    def test_variable_detected(self):
        code = "element.innerHTML = userContent"
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A03-INNERHTML" for f in findings)

    def test_literal_clean(self):
        code = 'element.innerHTML = "<p>hello</p>"'
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A03-INNERHTML"]
        assert len(findings) == 0

    def test_textcontent_clean(self):
        code = "element.textContent = userContent"
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A03-INNERHTML"]
        assert len(findings) == 0


class TestJSEmptyCatch:
    """A04 — Empty catch blocks."""

    def test_empty_catch_detected(self):
        code = "try { doSomething() } catch(e) {}"
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A04-EMPTY-CATCH" for f in findings)

    def test_catch_with_logging_clean(self):
        code = "try { doSomething() } catch(e) { console.error(e) }"
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A04-EMPTY-CATCH"]
        assert len(findings) == 0


class TestJSHardcodedSecrets:
    """A02 — Hard-coded secrets in JS."""

    def test_const_secret_detected(self):
        code = 'const apiSecret = "sk-live-abc123"'
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A02-HARDCODED-SECRET" for f in findings)

    def test_env_var_clean(self):
        code = "const apiSecret = process.env.API_SECRET"
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A02-HARDCODED-SECRET"]
        assert len(findings) == 0


class TestJSLoggingSensitive:
    """A09 — Sensitive data in console.log."""

    def test_console_log_password_detected(self):
        code = "console.log(password)"
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A09-LOG-SENSITIVE" for f in findings)

    def test_console_log_username_clean(self):
        code = 'console.log("User logged in:", username)'
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A09-LOG-SENSITIVE"]
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════
# JavaScript Memory Leak Heuristics
# ═══════════════════════════════════════════════════════════════════════


class TestJSEventListenerLeak:
    """Memory — addEventListener without removeEventListener."""

    def test_no_remove_detected(self):
        code = 'document.addEventListener("click", handleClick)'
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "MEM-JS-EVENT-LISTENER-LEAK" for f in findings)

    def test_with_remove_clean(self):
        code = (
            'document.addEventListener("click", handleClick)\n'
            'document.removeEventListener("click", handleClick)'
        )
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "MEM-JS-EVENT-LISTENER-LEAK"]
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════
# TypeScript — same heuristics as JS
# ═══════════════════════════════════════════════════════════════════════


class TestTypeScript:
    """Verify TypeScript files get the same JS heuristics."""

    def test_ts_eval_detected(self):
        code = "eval(userInput)"
        findings = analyze_chunk(code, "app.ts")
        assert any(f.rule_id == "OWASP-A03-EVAL" for f in findings)

    def test_tsx_eval_detected(self):
        code = "eval(userInput)"
        findings = analyze_chunk(code, "component.tsx")
        assert any(f.rule_id == "OWASP-A03-EVAL" for f in findings)

    def test_ts_sql_injection(self):
        code = "db.query(`SELECT * FROM t WHERE id=${id}`)"
        findings = analyze_chunk(code, "repo.ts")
        assert any(f.rule_id == "OWASP-A03-SQL-INJECTION" for f in findings)


# ═══════════════════════════════════════════════════════════════════════
# Diff-Aware Filtering (Section 3.3.2)
# ═══════════════════════════════════════════════════════════════════════


class TestDiffAwareFiltering:
    """Only report findings on modified lines."""

    def test_finding_on_modified_line_kept(self):
        code = "x = 1\neval(data)\ny = 2"
        # eval is on line 2
        findings = analyze_chunk(code, "app.py", modified_lines={2})
        assert any(f.rule_id == "OWASP-A03-EVAL" for f in findings)

    def test_finding_outside_modified_lines_filtered(self):
        code = "x = 1\neval(data)\ny = 2"
        # Only line 1 modified — eval on line 2 should be filtered
        findings = analyze_chunk(code, "app.py", modified_lines={1, 3})
        assert not any(f.rule_id == "OWASP-A03-EVAL" for f in findings)

    def test_no_filter_when_modified_lines_none(self):
        code = "eval(data)"
        findings = analyze_chunk(code, "app.py", modified_lines=None)
        assert len(findings) > 0


# ═══════════════════════════════════════════════════════════════════════
# Finding Structure
# ═══════════════════════════════════════════════════════════════════════


class TestFindingStructure:
    """Verify all findings have the required fields."""

    def test_all_fields_present(self):
        code = "eval(data)"
        findings = analyze_chunk(code, "app.py")
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id
        assert f.category
        assert f.title
        assert f.severity in ("critical", "high", "medium", "low", "info")
        assert f.confidence in ("high", "medium", "low")
        assert f.file_path == "app.py"
        assert f.line_start >= 1
        assert f.line_end >= f.line_start
        assert f.explanation
        assert f.remediation
        assert f.source == "ast"

    def test_line_numbers_are_1_indexed(self):
        code = "# comment\neval(data)"
        findings = analyze_chunk(code, "app.py")
        eval_findings = [f for f in findings if f.rule_id == "OWASP-A03-EVAL"]
        assert eval_findings[0].line_start == 2


# ═══════════════════════════════════════════════════════════════════════
# Integration: Fixture Files
# ═══════════════════════════════════════════════════════════════════════


class TestPythonFixtureIntegration:
    """Run all heuristics against the full fixture files."""

    def test_vulnerable_file_has_findings(self):
        source = (FIXTURES / "python_vulnerable.py").read_text()
        findings = analyze_chunk(source, "python_vulnerable.py")
        rule_ids = {f.rule_id for f in findings}
        # Should detect at least these categories
        assert "OWASP-A03-SQL-INJECTION" in rule_ids
        assert "OWASP-A03-EVAL" in rule_ids
        assert "OWASP-A03-COMMAND-INJECTION" in rule_ids
        assert "OWASP-A04-EMPTY-EXCEPT" in rule_ids
        assert "OWASP-A02-HARDCODED-SECRET" in rule_ids
        assert "OWASP-A02-WEAK-HASH" in rule_ids
        assert "OWASP-A05-DEBUG-TRUE" in rule_ids
        assert "OWASP-A08-PICKLE" in rule_ids
        assert "OWASP-A08-YAML-UNSAFE" in rule_ids
        assert "OWASP-A09-LOG-SENSITIVE" in rule_ids
        assert "OWASP-A07-JWT-NO-VERIFY" in rule_ids
        assert "OWASP-A10-SSRF" in rule_ids
        assert "MEM-PYTHON-UNCLOSED-RESOURCE" in rule_ids

    def test_clean_file_has_no_owasp_findings(self):
        source = (FIXTURES / "python_clean.py").read_text()
        findings = analyze_chunk(source, "python_clean.py")
        owasp = [f for f in findings if f.rule_id.startswith("OWASP-")]
        assert len(owasp) == 0, f"False positives: {[f.rule_id for f in owasp]}"

    def test_clean_file_has_no_memory_findings(self):
        source = (FIXTURES / "python_clean.py").read_text()
        findings = analyze_chunk(source, "python_clean.py")
        mem = [f for f in findings if f.rule_id.startswith("MEM-")]
        assert len(mem) == 0, f"False positives: {[f.rule_id for f in mem]}"


class TestJSFixtureIntegration:
    """Run all heuristics against the full JS fixture files."""

    def test_vulnerable_file_has_findings(self):
        source = (FIXTURES / "javascript_vulnerable.js").read_text()
        findings = analyze_chunk(source, "javascript_vulnerable.js")
        rule_ids = {f.rule_id for f in findings}
        assert "OWASP-A03-EVAL" in rule_ids
        assert "OWASP-A03-SQL-INJECTION" in rule_ids
        assert "OWASP-A03-INNERHTML" in rule_ids
        assert "OWASP-A04-EMPTY-CATCH" in rule_ids
        assert "OWASP-A02-HARDCODED-SECRET" in rule_ids
        assert "OWASP-A09-LOG-SENSITIVE" in rule_ids
        assert "MEM-JS-EVENT-LISTENER-LEAK" in rule_ids

    def test_clean_file_has_no_findings(self):
        source = (FIXTURES / "javascript_clean.js").read_text()
        findings = analyze_chunk(source, "javascript_clean.js")
        assert len(findings) == 0, f"False positives: {[f.rule_id for f in findings]}"
