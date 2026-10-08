"""Tests for the AST analysis engine — Phase 3.

Each heuristic has a "fires on vulnerable code" and "silent on clean code" test.
Uses inline code snippets for unit tests and fixture files for integration tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codepulse.analysis.ast_engine import analyze_chunk
from codepulse.analysis.languages import detect_language

FIXTURES = Path(__file__).parent / "fixtures"


# ═══════════════════════════════════════════════════════════════════════
# Language Detection
# ═══════════════════════════════════════════════════════════════════════


class TestLanguageDetection:
    @pytest.mark.parametrize(
        "filename, expected",
        [
            ("app.py", "python"),
            ("stubs.pyi", "python"),
            ("app.js", "javascript"),
            ("component.jsx", "javascript"),
            ("module.mjs", "javascript"),
            ("module.cjs", "javascript"),
            ("app.ts", "typescript"),
            ("component.tsx", "tsx"),
        ],
    )
    def test_supported_language(self, filename, expected):
        assert detect_language(filename) == expected

    @pytest.mark.parametrize("filename", ["main.go", "App.java", "image.png"])
    def test_unsupported_language(self, filename):
        assert detect_language(filename) is None

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

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("os.system(user_cmd)", True),
            ('subprocess.run(f"echo {user_input}", shell=True)', True),
            ('subprocess.run(["echo", "hello"], check=True)', False),
        ],
    )
    def test_command_injection(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A03-COMMAND-INJECTION"]
        assert bool(findings) is should_fire


class TestPythonEmptyExcept:
    """A04 — Empty except blocks."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("try:\n    x()\nexcept:\n    pass", True),
            ("try:\n    x()\nexcept Exception:\n    pass", True),
            ("try:\n    x()\nexcept Exception as e:\n    logger.error(e)\n    raise", False),
        ],
    )
    def test_empty_except(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A04-EMPTY-EXCEPT"]
        assert bool(findings) is should_fire


class TestPythonHardcodedSecrets:
    """A02 — Hard-coded secrets."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ('password = "super_secret_123"', True),
            ('api_key = "sk-live-abc123"', True),
            ('import os\npassword = os.environ.get("PASSWORD")', False),
        ],
    )
    def test_hardcoded_secrets(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A02-HARDCODED-SECRET"]
        assert bool(findings) is should_fire


class TestPythonWeakCrypto:
    """A02 — Weak hash functions."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("hashlib.md5(data)", True),
            ("hashlib.sha1(data)", True),
            ("hashlib.sha256(data)", False),
        ],
    )
    def test_weak_crypto(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A02-WEAK-HASH"]
        assert bool(findings) is should_fire


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

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("logger.info(password)", True),
            ("print(access_token)", True),
            ('logger.info("User logged in: %s", username)', False),
        ],
    )
    def test_logging_sensitive(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A09-LOG-SENSITIVE"]
        assert bool(findings) is should_fire


class TestPythonJWTVerify:
    """A07 — JWT decode with verification disabled."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ('jwt.decode(token, options={"verify_signature": False})', True),
            ('jwt.decode(token, key, algorithms=["HS256"])', False),
        ],
    )
    def test_jwt_verify(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A07-JWT-NO-VERIFY"]
        assert bool(findings) is should_fire


class TestPythonSSRF:
    """A10 — SSRF via user-controlled URL."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("requests.get(user_url)", True),
            ('requests.get("https://api.example.com/data")', False),
        ],
    )
    def test_ssrf(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "OWASP-A10-SSRF"]
        assert bool(findings) is should_fire


# ═══════════════════════════════════════════════════════════════════════
# Python Memory Leak Heuristics
# ═══════════════════════════════════════════════════════════════════════


class TestPythonUnclosedResource:
    """Memory — open() without with statement."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ('f = open("data.txt")\ndata = f.read()', True),
            ('with open("data.txt") as f:\n    data = f.read()', False),
        ],
    )
    def test_unclosed_resource(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.py") if f.rule_id == "MEM-PYTHON-UNCLOSED-RESOURCE"]
        assert bool(findings) is should_fire


# ═══════════════════════════════════════════════════════════════════════
# JavaScript OWASP Heuristics
# ═══════════════════════════════════════════════════════════════════════


class TestJSEval:
    """A03 — eval() in JavaScript."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("eval(userInput)", True),
            ("JSON.parse(data)", False),
        ],
    )
    def test_eval(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A03-EVAL"]
        assert bool(findings) is should_fire


class TestJSSQLInjection:
    """A03 — SQL injection in JS."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ('db.query("SELECT * FROM users WHERE id=" + userId)', True),
            ("db.query(`SELECT * FROM users WHERE id=${userId}`)", True),
            ('db.query("SELECT * FROM users WHERE id=$1", [userId])', False),
        ],
    )
    def test_sql_injection(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A03-SQL-INJECTION"]
        assert bool(findings) is should_fire


class TestJSInnerHTML:
    """A03 — innerHTML XSS."""

    def test_variable_detected(self):
        code = "element.innerHTML = userContent"
        findings = analyze_chunk(code, "app.js")
        assert any(f.rule_id == "OWASP-A03-INNERHTML" for f in findings)

    @pytest.mark.parametrize(
        "code",
        [
            'element.innerHTML = "<p>hello</p>"',
            "element.textContent = userContent",
        ],
    )
    def test_safe_dom_manipulation_clean(self, code: str) -> None:
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A03-INNERHTML"]
        assert len(findings) == 0


class TestJSEmptyCatch:
    """A04 — Empty catch blocks."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("try { doSomething() } catch(e) {}", True),
            ("try { doSomething() } catch(e) { console.error(e) }", False),
        ],
    )
    def test_empty_catch(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A04-EMPTY-CATCH"]
        assert bool(findings) is should_fire


class TestJSHardcodedSecrets:
    """A02 — Hard-coded secrets in JS."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ('const apiSecret = "sk-live-abc123"', True),
            ("const apiSecret = process.env.API_SECRET", False),
        ],
    )
    def test_hardcoded_secrets(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A02-HARDCODED-SECRET"]
        assert bool(findings) is should_fire


class TestJSLoggingSensitive:
    """A09 — Sensitive data in console.log."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ("console.log(password)", True),
            ('console.log("User logged in:", username)', False),
        ],
    )
    def test_logging_sensitive(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "OWASP-A09-LOG-SENSITIVE"]
        assert bool(findings) is should_fire


# ═══════════════════════════════════════════════════════════════════════
# JavaScript Memory Leak Heuristics
# ═══════════════════════════════════════════════════════════════════════


class TestJSEventListenerLeak:
    """Memory — addEventListener without removeEventListener."""

    @pytest.mark.parametrize(
        "code, should_fire",
        [
            ('document.addEventListener("click", handleClick)', True),
            (
                'document.addEventListener("click", handleClick)\n'
                'document.removeEventListener("click", handleClick)',
                False,
            ),
        ],
    )
    def test_event_listener_leak(self, code: str, should_fire: bool) -> None:
        findings = [f for f in analyze_chunk(code, "app.js") if f.rule_id == "MEM-JS-EVENT-LISTENER-LEAK"]
        assert bool(findings) is should_fire


# ═══════════════════════════════════════════════════════════════════════
# TypeScript — same heuristics as JS
# ═══════════════════════════════════════════════════════════════════════


class TestTypeScript:
    """Verify TypeScript files get the same JS heuristics."""

    @pytest.mark.parametrize("filename", ["app.ts", "component.tsx"])
    def test_eval_detected(self, filename: str) -> None:
        code = "eval(userInput)"
        findings = analyze_chunk(code, filename)
        assert any(f.rule_id == "OWASP-A03-EVAL" for f in findings)

    @pytest.mark.parametrize("filename", ["repo.ts", "component.tsx"])
    def test_sql_injection(self, filename: str) -> None:
        code = "db.query(`SELECT * FROM t WHERE id=${id}`)"
        findings = analyze_chunk(code, filename)
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
