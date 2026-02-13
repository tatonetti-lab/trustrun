"""Tests for the static code scanner."""

from __future__ import annotations

from pathlib import Path

from trustrun.policy.models import Action, Policy, PolicyDefaults, Rule
from trustrun.scanner.engine import ScanEngine
from trustrun.scanner.languages.generic import scan_generic
from trustrun.scanner.languages.javascript import scan_javascript
from trustrun.scanner.languages.python import scan_python
from trustrun.scanner.models import Severity
from trustrun.scanner.patterns import is_excluded


class TestPatterns:
    def test_url_detection(self):
        findings = scan_generic(
            'url = "https://api.openai.com/v1/chat"',
            "test.txt",
        )
        urls = [f for f in findings if f.pattern_name == "url"]
        assert len(urls) == 1
        assert "openai.com" in urls[0].matched_text

    def test_ip_literal_detection(self):
        findings = scan_generic(
            'host = "192.168.1.100:8080"',
            "test.txt",
        )
        ips = [f for f in findings if f.pattern_name == "ip_literal"]
        assert len(ips) == 1

    def test_aws_key_detection(self):
        findings = scan_generic(
            'aws_key = "AKIAIOSFODNN7EXAMPLE"',
            "test.txt",
        )
        keys = [f for f in findings if f.pattern_name == "aws_access_key"]
        assert len(keys) == 1
        assert keys[0].severity == Severity.CRITICAL

    def test_openai_key_detection(self):
        findings = scan_generic(
            'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"',
            "test.txt",
        )
        keys = [
            f
            for f in findings
            if f.pattern_name == "openai_api_key"
        ]
        assert len(keys) == 1
        assert keys[0].severity == Severity.CRITICAL

    def test_localhost_excluded(self):
        assert is_excluded("http://localhost:8080")
        assert is_excluded("http://127.0.0.1:3000")

    def test_external_url_not_excluded(self):
        assert not is_excluded("https://api.openai.com")


class TestPythonAnalyzer:
    def test_detects_requests_call(self):
        code = 'response = requests.get("https://api.example.com")'
        findings = scan_python(code, "app.py")
        patterns = [f.pattern_name for f in findings]
        assert "python_network_call" in patterns

    def test_detects_url_in_ast(self):
        code = 'url = "https://api.production.com/data"\n'
        findings = scan_python(code, "app.py")
        endpoints = [
            f for f in findings if f.pattern_name == "python_url_literal"
        ]
        assert len(endpoints) >= 1

    def test_detects_base_url_kwarg(self):
        code = 'client = OpenAI(base_url="https://my-api.com/v1")\n'
        findings = scan_python(code, "app.py")
        kwargs = [
            f
            for f in findings
            if f.pattern_name == "python_endpoint_kwarg"
        ]
        assert len(kwargs) >= 1

    def test_syntax_error_falls_back(self):
        code = "this is not valid python {{{"
        # Should not raise, falls back to regex
        findings = scan_python(code, "bad.py")
        assert isinstance(findings, list)


class TestJavaScriptAnalyzer:
    def test_detects_fetch(self):
        code = 'const resp = await fetch("https://api.com/data");'
        findings = scan_javascript(code, "app.js")
        patterns = [f.pattern_name for f in findings]
        assert "js_network_call" in patterns

    def test_detects_axios(self):
        code = 'const data = await axios.get("/api/users");'
        findings = scan_javascript(code, "app.ts")
        patterns = [f.pattern_name for f in findings]
        assert "js_network_call" in patterns


class TestScanEngine:
    def test_scan_directory(self, tmp_path: Path):
        # Create test files
        py_file = tmp_path / "app.py"
        py_file.write_text(
            'import requests\n'
            'resp = requests.get("https://api.openai.com/v1/chat")\n'
        )
        js_file = tmp_path / "app.js"
        js_file.write_text(
            'const resp = await fetch("https://api.openai.com");\n'
        )

        engine = ScanEngine()
        result = engine.scan(tmp_path)

        assert result.files_scanned >= 2
        assert len(result.findings) > 0

    def test_scan_with_policy_elevates_severity(self, tmp_path: Path):
        py_file = tmp_path / "app.py"
        py_file.write_text(
            'url = "https://api.openai.com/v1/chat"\n'
        )

        policy = Policy(
            name="test",
            rules=(
                Rule(
                    match="*.openai.com",
                    action=Action.BLOCK,
                    reason="Direct OpenAI blocked",
                ),
            ),
        )

        engine = ScanEngine(policy=policy)
        result = engine.scan(tmp_path)

        critical = [
            f
            for f in result.findings
            if f.severity == Severity.CRITICAL
        ]
        assert len(critical) > 0

    def test_scan_skips_gitdir(self, tmp_path: Path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("secret stuff")

        engine = ScanEngine()
        result = engine.scan(tmp_path)
        scanned_files = [
            f.file_path for f in result.findings
        ]
        assert not any(".git" in p for p in scanned_files)

    def test_scan_with_exclude(self, tmp_path: Path):
        (tmp_path / "keep.py").write_text(
            'x = "https://api.example.com"\n'
        )
        (tmp_path / "skip.py").write_text(
            'x = "https://api.secret.com"\n'
        )

        engine = ScanEngine(exclude_patterns=["skip.py"])
        result = engine.scan(tmp_path)
        files = [f.file_path for f in result.findings]
        assert not any("skip.py" in f for f in files)
