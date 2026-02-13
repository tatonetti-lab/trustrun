"""Scan engine — orchestrates static analysis across files."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from trustrun.policy.evaluator import PolicyEvaluator
from trustrun.policy.models import Action, Policy
from trustrun.scanner.languages.generic import scan_generic
from trustrun.scanner.languages.javascript import scan_javascript
from trustrun.scanner.languages.python import scan_python
from trustrun.scanner.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# File extension → analyzer mapping
_ANALYZERS = {
    ".py": scan_python,
    ".js": scan_javascript,
    ".ts": scan_javascript,
    ".jsx": scan_javascript,
    ".tsx": scan_javascript,
    ".mjs": scan_javascript,
}

# Directories to always skip
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    ".env",
    "env",
    "dist",
    "build",
    ".tox",
    ".eggs",
    "*.egg-info",
}

# Binary / non-text extensions to skip
_SKIP_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".dat",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".pdf",
    ".doc",
    ".docx",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".whl",
    ".egg",
    ".db",
    ".sqlite",
    ".sqlite3",
}

# Max file size to scan (1 MB)
_MAX_FILE_SIZE = 1_048_576


class ScanEngine:
    """Orchestrates static code analysis across a directory."""

    def __init__(
        self,
        policy: Policy | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> None:
        self._policy = policy
        self._evaluator = PolicyEvaluator(policy) if policy else None
        self._exclude = set(exclude_patterns or [])

    def scan(self, directory: str | Path) -> ScanResult:
        """Scan a directory and return aggregated results."""
        directory = Path(directory).resolve()
        start = time.time()

        result = ScanResult(
            directory=str(directory),
            policy_name=self._policy.name if self._policy else "",
        )

        for file_path in self._walk(directory):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError) as e:
                logger.debug("Skipping %s: %s", file_path, e)
                result.files_skipped += 1
                continue

            result.files_scanned += 1
            findings = self._analyze_file(content, str(file_path))

            # Elevate severity if endpoint matches a block/kill rule
            if self._evaluator:
                for f in findings:
                    if f.extracted_endpoint:
                        self._evaluate_finding(f)

            result.findings.extend(findings)

        result.duration = time.time() - start
        return result

    def _walk(self, directory: Path):
        """Walk directory yielding scannable files."""
        for root, dirs, files in os.walk(directory):
            # Prune skipped directories in-place
            dirs[:] = [
                d
                for d in dirs
                if d not in _SKIP_DIRS
                and not d.endswith(".egg-info")
                and d not in self._exclude
            ]

            for name in files:
                path = Path(root) / name
                if path.suffix in _SKIP_EXTENSIONS:
                    continue
                if name in self._exclude:
                    continue
                try:
                    if path.stat().st_size > _MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                yield path

    def _analyze_file(self, content: str, file_path: str) -> list[Finding]:
        """Select the appropriate analyzer for a file."""
        ext = Path(file_path).suffix.lower()
        analyzer = _ANALYZERS.get(ext)
        if analyzer:
            return analyzer(content, file_path)
        # Generic fallback for text files
        return scan_generic(content, file_path)

    def _evaluate_finding(self, finding: Finding) -> None:
        """Elevate severity based on policy evaluation."""
        if not self._evaluator:
            return

        endpoint = finding.extracted_endpoint
        # Try to extract hostname from URL
        hostname = _extract_hostname(endpoint)
        if not hostname:
            return

        verdict = self._evaluator.evaluate(ip="", hostname=hostname, port=0)
        if verdict.matched_rule and verdict.action in (Action.BLOCK, Action.KILL):
            finding.severity = Severity.CRITICAL
        elif verdict.is_default:
            # Unrecognized endpoint — bump to warning at minimum
            if finding.severity == Severity.INFO:
                finding.severity = Severity.WARNING


def _extract_hostname(endpoint: str) -> str:
    """Extract hostname from a URL or return as-is."""
    if "://" in endpoint:
        # Remove scheme
        after_scheme = endpoint.split("://", 1)[1]
        # Remove path, port, auth
        host = after_scheme.split("/", 1)[0]
        host = host.split(":", 1)[0]
        host = host.split("@")[-1]
        return host
    return endpoint
