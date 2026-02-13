"""Python-specific analyzer using stdlib ast + regex fallback."""

from __future__ import annotations

import ast
import logging
import re

from trustrun.scanner.languages.generic import scan_generic
from trustrun.scanner.models import Finding, Severity

logger = logging.getLogger(__name__)

# Python-specific patterns for network calls
_NETWORK_CALL_PATTERNS = [
    re.compile(r"requests\.(get|post|put|delete|patch|head|options)\s*\("),
    re.compile(r"httpx\.(get|post|put|delete|patch|head|options)\s*\("),
    re.compile(r"httpx\.Client\s*\("),
    re.compile(r"httpx\.AsyncClient\s*\("),
    re.compile(r"urllib\.request\.\w+\s*\("),
    re.compile(r"aiohttp\.ClientSession\s*\("),
    re.compile(r"openai\.OpenAI\s*\("),
    re.compile(r"openai\.AzureOpenAI\s*\("),
    re.compile(r"boto3\.client\s*\("),
    re.compile(r"boto3\.resource\s*\("),
]


def scan_python(content: str, file_path: str) -> list[Finding]:
    """Scan Python source code for network-related patterns."""
    findings = scan_generic(content, file_path, language="python")

    # Try AST-based analysis
    try:
        tree = ast.parse(content)
        findings.extend(_analyze_ast(tree, content, file_path))
    except SyntaxError:
        logger.debug("AST parse failed for %s, using regex only", file_path)

    # Python-specific regex patterns
    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern in _NETWORK_CALL_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=line_num,
                        column=match.start() + 1,
                        pattern_name="python_network_call",
                        matched_text=match.group(0),
                        context_line=line.strip(),
                        severity=Severity.INFO,
                        language="python",
                    )
                )

    return findings


def _analyze_ast(
    tree: ast.Module,
    content: str,
    file_path: str,
) -> list[Finding]:
    """Walk the AST looking for network-related constructs."""
    findings: list[Finding] = []
    lines = content.splitlines()

    for node in ast.walk(tree):
        # Detect string literals that look like URLs
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value
            if re.match(r"https?://", val) and not _is_benign_url(val):
                line_text = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        pattern_name="python_url_literal",
                        matched_text=val,
                        context_line=line_text.strip(),
                        severity=Severity.WARNING,
                        extracted_endpoint=val,
                        language="python",
                    )
                )

        # Detect keyword arguments like base_url=, endpoint=, host=
        if isinstance(node, ast.keyword) and node.arg in (
            "base_url",
            "endpoint",
            "host",
            "url",
            "api_base",
            "azure_endpoint",
        ):
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                val = node.value.value
                line_text = (
                    lines[node.value.lineno - 1]
                    if node.value.lineno <= len(lines)
                    else ""
                )
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=node.value.lineno,
                        column=node.value.col_offset + 1,
                        pattern_name="python_endpoint_kwarg",
                        matched_text=f"{node.arg}={val!r}",
                        context_line=line_text.strip(),
                        severity=Severity.WARNING,
                        extracted_endpoint=val,
                        language="python",
                    )
                )

    return findings


def _is_benign_url(url: str) -> bool:
    """Check if a URL is unlikely to be a real endpoint."""
    benign = (
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "example.com",
        "schemas.",
        "www.w3.org",
        "tools.ietf.org",
    )
    return any(b in url for b in benign)
