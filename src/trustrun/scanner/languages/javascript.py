"""JavaScript/TypeScript analyzer — regex-based pattern detection."""

from __future__ import annotations

import re

from trustrun.scanner.languages.generic import scan_generic
from trustrun.scanner.models import Finding, Severity

_JS_NETWORK_PATTERNS = [
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\baxios\.(get|post|put|delete|patch)\s*\("),
    re.compile(r"\baxios\s*\("),
    re.compile(r"\bnew\s+URL\s*\("),
    re.compile(r"\bXMLHttpRequest\b"),
    re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)'),
]


def scan_javascript(content: str, file_path: str) -> list[Finding]:
    """Scan JS/TS source for network-related patterns."""
    findings = scan_generic(content, file_path, language="javascript")

    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern in _JS_NETWORK_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=line_num,
                        column=match.start() + 1,
                        pattern_name="js_network_call",
                        matched_text=match.group(0),
                        context_line=line.strip(),
                        severity=Severity.INFO,
                        language="javascript",
                    )
                )

    return findings
