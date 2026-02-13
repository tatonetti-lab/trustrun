"""Generic regex-based analyzer — fallback for any file type."""

from __future__ import annotations

from trustrun.scanner.models import Finding
from trustrun.scanner.patterns import PATTERNS, is_excluded


def scan_generic(
    content: str,
    file_path: str,
    language: str = "",
) -> list[Finding]:
    """Scan file content using universal regex patterns."""
    findings: list[Finding] = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                matched_text = match.group(0)
                if is_excluded(matched_text):
                    continue

                endpoint = ""
                if pattern.extract_endpoint:
                    endpoint = pattern.extract_endpoint(match)

                findings.append(
                    Finding(
                        file_path=file_path,
                        line=line_num,
                        column=match.start() + 1,
                        pattern_name=pattern.name,
                        matched_text=matched_text,
                        context_line=line.strip(),
                        severity=pattern.severity,
                        extracted_endpoint=endpoint,
                        language=language,
                    )
                )

    return findings
