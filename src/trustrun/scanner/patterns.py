"""Universal regex patterns for detecting endpoints, keys, and secrets."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from trustrun.scanner.models import Severity


@dataclass
class Pattern:
    """A detection pattern with compiled regex and metadata."""

    name: str
    regex: re.Pattern[str]
    severity: Severity
    extract_endpoint: Callable[[re.Match[str]], str] | None = None


def _extract_url(m: re.Match[str]) -> str:
    return m.group(0)


def _extract_ip(m: re.Match[str]) -> str:
    return m.group(1)


def _extract_host_port(m: re.Match[str]) -> str:
    return m.group(0)


PATTERNS: list[Pattern] = [
    Pattern(
        name="url",
        regex=re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+"),
        severity=Severity.WARNING,
        extract_endpoint=_extract_url,
    ),
    Pattern(
        name="ip_literal",
        regex=re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"(?::(\d{1,5}))?\b"
        ),
        severity=Severity.WARNING,
        extract_endpoint=_extract_ip,
    ),
    Pattern(
        name="aws_access_key",
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity=Severity.CRITICAL,
    ),
    Pattern(
        name="azure_connection_string",
        regex=re.compile(
            r"DefaultEndpointsProtocol=https?;"
            r"AccountName=[^;]+;"
            r"AccountKey=[^;]+",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
    ),
    Pattern(
        name="openai_api_key",
        regex=re.compile(r"\b(sk-[a-zA-Z0-9]{20,})\b"),
        severity=Severity.CRITICAL,
    ),
    Pattern(
        name="generic_api_key",
        regex=re.compile(
            r"(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)"
            r'\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
            re.IGNORECASE,
        ),
        severity=Severity.WARNING,
    ),
]

# Common false-positive patterns to exclude
EXCLUDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)"),
    re.compile(r"https?://example\.com"),
    re.compile(r"https?://schemas\."),
    re.compile(r"https?://www\.w3\.org"),
    re.compile(r"https?://tools\.ietf\.org"),
    re.compile(r"\b(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d+)\b"),
    re.compile(r"\b10\.0\.0\.0\b"),  # common in CIDR notation
]


def is_excluded(text: str) -> bool:
    """Check if matched text is a known false positive."""
    return any(p.search(text) for p in EXCLUDE_PATTERNS)
