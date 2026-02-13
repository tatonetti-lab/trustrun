"""Scanner data models — findings and scan results."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Finding severity level."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single static analysis finding."""

    file_path: str
    line: int
    column: int
    pattern_name: str
    matched_text: str
    context_line: str
    severity: Severity
    extracted_endpoint: str = ""
    language: str = ""


@dataclass
class ScanResult:
    """Aggregate result of a static scan."""

    directory: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    duration: float = 0.0
    policy_name: str = ""
    timestamp: float = field(default_factory=time.time)
