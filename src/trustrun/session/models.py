"""Session data models — connection events, violations, and session state."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field


class SessionStatus(enum.Enum):
    """Lifecycle state of a monitoring session."""

    PENDING = "pending"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class ConnectionEvent:
    """A single observed network connection."""

    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    local_ip: str = ""
    local_port: int = 0
    hostname: str = ""
    org: str = ""
    protocol: str = "tcp"
    status: str = "ESTABLISHED"
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class Violation:
    """A policy violation linked to a connection event."""

    event: ConnectionEvent
    action: str
    rule_match: str
    reason: str
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class Session:
    """A monitoring session tying together capture, evaluation, and actions."""

    pid: int
    policy_name: str
    command: str = ""
    status: SessionStatus = SessionStatus.PENDING
    events: list[ConnectionEvent] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
