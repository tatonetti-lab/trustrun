"""Policy data models — immutable dataclasses used across the entire codebase."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Action(enum.Enum):
    """What to do when a connection matches a rule."""

    ALERT = "alert"
    BLOCK = "block"
    KILL = "kill"


class CaptureLevel(enum.Enum):
    """How deeply to inspect traffic."""

    METADATA = "metadata"
    HEADERS = "headers"
    FULL = "full"


@dataclass(frozen=True)
class Rule:
    """A single policy rule that matches against connection destinations."""

    match: str
    action: Action
    reason: str = ""
    ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class PolicyDefaults:
    """Default behaviour when no rule matches."""

    action: Action = Action.ALERT


@dataclass(frozen=True)
class Policy:
    """A complete policy definition."""

    name: str
    rules: tuple[Rule, ...] = ()
    defaults: PolicyDefaults = field(default_factory=PolicyDefaults)
    description: str = ""
    capture_level: CaptureLevel = CaptureLevel.METADATA
    inherit: tuple[str, ...] = ()
