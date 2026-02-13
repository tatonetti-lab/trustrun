"""Action handler protocol — response actions when violations are detected."""

from __future__ import annotations

from typing import Protocol

from trustrun.session.models import ConnectionEvent, Violation


class ActionHandler(Protocol):
    """Protocol for violation response actions."""

    def execute(self, event: ConnectionEvent, violation: Violation) -> bool:
        """Execute the action. Returns True if action was successful."""
        ...
