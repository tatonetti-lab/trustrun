"""Alert action — logs violations and calls optional callback."""

from __future__ import annotations

import logging
from collections.abc import Callable

from trustrun.session.models import ConnectionEvent, Violation

logger = logging.getLogger(__name__)


class AlertAction:
    """Logs violation details and optionally invokes a callback."""

    def __init__(
        self,
        callback: Callable[[ConnectionEvent, Violation], None] | None = None,
    ) -> None:
        self._callback = callback

    def execute(self, event: ConnectionEvent, violation: Violation) -> bool:
        logger.warning(
            "VIOLATION [%s]: %s:%d (%s) — %s",
            violation.action,
            event.remote_ip,
            event.remote_port,
            event.hostname or "unknown",
            violation.reason,
        )
        if self._callback:
            self._callback(event, violation)
        return True
