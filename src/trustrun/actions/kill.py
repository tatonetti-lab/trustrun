"""Kill action — terminate the offending process."""

from __future__ import annotations

import logging
import os
import signal

from trustrun.session.models import ConnectionEvent, Violation

logger = logging.getLogger(__name__)


class KillAction:
    """Terminates the process that made a policy-violating connection."""

    def execute(self, event: ConnectionEvent, violation: Violation) -> bool:
        pid = event.pid
        logger.critical(
            "KILLING process %d (%s) — connection to %s:%d — %s",
            pid,
            event.process_name,
            event.remote_ip,
            event.remote_port,
            violation.reason,
        )

        try:
            os.kill(pid, signal.SIGKILL)
            logger.info("Process %d killed successfully", pid)
            return True
        except ProcessLookupError:
            logger.warning("Process %d already exited", pid)
            return True
        except PermissionError:
            logger.error("Permission denied killing process %d", pid)
            return False
