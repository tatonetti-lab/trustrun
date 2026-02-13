"""Thread-safe shared state between the monitor thread and the TUI thread."""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field

from trustrun.policy.models import Policy
from trustrun.session.models import ConnectionEvent, Violation


class ViewMode(enum.Enum):
    """Which view the TUI is currently showing."""

    TABLE = "table"
    DETAIL = "detail"
    POLICY = "policy"
    HELP = "help"


@dataclass
class TuiState:
    """Shared state for the interactive TUI.

    The monitor thread calls add_event / add_violation (lock-guarded).
    The TUI thread reads via snapshot() and mutates cursor/scroll/mode directly
    (single-writer, no lock needed for those).
    """

    policy: Policy
    pid: int
    sniffer_active: bool = False
    command: str = ""

    # --- Guarded by _lock (written by monitor thread) ---
    _events: list[ConnectionEvent] = field(default_factory=list)
    _violations: list[Violation] = field(default_factory=list)
    _violation_event_ids: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # --- TUI-thread only (no lock needed) ---
    cursor: int = 0
    scroll_offset: int = 0
    mode: ViewMode = ViewMode.TABLE
    follow: bool = True
    running: bool = True
    policy_dirty: bool = False
    status_message: str = ""
    _status_expiry: float = 0.0

    def add_event(self, event: ConnectionEvent) -> None:
        """Append a connection event (called from monitor thread)."""
        with self._lock:
            self._events.append(event)

    def add_violation(self, violation: Violation) -> None:
        """Append a violation (called from monitor thread)."""
        with self._lock:
            self._violations.append(violation)
            self._violation_event_ids.add(violation.event.id)

    def snapshot(
        self,
    ) -> tuple[list[ConnectionEvent], list[Violation], set[str]]:
        """Return consistent copies of events, violations, and violation IDs."""
        with self._lock:
            return (
                list(self._events),
                list(self._violations),
                set(self._violation_event_ids),
            )

    @property
    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    @property
    def violation_count(self) -> int:
        with self._lock:
            return len(self._violations)

    def clamp_cursor(self, total: int) -> None:
        """Keep cursor within valid bounds for the current event list size."""
        if total == 0:
            self.cursor = 0
        else:
            self.cursor = max(0, min(self.cursor, total - 1))

    def reevaluate_violations(
        self,
        evaluate_fn: object,
    ) -> int:
        """Re-check all violations against a new evaluator.

        Drops violations that are no longer violations under the new
        policy (i.e., now matched by an explicit ALERT rule).

        ``evaluate_fn`` must be callable with (ip, hostname, port)
        keyword arguments and return a verdict with ``is_default``
        and ``action`` attributes.

        Returns the number of violations removed.
        """
        from trustrun.policy.models import Action

        with self._lock:
            kept: list[Violation] = []
            new_ids: set[str] = set()
            for v in self._violations:
                ev = v.event
                verdict = evaluate_fn(  # type: ignore[operator]
                    ip=ev.remote_ip,
                    hostname=ev.hostname,
                    port=ev.remote_port,
                )
                # Same logic as SessionManager._handle_verdict:
                # explicit ALERT match → no longer a violation
                if (
                    not verdict.is_default
                    and verdict.action == Action.ALERT
                ):
                    continue
                kept.append(v)
                new_ids.add(ev.id)
            removed = len(self._violations) - len(kept)
            self._violations = kept
            self._violation_event_ids = new_ids
            return removed
