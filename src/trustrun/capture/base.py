"""CaptureBackend protocol — all capture implementations must satisfy this."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from trustrun.session.models import ConnectionEvent


@runtime_checkable
class CaptureBackend(Protocol):
    """Protocol for network capture backends."""

    def start(self, pid: int, include_children: bool = True) -> None:
        """Begin capturing connections for the given PID."""
        ...

    def stop(self) -> None:
        """Stop capturing."""
        ...

    def poll(self) -> list[ConnectionEvent]:
        """Return new connection events since last poll."""
        ...

    @property
    def is_running(self) -> bool:
        """Whether the backend is actively capturing."""
        ...
