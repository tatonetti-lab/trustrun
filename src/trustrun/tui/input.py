"""Non-blocking keyboard input via termios cbreak mode."""

from __future__ import annotations

import os
import selectors
import sys
import termios
import tty
from types import TracebackType

# Escape sequence mappings
_ESCAPE_SEQUENCES = {
    "[A": "up",
    "[B": "down",
    "[C": "right",
    "[D": "left",
}


class KeyboardInput:
    """Context manager that puts stdin into cbreak mode for single-key reads.

    Uses ``os.read`` on the raw file descriptor so that reads stay in
    sync with what ``selectors`` reports as available.  Python's
    buffered ``sys.stdin.read`` can consume multiple bytes into its
    internal buffer, causing the selector to miss subsequent bytes of
    an escape sequence.

    Usage::

        with KeyboardInput() as kb:
            key = kb.read(timeout=0.05)  # returns key string or None
    """

    def __init__(self) -> None:
        self._old_settings: list | None = None
        self._selector = selectors.DefaultSelector()
        self._fd: int = sys.stdin.fileno()

    def __enter__(self) -> KeyboardInput:
        self._old_settings = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)
        self._selector.register(self._fd, selectors.EVENT_READ)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._selector.unregister(self._fd)
        self._selector.close()
        if self._old_settings is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_settings)

    def _read_byte(self) -> str:
        return os.read(self._fd, 1).decode("utf-8", errors="replace")

    def read(self, timeout: float = 0.05) -> str | None:
        """Read a single key press, returning None on timeout.

        Handles escape sequences for arrow keys.
        """
        ready = self._selector.select(timeout=timeout)
        if not ready:
            return None

        ch = self._read_byte()
        if ch == "\x1b":
            # Possible escape sequence — read more if available
            return self._read_escape_sequence()
        return ch

    def _read_escape_sequence(self) -> str:
        """Try to read an escape sequence like \\x1b[A (arrow up)."""
        seq = ""
        for _ in range(2):
            ready = self._selector.select(timeout=0.02)
            if not ready:
                break
            seq += self._read_byte()

        return _ESCAPE_SEQUENCES.get(seq, "escape")
