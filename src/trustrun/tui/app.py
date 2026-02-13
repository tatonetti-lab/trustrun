"""TUI application — main orchestrator for the interactive htop-style interface."""

from __future__ import annotations

import logging
import os
import signal
import sys
import time

from rich.console import Console
from rich.live import Live

from trustrun.policy.evaluator import PolicyEvaluator
from trustrun.policy.models import Policy
from trustrun.session.manager import SessionManager
from trustrun.tui.display import TuiDisplay
from trustrun.tui.input import KeyboardInput
from trustrun.tui.policy_mutator import (
    add_allow_rule,
    add_block_rule,
    export_policy,
    save_overrides,
)
from trustrun.tui.state import TuiState, ViewMode

logger = logging.getLogger(__name__)

# Status message display duration in seconds
_STATUS_DURATION = 3.0


class TuiApp:
    """Interactive TUI application for TrustRun monitoring sessions.

    Threading model:
    - Main thread: keyboard input + Rich Live rendering (this class)
    - Daemon thread: SessionManager.monitor_loop() (started by caller)
    """

    def __init__(self, state: TuiState, manager: SessionManager) -> None:
        self._state = state
        self._manager = manager
        self._display = TuiDisplay()
        self._console = Console(stderr=True)

    def run(self) -> None:
        """Run the TUI main loop. Blocks until quit or monitor stops."""
        state = self._state

        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def _signal_handler(signum: int, frame: object) -> None:
            state.running = False
            self._manager.stop()

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        try:
            with KeyboardInput() as kb:
                with Live(
                    console=self._console,
                    screen=True,
                    refresh_per_second=4,
                ) as live:
                    while state.running:
                        key = kb.read(timeout=0.05)
                        if key is not None:
                            self._dispatch_key(key)

                        size = os.get_terminal_size(sys.stderr.fileno())
                        layout = self._display.render(
                            state, height=size.lines, width=size.columns
                        )
                        live.update(layout)

                        # Check if monitor thread has finished
                        if not self._manager._stop_event.is_set():
                            continue
                        # Give a moment for final events
                        time.sleep(0.1)
                        state.running = False
        except Exception:
            logger.exception("TUI error")
        finally:
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)

    def _dispatch_key(self, key: str) -> None:
        state = self._state

        # Global keys
        if key == "q":
            state.running = False
            self._manager.stop()
            return

        if key == "?" and state.mode != ViewMode.HELP:
            state.mode = ViewMode.HELP
            return

        if key in ("escape", "\x1b"):
            if state.mode != ViewMode.TABLE:
                state.mode = ViewMode.TABLE
            return

        # Mode-specific dispatch
        if state.mode == ViewMode.TABLE:
            self._handle_table_key(key)
        elif state.mode == ViewMode.DETAIL:
            self._handle_detail_key(key)
        elif state.mode == ViewMode.POLICY:
            self._handle_policy_key(key)
        elif state.mode == ViewMode.HELP:
            # Any key in help returns to table
            if key not in ("q",):
                state.mode = ViewMode.TABLE

    def _handle_table_key(self, key: str) -> None:
        state = self._state

        if key in ("j", "down"):
            state.follow = False
            state.cursor += 1
        elif key in ("k", "up"):
            state.follow = False
            state.cursor = max(0, state.cursor - 1)
        elif key == "g":
            state.follow = False
            state.cursor = 0
            state.scroll_offset = 0
        elif key == "G":
            state.follow = True
        elif key in ("\r", "\n"):
            state.mode = ViewMode.DETAIL
        elif key == "a":
            self._add_allow()
        elif key == "b":
            self._add_block()
        elif key == "p":
            state.mode = ViewMode.POLICY
        elif key == "e":
            self._export_policy()

    def _handle_detail_key(self, key: str) -> None:
        state = self._state

        if key in ("j", "down"):
            state.cursor += 1
        elif key in ("k", "up"):
            state.cursor = max(0, state.cursor - 1)
        elif key == "a":
            self._add_allow()
        elif key == "b":
            self._add_block()

    def _handle_policy_key(self, key: str) -> None:
        if key == "e":
            self._export_policy()

    def _add_allow(self) -> None:
        events, _v, _ids = self._state.snapshot()
        total = len(events)
        if total == 0:
            return
        self._state.clamp_cursor(total)
        event = events[self._state.cursor]

        new_policy = add_allow_rule(self._state.policy, event)
        self._apply_policy(new_policy)
        dest = event.hostname or event.remote_ip
        cleared = self._reevaluate_violations(new_policy)
        suffix = f" ({cleared} cleared)" if cleared else ""
        self._set_status(f"Allowed: {dest}{suffix}")

    def _add_block(self) -> None:
        events, _v, _ids = self._state.snapshot()
        total = len(events)
        if total == 0:
            return
        self._state.clamp_cursor(total)
        event = events[self._state.cursor]

        new_policy = add_block_rule(self._state.policy, event)
        self._apply_policy(new_policy)
        dest = event.hostname or event.remote_ip
        self._reevaluate_violations(new_policy)
        self._set_status(f"Blocked: {dest}")

    def _apply_policy(self, policy: Policy) -> None:
        """Update state and manager with a new policy, and persist."""
        self._state.policy = policy
        self._state.policy_dirty = True
        self._manager.swap_policy(policy)
        try:
            save_overrides(policy)
        except OSError:
            logger.warning("Failed to save overrides", exc_info=True)

    def _reevaluate_violations(self, policy: Policy) -> int:
        """Re-check existing violations against the new policy.

        Returns the number of violations cleared.
        """
        evaluator = PolicyEvaluator(policy)
        return self._state.reevaluate_violations(evaluator.evaluate)

    def _export_policy(self) -> None:
        try:
            filename = export_policy(self._state.policy)
            self._set_status(f"Exported: {filename}")
        except OSError as e:
            self._set_status(f"Export failed: {e}")

    def _set_status(self, message: str) -> None:
        self._state.status_message = message
        self._state._status_expiry = time.time() + _STATUS_DURATION
