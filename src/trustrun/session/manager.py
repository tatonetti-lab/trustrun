"""Session manager — orchestrates capture, evaluation, and actions."""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from collections.abc import Callable

from trustrun.actions.alert import AlertAction
from trustrun.capture.psutil_ import PsutilCapture
from trustrun.policy.evaluator import PolicyEvaluator, Verdict
from trustrun.policy.models import Action, Policy
from trustrun.session.models import (
    ConnectionEvent,
    Session,
    SessionStatus,
    Violation,
)

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages a monitoring session: capture backend + policy evaluation + actions."""

    def __init__(
        self,
        policy: Policy,
        poll_interval: float = 0.5,
        on_event: Callable[[ConnectionEvent], None] | None = None,
        on_violation: Callable[[Violation], None] | None = None,
    ) -> None:
        self._policy = policy
        self._evaluator = PolicyEvaluator(policy)
        self._poll_interval = poll_interval
        self._on_event = on_event
        self._on_violation = on_violation
        self._capture = PsutilCapture()
        self._alert = AlertAction()
        self._stop_event = threading.Event()
        self._session: Session | None = None
        self._subprocess: subprocess.Popen[bytes] | None = None

    @property
    def session(self) -> Session | None:
        return self._session

    @property
    def capture_sniffer_active(self) -> bool:
        """Whether the passive DNS/SNI sniffer is running."""
        return self._capture.sniffer_active

    def watch(self, pid: int) -> Session:
        """Attach to an existing process by PID."""
        self._session = Session(
            pid=pid,
            policy_name=self._policy.name,
            status=SessionStatus.RUNNING,
        )
        self._capture.start(pid, include_children=True)
        logger.info("Watching PID %d with policy '%s'", pid, self._policy.name)
        return self._session

    def run(self, command: list[str]) -> Session:
        """Launch a subprocess and monitor it."""
        self._subprocess = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        pid = self._subprocess.pid
        self._session = Session(
            pid=pid,
            policy_name=self._policy.name,
            command=" ".join(command),
            status=SessionStatus.RUNNING,
        )
        self._capture.start(pid, include_children=True)
        logger.info(
            "Running '%s' (PID %d) with policy '%s'",
            " ".join(command),
            pid,
            self._policy.name,
        )
        return self._session

    def monitor_loop(self) -> None:
        """Blocking poll→evaluate→act loop until stop() or process exit."""
        if self._session is None:
            raise RuntimeError("No session started — call watch() or run() first")

        self._stop_event.clear()

        while not self._stop_event.is_set():
            if not self._capture.is_running:
                logger.info("Capture backend stopped — ending monitor loop")
                break

            # Check if subprocess has exited (for `run` mode)
            if self._subprocess is not None and self._subprocess.poll() is not None:
                logger.info(
                    "Subprocess exited with code %d", self._subprocess.returncode
                )
                # Do one final poll to catch last connections
                self._poll_and_evaluate()
                break

            self._poll_and_evaluate()
            self._stop_event.wait(timeout=self._poll_interval)

        self._finalize()

    def stop(self) -> None:
        """Signal the monitor loop to stop."""
        self._stop_event.set()

    def get_subprocess_returncode(self) -> int | None:
        """Return subprocess exit code, or None if N/A."""
        if self._subprocess is not None:
            return self._subprocess.returncode
        return None

    def terminate_subprocess(self) -> None:
        """Terminate the managed subprocess if running."""
        if self._subprocess is not None and self._subprocess.poll() is None:
            self._subprocess.terminate()
            try:
                self._subprocess.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._subprocess.kill()

    def _poll_and_evaluate(self) -> None:
        events = self._capture.poll()
        for event in events:
            if self._session is not None:
                self._session.events.append(event)

            if self._on_event:
                self._on_event(event)

            verdict = self._evaluator.evaluate(
                ip=event.remote_ip,
                hostname=event.hostname,
                port=event.remote_port,
            )
            self._handle_verdict(event, verdict)

    def _handle_verdict(self, event: ConnectionEvent, verdict: Verdict) -> None:
        # Explicit rule matches with alert action are just logged, not violations
        if not verdict.is_default and verdict.action == Action.ALERT:
            logger.debug(
                "Allowed: %s:%d matched rule '%s'",
                event.remote_ip,
                event.remote_port,
                verdict.matched_rule.match if verdict.matched_rule else "?",
            )
            return

        # Violations: block/kill actions, or unmatched (default) connections
        rule_match = verdict.matched_rule.match if verdict.matched_rule else "<default>"
        reason = (
            verdict.matched_rule.reason
            if verdict.matched_rule
            else f"No rule matched — default action: {verdict.action.value}"
        )

        violation = Violation(
            event=event,
            action=verdict.action.value,
            rule_match=rule_match,
            reason=reason,
        )

        if self._session is not None:
            self._session.violations.append(violation)

        self._alert.execute(event, violation)

        if self._on_violation:
            self._on_violation(violation)

    def _finalize(self) -> None:
        self._capture.stop()
        if self._session is not None:
            self._session.status = SessionStatus.STOPPED
            self._session.end_time = time.time()
