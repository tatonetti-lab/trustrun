"""Tests for the session manager."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

from trustrun.policy.models import Action, Policy, PolicyDefaults, Rule
from trustrun.session.manager import SessionManager
from trustrun.session.models import ConnectionEvent, SessionStatus


def _make_event(
    remote_ip: str = "1.2.3.4",
    remote_port: int = 443,
    hostname: str = "",
) -> ConnectionEvent:
    return ConnectionEvent(
        pid=1234,
        process_name="test",
        remote_ip=remote_ip,
        remote_port=remote_port,
        hostname=hostname,
    )


@patch("trustrun.session.manager.PsutilCapture")
def test_watch_creates_session(mock_capture_cls: MagicMock):
    capture = MagicMock()
    mock_capture_cls.return_value = capture

    policy = Policy(name="test", defaults=PolicyDefaults(action=Action.ALERT))
    manager = SessionManager(policy=policy)
    session = manager.watch(pid=1234)

    assert session.pid == 1234
    assert session.status == SessionStatus.RUNNING
    assert session.policy_name == "test"
    capture.start.assert_called_once_with(1234, include_children=True)


@patch("trustrun.session.manager.PsutilCapture")
def test_monitor_loop_processes_events(mock_capture_cls: MagicMock):
    capture = MagicMock()
    capture.is_running = True
    mock_capture_cls.return_value = capture

    events_seen: list[ConnectionEvent] = []
    violations_seen: list = []

    policy = Policy(
        name="test",
        rules=(Rule(match="*.allowed.com", action=Action.ALERT),),
        defaults=PolicyDefaults(action=Action.BLOCK),
    )

    manager = SessionManager(
        policy=policy,
        poll_interval=0.01,
        on_event=lambda e: events_seen.append(e),
        on_violation=lambda v: violations_seen.append(v),
    )
    manager.watch(pid=1234)

    # First poll returns events, second poll triggers stop
    call_count = 0

    def mock_poll():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [
                _make_event("1.2.3.4", 443, "api.allowed.com"),
                _make_event("9.9.9.9", 80, "bad.unknown.com"),
            ]
        manager.stop()
        return []

    capture.poll.side_effect = mock_poll

    manager.monitor_loop()

    assert len(events_seen) == 2
    # api.allowed.com matches alert rule → not a violation
    # bad.unknown.com falls to default (block) → violation
    assert len(violations_seen) == 1
    assert violations_seen[0].action == "block"


@patch("trustrun.session.manager.PsutilCapture")
def test_stop_ends_loop(mock_capture_cls: MagicMock):
    capture = MagicMock()
    capture.is_running = True
    capture.poll.return_value = []
    mock_capture_cls.return_value = capture

    policy = Policy(name="test", defaults=PolicyDefaults(action=Action.ALERT))
    manager = SessionManager(policy=policy, poll_interval=0.01)
    manager.watch(pid=1234)

    # Stop from another thread
    def stop_later():
        import time
        time.sleep(0.05)
        manager.stop()

    t = threading.Thread(target=stop_later)
    t.start()

    manager.monitor_loop()
    t.join()

    session = manager.session
    assert session is not None
    assert session.status == SessionStatus.STOPPED


@patch("trustrun.session.manager.PsutilCapture")
def test_session_records_events_and_violations(mock_capture_cls: MagicMock):
    capture = MagicMock()
    capture.is_running = True
    mock_capture_cls.return_value = capture

    policy = Policy(
        name="test",
        rules=(),
        defaults=PolicyDefaults(action=Action.ALERT),
    )

    manager = SessionManager(policy=policy, poll_interval=0.01)
    manager.watch(pid=1234)

    call_count = 0

    def mock_poll():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [_make_event("8.8.8.8", 53)]
        manager.stop()
        return []

    capture.poll.side_effect = mock_poll
    manager.monitor_loop()

    session = manager.session
    assert session is not None
    assert len(session.events) == 1
    # Default alert action on unmatched → violation
    assert len(session.violations) == 1
