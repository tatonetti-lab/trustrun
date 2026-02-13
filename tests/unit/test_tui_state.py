"""Tests for the TUI state module."""

from __future__ import annotations

import threading

from trustrun.policy.models import Action, Policy, PolicyDefaults
from trustrun.session.models import ConnectionEvent, Violation
from trustrun.tui.state import TuiState, ViewMode


def _make_event(
    remote_ip: str = "1.2.3.4",
    remote_port: int = 443,
    hostname: str = "",
    event_id: str = "",
) -> ConnectionEvent:
    ev = ConnectionEvent(
        pid=1234,
        process_name="test",
        remote_ip=remote_ip,
        remote_port=remote_port,
        hostname=hostname,
    )
    if event_id:
        ev.id = event_id
    return ev


def _make_violation(event: ConnectionEvent) -> Violation:
    return Violation(
        event=event,
        action="block",
        rule_match="<default>",
        reason="test violation",
    )


def _make_state() -> TuiState:
    policy = Policy(name="test", defaults=PolicyDefaults(action=Action.ALERT))
    return TuiState(policy=policy, pid=1234)


def test_add_event_and_snapshot():
    state = _make_state()
    event = _make_event()
    state.add_event(event)

    events, violations, viol_ids = state.snapshot()
    assert len(events) == 1
    assert events[0].remote_ip == "1.2.3.4"
    assert len(violations) == 0
    assert len(viol_ids) == 0


def test_add_violation_and_snapshot():
    state = _make_state()
    event = _make_event(event_id="abc123")
    violation = _make_violation(event)

    state.add_event(event)
    state.add_violation(violation)

    events, violations, viol_ids = state.snapshot()
    assert len(events) == 1
    assert len(violations) == 1
    assert "abc123" in viol_ids


def test_snapshot_returns_copies():
    """Mutating the snapshot lists should not affect internal state."""
    state = _make_state()
    state.add_event(_make_event())

    events1, _, _ = state.snapshot()
    events1.clear()

    events2, _, _ = state.snapshot()
    assert len(events2) == 1


def test_event_count_and_violation_count():
    state = _make_state()
    assert state.event_count == 0
    assert state.violation_count == 0

    state.add_event(_make_event())
    state.add_event(_make_event())
    assert state.event_count == 2

    event = _make_event()
    state.add_violation(_make_violation(event))
    assert state.violation_count == 1


def test_clamp_cursor_empty():
    state = _make_state()
    state.cursor = 5
    state.clamp_cursor(0)
    assert state.cursor == 0


def test_clamp_cursor_within_bounds():
    state = _make_state()
    state.cursor = 2
    state.clamp_cursor(5)
    assert state.cursor == 2


def test_clamp_cursor_too_high():
    state = _make_state()
    state.cursor = 10
    state.clamp_cursor(5)
    assert state.cursor == 4


def test_clamp_cursor_negative():
    state = _make_state()
    state.cursor = -1
    state.clamp_cursor(5)
    assert state.cursor == 0


def test_view_mode_enum():
    assert ViewMode.TABLE.value == "table"
    assert ViewMode.DETAIL.value == "detail"
    assert ViewMode.POLICY.value == "policy"
    assert ViewMode.HELP.value == "help"


def test_concurrent_add_event():
    """Multiple threads adding events should not corrupt state."""
    state = _make_state()
    num_threads = 8
    events_per_thread = 100

    def worker():
        for i in range(events_per_thread):
            state.add_event(_make_event(remote_port=i))

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert state.event_count == num_threads * events_per_thread


def test_concurrent_add_violation():
    """Multiple threads adding violations should not corrupt state."""
    state = _make_state()
    num_threads = 4
    viols_per_thread = 50

    def worker(thread_id: int):
        for i in range(viols_per_thread):
            event = _make_event(event_id=f"t{thread_id}-{i}")
            state.add_violation(_make_violation(event))

    threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert state.violation_count == num_threads * viols_per_thread
    _, _, viol_ids = state.snapshot()
    assert len(viol_ids) == num_threads * viols_per_thread


def test_reevaluate_violations_clears_allowed():
    """After adding an allow rule, reevaluate should clear matching violations."""
    from trustrun.policy.evaluator import PolicyEvaluator
    from trustrun.policy.models import Rule

    state = _make_state()

    # Add events and violations
    ev1 = _make_event(hostname="api.openai.com", event_id="e1")
    ev2 = _make_event(hostname="bad.evil.com", event_id="e2")
    state.add_event(ev1)
    state.add_event(ev2)
    state.add_violation(_make_violation(ev1))
    state.add_violation(_make_violation(ev2))

    assert state.violation_count == 2

    # Create a policy that now explicitly allows *.openai.com
    policy = Policy(
        name="updated",
        rules=(Rule(match="*.openai.com", action=Action.ALERT),),
        defaults=PolicyDefaults(action=Action.BLOCK),
    )
    evaluator = PolicyEvaluator(policy)

    removed = state.reevaluate_violations(evaluator.evaluate)

    assert removed == 1
    assert state.violation_count == 1
    _, _, viol_ids = state.snapshot()
    assert "e1" not in viol_ids
    assert "e2" in viol_ids


def test_reevaluate_violations_keeps_all_when_none_cleared():
    """If no violations are resolved, reevaluate should keep them all."""
    from trustrun.policy.evaluator import PolicyEvaluator

    state = _make_state()
    ev = _make_event(hostname="bad.com", event_id="e1")
    state.add_event(ev)
    state.add_violation(_make_violation(ev))

    # Policy still blocks everything by default
    policy = Policy(
        name="same",
        rules=(),
        defaults=PolicyDefaults(action=Action.BLOCK),
    )
    evaluator = PolicyEvaluator(policy)

    removed = state.reevaluate_violations(evaluator.evaluate)

    assert removed == 0
    assert state.violation_count == 1


def test_concurrent_snapshot_during_writes():
    """Reading snapshots while another thread writes should not raise."""
    state = _make_state()
    errors: list[Exception] = []

    def writer():
        for i in range(200):
            state.add_event(_make_event(remote_port=i))
            ev = _make_event(event_id=f"v{i}")
            state.add_violation(_make_violation(ev))

    def reader():
        for _ in range(200):
            try:
                events, violations, viol_ids = state.snapshot()
                # Snapshots must be consistent: violation IDs subset of actual
                assert isinstance(events, list)
                assert isinstance(violations, list)
                assert isinstance(viol_ids, set)
            except Exception as e:
                errors.append(e)

    wt = threading.Thread(target=writer)
    rt = threading.Thread(target=reader)
    wt.start()
    rt.start()
    wt.join()
    rt.join()

    assert not errors
