"""Tests for the TUI display module."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from trustrun.policy.models import Action, Policy, PolicyDefaults, Rule
from trustrun.session.models import ConnectionEvent, Violation
from trustrun.tui.display import TuiDisplay
from trustrun.tui.state import TuiState, ViewMode


def _make_event(
    remote_ip: str = "1.2.3.4",
    remote_port: int = 443,
    hostname: str = "",
    process_name: str = "python3",
    org: str = "",
    event_id: str = "",
) -> ConnectionEvent:
    ev = ConnectionEvent(
        pid=1234,
        process_name=process_name,
        remote_ip=remote_ip,
        remote_port=remote_port,
        hostname=hostname,
        org=org,
    )
    if event_id:
        ev.id = event_id
    return ev


def _make_violation(event: ConnectionEvent) -> Violation:
    return Violation(
        event=event,
        action="block",
        rule_match="<default>",
        reason="No rule matched",
    )


def _make_policy() -> Policy:
    return Policy(
        name="test-policy",
        rules=(
            Rule(match="*.allowed.com", action=Action.ALERT, reason="Allowed"),
            Rule(match="*.blocked.com", action=Action.BLOCK, reason="Blocked"),
        ),
        defaults=PolicyDefaults(action=Action.ALERT),
    )


def _render_to_string(state: TuiState, height: int = 24, width: int = 80) -> str:
    """Render the TUI to a string for assertion."""
    display = TuiDisplay()
    layout = display.render(state, height=height, width=width)
    buf = StringIO()
    console = Console(file=buf, width=width, height=height, force_terminal=True)
    console.print(layout)
    return buf.getvalue()


def test_render_table_empty_state():
    state = TuiState(policy=_make_policy(), pid=1234)
    output = _render_to_string(state)
    assert "Waiting for connections..." in output


def test_render_table_with_events():
    state = TuiState(policy=_make_policy(), pid=1234)
    state.add_event(_make_event(hostname="api.azure.com", org="Microsoft"))
    state.add_event(_make_event(hostname="pypi.org", org="Fastly"))

    output = _render_to_string(state, width=120)
    assert "api.azure.com" in output
    assert "pypi.org" in output
    assert "Microsoft" in output


def test_render_table_violation_row():
    state = TuiState(policy=_make_policy(), pid=1234)
    event = _make_event(hostname="api.openai.com", event_id="viol1")
    state.add_event(event)
    state.add_violation(_make_violation(event))

    output = _render_to_string(state)
    assert "api.openai.com" in output


def test_render_detail_mode():
    state = TuiState(policy=_make_policy(), pid=1234)
    event = _make_event(
        hostname="api.openai.com",
        remote_ip="104.18.6.192",
        remote_port=443,
        process_name="python3",
        org="Cloudflare",
        event_id="det1",
    )
    state.add_event(event)
    state.cursor = 0
    state.mode = ViewMode.DETAIL

    output = _render_to_string(state)
    assert "Connection Detail" in output
    assert "api.openai.com" in output
    assert "104.18.6.192" in output
    assert "python3" in output
    assert "Cloudflare" in output
    assert "No violation" in output


def test_render_detail_mode_violation():
    state = TuiState(policy=_make_policy(), pid=1234)
    event = _make_event(hostname="api.openai.com", event_id="det2")
    state.add_event(event)
    violation = _make_violation(event)
    state.add_violation(violation)
    state.cursor = 0
    state.mode = ViewMode.DETAIL

    # Use a taller terminal so all detail lines are visible
    output = _render_to_string(state, height=30)
    assert "VIOLATION" in output
    assert "BLOCK" in output
    assert "No rule matched" in output


def test_render_policy_mode():
    state = TuiState(policy=_make_policy(), pid=1234)
    state.mode = ViewMode.POLICY

    output = _render_to_string(state)
    assert "Policy Rules" in output
    assert "*.allowed.com" in output
    assert "*.blocked.com" in output
    assert "Allowed" in output
    assert "Blocked" in output


def test_render_policy_mode_new_marker():
    """Rules added via TUI should show [+NEW] marker."""
    policy = Policy(
        name="test",
        rules=(
            Rule(
                match="*.new.com",
                action=Action.ALERT,
                reason="Allowed interactively via TUI",
            ),
            Rule(match="*.old.com", action=Action.BLOCK, reason="Original rule"),
        ),
        defaults=PolicyDefaults(action=Action.ALERT),
    )
    state = TuiState(policy=policy, pid=1234)
    state.mode = ViewMode.POLICY

    output = _render_to_string(state)
    assert "+NEW" in output


def test_render_policy_mode_dirty_marker():
    state = TuiState(policy=_make_policy(), pid=1234)
    state.mode = ViewMode.POLICY
    state.policy_dirty = True

    output = _render_to_string(state)
    assert "modified" in output


def test_render_help_mode():
    state = TuiState(policy=_make_policy(), pid=1234)
    state.mode = ViewMode.HELP

    output = _render_to_string(state)
    assert "Key Bindings" in output
    assert "Navigate" in output or "Move cursor" in output
    assert "Quit" in output
    assert "Allow" in output or "allow" in output


def test_render_header_shows_pid_and_policy():
    state = TuiState(policy=_make_policy(), pid=5678)
    output = _render_to_string(state)
    assert "5678" in output
    assert "test-policy" in output


def test_render_header_shows_event_count():
    state = TuiState(policy=_make_policy(), pid=1234)
    for i in range(5):
        state.add_event(_make_event(remote_port=i + 1))

    output = _render_to_string(state)
    assert "Events: 5" in output


def test_render_footer_table_mode():
    state = TuiState(policy=_make_policy(), pid=1234)
    state.mode = ViewMode.TABLE
    output = _render_to_string(state)
    assert "Quit" in output
    assert "Navigate" in output or "↑/↓" in output


def test_render_footer_detail_mode():
    state = TuiState(policy=_make_policy(), pid=1234)
    state.add_event(_make_event())
    state.mode = ViewMode.DETAIL
    output = _render_to_string(state)
    assert "Back" in output
