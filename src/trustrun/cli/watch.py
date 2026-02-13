"""CLI command: trustrun watch <PID> — attach to a running process."""

from __future__ import annotations

import signal
import sys

import click
from rich.console import Console
from rich.table import Table

from trustrun.policy.loader import load_policy
from trustrun.policy.models import Action, Policy, PolicyDefaults
from trustrun.session.manager import SessionManager
from trustrun.session.models import ConnectionEvent, Violation

console = Console(stderr=True)


def _default_policy() -> Policy:
    return Policy(
        name="default-alert-all",
        rules=(),
        defaults=PolicyDefaults(action=Action.ALERT),
        description="Default policy: alert on all connections",
    )


@click.command()
@click.argument("pid", type=int)
@click.pass_context
def watch(ctx: click.Context, pid: int) -> None:
    """Monitor network connections of a running process."""
    policy_path = ctx.obj.get("policy_path")
    policy = load_policy(policy_path) if policy_path else _default_policy()

    console.print(
        f"[bold]TrustRun[/bold] watching PID {pid} with policy "
        f"[cyan]{policy.name}[/cyan]"
    )
    console.print(
        f"  Rules: {len(policy.rules)}, Default: {policy.defaults.action.value}"
    )
    console.print("  Press Ctrl+C to stop.\n")

    def on_event(event: ConnectionEvent) -> None:
        dest = event.hostname or event.remote_ip
        org_suffix = f" ({event.org})" if event.org else ""
        console.print(
            f"  [dim]{event.process_name}[/dim] → "
            f"[blue]{dest}:{event.remote_port}[/blue]{org_suffix} "
            f"({event.protocol})"
        )

    def on_violation(violation: Violation) -> None:
        ev = violation.event
        dest = ev.hostname or ev.remote_ip
        org_suffix = f" ({ev.org})" if ev.org else ""
        color = "red" if violation.action in ("block", "kill") else "yellow"
        act = violation.action.upper()
        console.print(
            f"  [{color}]⚠ VIOLATION[/{color}] [{color}]{act}[/{color}] "
            f"{dest}:{ev.remote_port}{org_suffix} — "
            f"{violation.reason}"
        )

    manager = SessionManager(
        policy=policy,
        on_event=on_event,
        on_violation=on_violation,
    )

    manager.watch(pid)

    if manager.capture_sniffer_active:
        console.print("  DNS/SNI capture: [green]active[/green] (elevated)")
    else:
        console.print(
            "  DNS/SNI capture: [dim]unavailable[/dim] "
            "(run with sudo for hostname resolution)"
        )

    def _signal_handler(signum: int, frame: object) -> None:
        console.print("\n[dim]Stopping...[/dim]")
        manager.stop()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        manager.monitor_loop()
    except KeyboardInterrupt:
        manager.stop()

    _print_summary(manager)


def _print_summary(manager: SessionManager) -> None:
    session = manager.session
    if session is None:
        return

    console.print("\n[bold]Session Summary[/bold]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()

    table.add_row("Session ID", session.id)
    table.add_row("PID", str(session.pid))
    table.add_row("Policy", session.policy_name)
    table.add_row("Connections", str(len(session.events)))
    table.add_row("Violations", str(len(session.violations)))
    table.add_row("Status", session.status.value)
    console.print(table)

    if session.violations:
        console.print(
            f"\n[yellow]⚠ {len(session.violations)} violation(s) detected[/yellow]"
        )
        sys.exit(1)
