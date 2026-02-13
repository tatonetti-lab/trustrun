"""CLI command: trustrun run <cmd> — launch a process under monitoring."""

from __future__ import annotations

import signal
import sys
import threading

import click
from rich.console import Console

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
@click.argument("command", nargs=-1, required=True)
@click.pass_context
def run(ctx: click.Context, command: tuple[str, ...]) -> None:
    """Launch a command and monitor its network connections."""
    policy_path = ctx.obj.get("policy_path")
    policy = load_policy(policy_path) if policy_path else _default_policy()

    console.print(
        f"[bold]TrustRun[/bold] running [cyan]{' '.join(command)}[/cyan] "
        f"with policy [cyan]{policy.name}[/cyan]"
    )
    console.print(
        f"  Rules: {len(policy.rules)}, Default: {policy.defaults.action.value}\n"
    )

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

    manager.run(list(command))

    if manager.capture_sniffer_active:
        console.print("  DNS/SNI capture: [green]active[/green] (elevated)")
    else:
        console.print(
            "  DNS/SNI capture: [dim]unavailable[/dim] "
            "(run with sudo for hostname resolution)"
        )
    console.print()

    # Monitor loop in daemon thread, subprocess wait in main thread
    monitor_thread = threading.Thread(target=manager.monitor_loop, daemon=True)
    monitor_thread.start()

    def _signal_handler(signum: int, frame: object) -> None:
        console.print("\n[dim]Stopping...[/dim]")
        manager.terminate_subprocess()
        manager.stop()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Wait for the monitor thread to finish (it exits when subprocess exits)
    monitor_thread.join()

    _print_summary(manager)

    # Exit with subprocess return code
    rc = manager.get_subprocess_returncode()
    if session := manager.session:
        if session.violations:
            console.print(
                f"\n[yellow]⚠ {len(session.violations)} violation(s) detected[/yellow]"
            )
            sys.exit(rc if rc and rc != 0 else 1)
    sys.exit(rc or 0)


def _print_summary(manager: SessionManager) -> None:
    from rich.table import Table

    session = manager.session
    if session is None:
        return

    console.print("\n[bold]Session Summary[/bold]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()

    table.add_row("Session ID", session.id)
    table.add_row("Command", session.command)
    table.add_row("PID", str(session.pid))
    table.add_row("Policy", session.policy_name)
    table.add_row("Connections", str(len(session.events)))
    table.add_row("Violations", str(len(session.violations)))

    rc = manager.get_subprocess_returncode()
    table.add_row("Exit Code", str(rc) if rc is not None else "N/A")
    console.print(table)
