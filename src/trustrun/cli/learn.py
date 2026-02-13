"""CLI command: trustrun learn — auto-learn mode to generate policies."""

from __future__ import annotations

import signal
import sys
from pathlib import Path

import click
from rich.console import Console

from trustrun.capture.psutil_ import PsutilCapture
from trustrun.policy.learner import PolicyLearner
from trustrun.policy.models import Action

console = Console(stderr=True)


@click.command()
@click.argument("pid", type=int)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output YAML file path.",
)
@click.option(
    "--name",
    default="learned-policy",
    help="Name for the generated policy.",
)
@click.option(
    "--default-action",
    type=click.Choice(["alert", "block", "kill"]),
    default="block",
    help="Default action for unmatched connections.",
)
@click.pass_context
def learn(
    ctx: click.Context,
    pid: int,
    output: str | None,
    name: str,
    default_action: str,
) -> None:
    """Observe a process and generate a policy from its network activity."""
    console.print(f"[bold]TrustRun[/bold] learning from PID {pid}")
    console.print("  Press Ctrl+C to stop and generate policy.\n")

    learner = PolicyLearner(name=name)
    capture = PsutilCapture()
    capture.start(pid, include_children=True)

    import threading

    stop_event = threading.Event()

    def _signal_handler(signum: int, frame: object) -> None:
        console.print("\n[dim]Stopping observation...[/dim]")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    while not stop_event.is_set():
        if not capture.is_running:
            break

        events = capture.poll()
        for event in events:
            learner.observe(event)
            dest = event.hostname or event.remote_ip
            console.print(f"  [dim]Learned:[/dim] {dest}:{event.remote_port}")

        stop_event.wait(timeout=0.5)

    capture.stop()

    if learner.endpoint_count == 0:
        console.print("[yellow]No endpoints observed.[/yellow]")
        sys.exit(0)

    action = Action(default_action)
    yaml_str = learner.export_yaml(default_action=action)

    console.print(
        f"\n[bold]Generated policy:[/bold] {learner.endpoint_count} endpoints"
    )
    console.print(f"[dim]{yaml_str}[/dim]")

    if output:
        Path(output).write_text(yaml_str, encoding="utf-8")
        console.print(f"\n[green]Policy written to {output}[/green]")
