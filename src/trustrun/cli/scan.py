"""CLI command: trustrun scan <directory> — static code analysis."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table

from trustrun.policy.loader import load_policy
from trustrun.scanner.engine import ScanEngine
from trustrun.scanner.models import Severity

console = Console(stderr=True)

_SEVERITY_COLORS = {
    Severity.INFO: "blue",
    Severity.WARNING: "yellow",
    Severity.CRITICAL: "red",
}


@click.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option(
    "--exclude",
    "-e",
    multiple=True,
    help="Patterns to exclude from scan.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    directory: str,
    exclude: tuple[str, ...],
) -> None:
    """Scan source code for hardcoded endpoints and secrets."""
    policy_path = ctx.obj.get("policy_path")
    policy = load_policy(policy_path) if policy_path else None

    policy_name = policy.name if policy else "none"
    console.print(
        f"[bold]TrustRun[/bold] scanning [cyan]{directory}[/cyan] "
        f"with policy [cyan]{policy_name}[/cyan]\n"
    )

    engine = ScanEngine(policy=policy, exclude_patterns=list(exclude))
    result = engine.scan(directory)

    if not result.findings:
        console.print("[green]No findings.[/green]")
        _print_summary(result)
        return

    # Sort by severity (critical first), then file, then line
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.WARNING: 1,
        Severity.INFO: 2,
    }
    result.findings.sort(
        key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line)
    )

    table = Table(title="Findings", show_lines=False)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right")
    table.add_column("Pattern")
    table.add_column("Match", max_width=50)

    for finding in result.findings:
        color = _SEVERITY_COLORS.get(finding.severity, "white")
        table.add_row(
            f"[{color}]{finding.severity.value}[/{color}]",
            _shorten_path(finding.file_path, directory),
            str(finding.line),
            finding.pattern_name,
            finding.matched_text[:50],
        )

    console.print(table)
    _print_summary(result)

    critical_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    if critical_count > 0:
        console.print(f"\n[red]{critical_count} critical finding(s)[/red]")
        sys.exit(1)


def _print_summary(result) -> None:
    console.print(
        f"\nScanned {result.files_scanned} files "
        f"({result.files_skipped} skipped) "
        f"in {result.duration:.2f}s"
    )
    console.print(f"Total findings: {len(result.findings)}")


def _shorten_path(file_path: str, base_dir: str) -> str:
    """Shorten file path relative to scan directory."""
    if file_path.startswith(base_dir):
        return file_path[len(base_dir) :].lstrip("/")
    return file_path
