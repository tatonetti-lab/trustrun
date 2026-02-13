"""CLI command: trustrun server — start the web UI."""

from __future__ import annotations

import click
from rich.console import Console

from trustrun.config import TrustRunConfig

console = Console(stderr=True)


@click.command()
@click.option(
    "--port",
    type=int,
    default=None,
    help="Port to listen on (default: 8470).",
)
@click.pass_context
def server(ctx: click.Context, port: int | None) -> None:
    """Start the TrustRun web dashboard."""
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]Web dependencies not installed.[/red]\n"
            "Install with: pip install trustrun[web]"
        )
        raise SystemExit(1)

    config = TrustRunConfig.load()
    if port is not None:
        config.web_port = port

    console.print(
        f"[bold]TrustRun[/bold] web UI starting on "
        f"[cyan]http://{config.web_host}:{config.web_port}[/cyan]"
    )
    console.print("  [dim]Bound to 127.0.0.1 only (by design)[/dim]\n")

    import asyncio

    from trustrun.web.app import create_app

    async def _run() -> None:
        app = await create_app(config)
        server_config = uvicorn.Config(
            app,
            host=config.web_host,
            port=config.web_port,
            log_level="info",
        )
        srv = uvicorn.Server(server_config)
        await srv.serve()

    asyncio.run(_run())
