"""CLI entry point — Click group with global options."""

from __future__ import annotations

import logging

import click

from trustrun import __version__


@click.group()
@click.version_option(version=__version__, prog_name="trustrun")
@click.option(
    "--policy",
    "-p",
    type=click.Path(exists=True),
    help="Path to a YAML policy file.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.pass_context
def main(ctx: click.Context, policy: str | None, verbose: bool) -> None:
    """TrustRun — network trust verification for HIPAA-sensitive environments."""
    ctx.ensure_object(dict)
    ctx.obj["policy_path"] = policy
    ctx.obj["verbose"] = verbose

    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _register_commands() -> None:
    from trustrun.cli.learn import learn  # noqa: F811
    from trustrun.cli.run import run  # noqa: F811
    from trustrun.cli.scan import scan  # noqa: F811
    from trustrun.cli.server import server  # noqa: F811
    from trustrun.cli.watch import watch  # noqa: F811

    main.add_command(watch)
    main.add_command(run)
    main.add_command(scan)
    main.add_command(server)
    main.add_command(learn)


_register_commands()
