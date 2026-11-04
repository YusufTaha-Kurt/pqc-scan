"""Command-line interface for pqc-scan."""

from __future__ import annotations

from typing import Annotated

import typer

from pqc_scan import __version__

AUTHORIZATION_WARNING = (
    "Only scan systems you own or have written permission to test. "
    "pqc-scan performs passive discovery: it reads handshake metadata, "
    "never logs in, and never attempts exploitation."
)

app = typer.Typer(
    name="pqc-scan",
    help=(
        "Find quantum-vulnerable cryptography in endpoints and code, "
        f"and plan your post-quantum migration.\n\n{AUTHORIZATION_WARNING}"
    ),
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"pqc-scan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """pqc-scan root command."""
