"""``decnet canary`` — HTTP + DNS callback receiver for canary tokens.

Worker process. Mirrors the shape of :mod:`decnet.cli.webhook`: a
``@app.command(name="canary")`` Typer entry point that delegates to
:func:`decnet.canary.worker.run`.

Not master-only — any host that hosts deckies can run its own
canary worker (the bus events stay local; the webhook worker on
each host fans them out to SIEMs independently per the design
in ``development/let-s-move-to-the-enumerated-pike.md``).
"""
from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="canary")
    def canary_cmd(
        daemon: bool = typer.Option(
            False, "--daemon", "-d", help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Run the canary HTTP + DNS callback receiver."""
        import asyncio

        from decnet.canary.worker import run

        if daemon:
            log.info("canary daemonizing")
            _utils._daemonize()

        log.info("canary starting")
        console.print("[bold cyan]Canary callback receiver starting[/]")

        try:
            asyncio.run(run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Canary worker stopped.[/]")
