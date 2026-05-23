# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="webhook")
    def webhook_cmd(
        daemon: bool = typer.Option(
            False, "--daemon", "-d", help="Detach to background as a daemon process"
        ),
    ) -> None:
        """Run the webhook dispatcher — bus consumer → external HTTP egress."""
        import asyncio
        from decnet.web.dependencies import repo
        from decnet.webhook import webhook_worker

        if daemon:
            log.info("webhook daemonizing")
            _utils._daemonize()

        log.info("webhook starting")
        console.print("[bold cyan]Webhook dispatcher starting[/]")

        async def _run() -> None:
            await repo.initialize()
            await webhook_worker(repo)

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Webhook worker stopped.[/]")
