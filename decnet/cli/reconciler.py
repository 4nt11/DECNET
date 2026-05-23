# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="reconcile")
    def reconcile_cmd(
        once: bool = typer.Option(
            False, "--once",
            help="Run a single reconcile pass and exit (no daemon loop).",
        ),
        interval: int = typer.Option(
            30, "--interval", "-i",
            help="Seconds between reconcile passes (ignored with --once).",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process (long-lived only).",
        ),
    ) -> None:
        """Converge fleet state across decnet-state.json, the DB, and docker."""
        import asyncio
        from decnet.web.dependencies import repo

        if once:
            from decnet.fleet.reconciler import reconcile_once

            async def _one() -> None:
                await repo.initialize()
                counts = await reconcile_once(repo)
                console.print(
                    f"[bold cyan]reconcile:[/] "
                    f"inserted={counts['inserted']} "
                    f"deleted={counts['deleted']} "
                    f"state_updated={counts['state_updated']}"
                )
            asyncio.run(_one())
            return

        from decnet.fleet.reconciler_worker import fleet_reconciler_worker

        if daemon:
            log.info("reconciler daemonizing interval=%d", interval)
            _utils._daemonize()

        log.info("reconciler starting interval=%d", interval)
        console.print(
            f"[bold cyan]Fleet reconciler starting[/] (interval: {interval}s)"
        )

        async def _run() -> None:
            await repo.initialize()
            await fleet_reconciler_worker(repo, interval=interval)

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Reconciler stopped.[/]")
