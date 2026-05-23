# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="profiler")
    def profiler_cmd(
        interval: int = typer.Option(30, "--interval", "-i", help="Seconds between profile rebuild cycles"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Run the attacker profiler as a standalone microservice."""
        import asyncio
        from decnet.profiler import attacker_profile_worker
        from decnet.web.dependencies import repo

        if daemon:
            log.info("profiler daemonizing interval=%d", interval)
            _utils._daemonize()

        log.info("profiler starting interval=%d", interval)
        console.print(f"[bold cyan]Profiler starting[/] (interval: {interval}s)")

        async def _run() -> None:
            await repo.initialize()
            await attacker_profile_worker(repo, interval=interval)

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Profiler stopped.[/]")
