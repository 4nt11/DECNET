from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="orchestrate")
    def orchestrate_cmd(
        interval: int = typer.Option(
            60, "--interval", "-i",
            help="Seconds between synthetic activity ticks",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Inject synthetic life (inter-decky traffic + file ops) into the fleet."""
        import asyncio
        from decnet.orchestrator import orchestrator_worker
        from decnet.web.dependencies import repo

        if daemon:
            log.info("orchestrator daemonizing interval=%d", interval)
            _utils._daemonize()

        log.info("orchestrator starting interval=%d", interval)
        console.print(
            f"[bold cyan]Orchestrator starting[/] (interval: {interval}s)"
        )

        async def _run() -> None:
            await repo.initialize()
            await orchestrator_worker(repo, interval=interval)

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Orchestrator stopped.[/]")
