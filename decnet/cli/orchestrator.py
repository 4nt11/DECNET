# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from typing import Optional

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
        llm: Optional[bool] = typer.Option(
            None, "--llm/--no-llm",
            help=(
                "Enable / disable LLM enrichment of user-class file "
                "bodies.  Default reads $DECNET_REALISM_LLM (any "
                "non-empty value enables; 'off' / unset disables)."
            ),
        ),
    ) -> None:
        """Inject synthetic life (inter-decky traffic + file ops + email) into the fleet."""
        import asyncio
        from decnet.orchestrator import orchestrator_worker
        from decnet.web.dependencies import repo

        if daemon:
            log.info("orchestrator daemonizing interval=%d", interval)
            _utils._daemonize()

        log.info(
            "orchestrator starting interval=%d llm=%s",
            interval, "default" if llm is None else ("on" if llm else "off"),
        )
        console.print(
            f"[bold cyan]Orchestrator starting[/] (interval: {interval}s)"
        )

        async def _run() -> None:
            await repo.initialize()
            await orchestrator_worker(repo, interval=interval, llm_enabled=llm)

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Orchestrator stopped.[/]")
