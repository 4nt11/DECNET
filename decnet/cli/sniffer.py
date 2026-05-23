# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import typer

from decnet.env import DECNET_INGEST_LOG_FILE

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="sniffer")
    def sniffer_cmd(
        log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path to write captured syslog + JSON records"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Run the network sniffer as a standalone microservice."""
        import asyncio
        from decnet.sniffer import sniffer_worker

        if daemon:
            log.info("sniffer daemonizing log_file=%s", log_file)
            _utils._daemonize()

        log.info("sniffer starting log_file=%s", log_file)
        console.print(f"[bold cyan]Sniffer starting[/] → {log_file}")

        try:
            asyncio.run(sniffer_worker(log_file))
        except KeyboardInterrupt:
            console.print("\n[yellow]Sniffer stopped.[/]")
