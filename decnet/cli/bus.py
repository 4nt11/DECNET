# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="bus")
    def bus_cmd(
        socket_path: str = typer.Option(
            None, "--socket", "-s",
            help="UNIX socket path (defaults to DECNET_BUS_SOCKET env var, "
                 "then /run/decnet/bus.sock, then ~/.decnet/bus.sock).",
        ),
        group: str = typer.Option(
            "decnet", "--group", "-g",
            help="POSIX group to chown the socket to (falls back to process "
                 "group if the named group does not exist).",
        ),
        heartbeat: int = typer.Option(
            10, "--heartbeat", "-H",
            help="Seconds between system.bus.health heartbeat events.",
        ),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process."),
    ) -> None:
        """Run the DECNET ServiceBus worker (host-local UNIX-socket pub/sub)."""
        import asyncio
        from decnet.bus.factory import _default_socket_path
        from decnet.bus.worker import bus_worker

        resolved = socket_path or _default_socket_path()

        if daemon:
            log.info("bus daemonizing socket=%s", resolved)
            _utils._daemonize()

        log.info("bus starting socket=%s group=%s heartbeat=%ds", resolved, group, heartbeat)
        console.print(f"[bold cyan]Bus starting[/] (socket: {resolved}, heartbeat: {heartbeat}s)")

        try:
            asyncio.run(bus_worker(resolved, group=group, heartbeat_interval=heartbeat))
        except KeyboardInterrupt:
            console.print("\n[yellow]Bus stopped.[/]")
