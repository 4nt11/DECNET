from __future__ import annotations

import asyncio
import pathlib
import signal
from typing import Optional

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def listener(
        bind_host: str = typer.Option("0.0.0.0", "--host", help="Bind address for the master syslog-TLS listener"),  # nosec B104
        bind_port: int = typer.Option(6514, "--port", help="Listener TCP port (RFC 5425 default 6514)"),
        log_path: Optional[str] = typer.Option(None, "--log-path", help="RFC 5424 forensic sink (default: ./master.log)"),
        json_path: Optional[str] = typer.Option(None, "--json-path", help="Parsed-JSON ingest sink (default: ./master.json)"),
        ca_dir: Optional[str] = typer.Option(None, "--ca-dir", help="DECNET CA dir (default: ~/.decnet/ca)"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Run the master-side syslog-over-TLS listener (RFC 5425, mTLS)."""
        from decnet.swarm import pki
        from decnet.swarm.log_listener import ListenerConfig, run_listener

        resolved_ca_dir = pathlib.Path(ca_dir) if ca_dir else pki.DEFAULT_CA_DIR
        resolved_log = pathlib.Path(log_path) if log_path else pathlib.Path("master.log")
        resolved_json = pathlib.Path(json_path) if json_path else pathlib.Path("master.json")

        cfg = ListenerConfig(
            log_path=resolved_log, json_path=resolved_json,
            bind_host=bind_host, bind_port=bind_port, ca_dir=resolved_ca_dir,
        )

        if daemon:
            log.info("listener daemonizing host=%s port=%d", bind_host, bind_port)
            _utils._daemonize()

        log.info("listener command invoked host=%s port=%d", bind_host, bind_port)
        console.print(f"[green]Starting DECNET log listener on {bind_host}:{bind_port} (mTLS)...[/]")

        async def _main() -> None:
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                try:
                    loop.add_signal_handler(sig, stop.set)
                except (NotImplementedError, RuntimeError):  # pragma: no cover
                    pass
            await run_listener(cfg, stop_event=stop)

        try:
            asyncio.run(_main())
        except KeyboardInterrupt:
            pass
