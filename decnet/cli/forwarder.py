from __future__ import annotations

import asyncio
import pathlib
import signal
from typing import Optional

import typer

from decnet.env import DECNET_INGEST_LOG_FILE

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def forwarder(
        master_host: Optional[str] = typer.Option(None, "--master-host", help="Master listener hostname/IP (default: $DECNET_SWARM_MASTER_HOST)"),
        master_port: int = typer.Option(6514, "--master-port", help="Master listener TCP port (RFC 5425 default 6514)"),
        log_file: Optional[str] = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Local RFC 5424 file to tail and forward"),
        agent_dir: Optional[str] = typer.Option(None, "--agent-dir", help="Worker cert bundle dir (default: ~/.decnet/agent)"),
        state_db: Optional[str] = typer.Option(None, "--state-db", help="Forwarder offset SQLite path (default: <agent_dir>/forwarder.db)"),
        poll_interval: float = typer.Option(0.5, "--poll-interval", help="Seconds between log file stat checks"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Run the worker-side syslog-over-TLS forwarder (RFC 5425, mTLS to master:6514)."""
        from decnet.env import DECNET_SWARM_MASTER_HOST
        from decnet.swarm import pki
        from decnet.swarm.log_forwarder import ForwarderConfig, run_forwarder

        resolved_host = master_host or DECNET_SWARM_MASTER_HOST
        if not resolved_host:
            console.print("[red]--master-host is required (or set DECNET_SWARM_MASTER_HOST).[/]")
            raise typer.Exit(2)

        resolved_agent_dir = pathlib.Path(agent_dir) if agent_dir else pki.DEFAULT_AGENT_DIR
        if not (resolved_agent_dir / "worker.crt").exists():
            console.print(f"[red]No worker cert bundle at {resolved_agent_dir} — enroll from the master first.[/]")
            raise typer.Exit(2)

        if not log_file:
            console.print("[red]--log-file is required.[/]")
            raise typer.Exit(2)

        cfg = ForwarderConfig(
            log_path=pathlib.Path(log_file),
            master_host=resolved_host,
            master_port=master_port,
            agent_dir=resolved_agent_dir,
            state_db=pathlib.Path(state_db) if state_db else None,
        )

        if daemon:
            log.info("forwarder daemonizing master=%s:%d log=%s", resolved_host, master_port, log_file)
            _utils._daemonize()

        log.info("forwarder command invoked master=%s:%d log=%s", resolved_host, master_port, log_file)
        console.print(f"[green]Starting DECNET forwarder → {resolved_host}:{master_port} (mTLS)...[/]")

        async def _main() -> None:
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                try:
                    loop.add_signal_handler(sig, stop.set)
                except (NotImplementedError, RuntimeError):  # pragma: no cover
                    pass
            await run_forwarder(cfg, poll_interval=poll_interval, stop_event=stop)

        try:
            asyncio.run(_main())
        except KeyboardInterrupt:
            pass
