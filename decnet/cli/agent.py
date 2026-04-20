from __future__ import annotations

import os
import pathlib as _pathlib
import sys as _sys
from typing import Optional

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def agent(
        port: int = typer.Option(8765, "--port", help="Port for the worker agent"),
        host: str = typer.Option("0.0.0.0", "--host", help="Bind address for the worker agent"),  # nosec B104
        agent_dir: Optional[str] = typer.Option(None, "--agent-dir", help="Worker cert bundle dir (default: ~/.decnet/agent, expanded under the running user's HOME — set this when running as sudo/root)"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
        no_forwarder: bool = typer.Option(False, "--no-forwarder", help="Do not auto-spawn the log forwarder alongside the agent"),
    ) -> None:
        """Run the DECNET SWARM worker agent (requires a cert bundle in ~/.decnet/agent/).

        By default, `decnet agent` auto-spawns `decnet forwarder` as a fully-
        detached sibling process so worker logs start flowing to the master
        without a second manual invocation. The forwarder survives agent
        restarts and crashes — if it dies on its own, restart it manually
        with `decnet forwarder --daemon …`. Pass --no-forwarder to skip.
        """
        from decnet.agent import server as _agent_server
        from decnet.env import DECNET_SWARM_MASTER_HOST, DECNET_INGEST_LOG_FILE
        from decnet.swarm import pki as _pki

        resolved_dir = _pathlib.Path(agent_dir) if agent_dir else _pki.DEFAULT_AGENT_DIR

        if daemon:
            log.info("agent daemonizing host=%s port=%d", host, port)
            _utils._daemonize()

        if not no_forwarder and DECNET_SWARM_MASTER_HOST:
            fw_argv = [
                _sys.executable, "-m", "decnet", "forwarder",
                "--master-host", DECNET_SWARM_MASTER_HOST,
                "--master-port", str(int(os.environ.get("DECNET_SWARM_SYSLOG_PORT", "6514"))),
                "--agent-dir", str(resolved_dir),
                "--log-file", str(DECNET_INGEST_LOG_FILE),
                "--daemon",
            ]
            try:
                pid = _utils._spawn_detached(fw_argv, _utils._pid_dir() / "forwarder.pid")
                log.info("agent auto-spawned forwarder pid=%d master=%s", pid, DECNET_SWARM_MASTER_HOST)
                console.print(f"[dim]Auto-spawned forwarder (pid {pid}) → {DECNET_SWARM_MASTER_HOST}.[/]")
            except Exception as e:  # noqa: BLE001
                log.warning("agent could not auto-spawn forwarder: %s", e)
                console.print(f"[yellow]forwarder auto-spawn skipped: {e}[/]")
        elif not no_forwarder:
            log.info("agent skipping forwarder auto-spawn (DECNET_SWARM_MASTER_HOST unset)")

        log.info("agent command invoked host=%s port=%d dir=%s", host, port, resolved_dir)
        console.print(f"[green]Starting DECNET worker agent on {host}:{port} (mTLS)...[/]")
        rc = _agent_server.run(host, port, agent_dir=resolved_dir)
        if rc != 0:
            raise typer.Exit(rc)
