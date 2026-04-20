from __future__ import annotations

import pathlib as _pathlib
from typing import Optional

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def updater(
        port: int = typer.Option(8766, "--port", help="Port for the self-updater daemon"),
        host: str = typer.Option("0.0.0.0", "--host", help="Bind address for the updater"),  # nosec B104
        updater_dir: Optional[str] = typer.Option(None, "--updater-dir", help="Updater cert bundle dir (default: ~/.decnet/updater)"),
        install_dir: Optional[str] = typer.Option(None, "--install-dir", help="Release install root (default: /opt/decnet)"),
        agent_dir: Optional[str] = typer.Option(None, "--agent-dir", help="Worker agent cert bundle (for local /health probes; default: ~/.decnet/agent)"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Run the DECNET self-updater (requires a bundle in ~/.decnet/updater/)."""
        from decnet.swarm import pki as _pki
        from decnet.updater import server as _upd_server

        resolved_updater = _pathlib.Path(updater_dir) if updater_dir else _upd_server.DEFAULT_UPDATER_DIR
        resolved_install = _pathlib.Path(install_dir) if install_dir else _pathlib.Path("/opt/decnet")
        resolved_agent = _pathlib.Path(agent_dir) if agent_dir else _pki.DEFAULT_AGENT_DIR

        if daemon:
            log.info("updater daemonizing host=%s port=%d", host, port)
            _utils._daemonize()

        log.info(
            "updater command invoked host=%s port=%d updater_dir=%s install_dir=%s",
            host, port, resolved_updater, resolved_install,
        )
        console.print(f"[green]Starting DECNET self-updater on {host}:{port} (mTLS)...[/]")
        rc = _upd_server.run(
            host, port,
            updater_dir=resolved_updater,
            install_dir=resolved_install,
            agent_dir=resolved_agent,
        )
        if rc != 0:
            raise typer.Exit(rc)
