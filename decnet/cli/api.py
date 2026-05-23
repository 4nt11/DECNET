# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import signal
import subprocess  # nosec B404
import sys

import typer

from decnet.env import DECNET_API_HOST, DECNET_API_PORT, DECNET_INGEST_LOG_FILE

from . import utils as _utils
from .gating import _require_master_mode
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def api(
        port: int = typer.Option(DECNET_API_PORT, "--port", help="Port for the backend API"),
        host: str = typer.Option(DECNET_API_HOST, "--host", help="Host IP for the backend API"),
        log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Path to the DECNET log file to monitor"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
        workers: int = typer.Option(1, "--workers", "-w", min=1, help="Number of uvicorn worker processes"),
    ) -> None:
        """Run the DECNET API and Web Dashboard in standalone mode."""
        _require_master_mode("api")
        if daemon:
            log.info("API daemonizing host=%s port=%d workers=%d", host, port, workers)
            _utils._daemonize()

        log.info("API command invoked host=%s port=%d workers=%d", host, port, workers)
        console.print(f"[green]Starting DECNET API on {host}:{port} (workers={workers})...[/]")
        _env: dict[str, str] = os.environ.copy()
        _env["DECNET_INGEST_LOG_FILE"] = str(log_file)
        _cmd = [sys.executable, "-m", "uvicorn", "decnet.web.api:app",
                "--host", host, "--port", str(port), "--workers", str(workers)]
        try:
            proc = subprocess.Popen(_cmd, env=_env, start_new_session=True)  # nosec B603 B404
            try:
                proc.wait()
            except KeyboardInterrupt:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                except ProcessLookupError:
                    pass
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start API. Ensure 'uvicorn' is installed in the current environment.[/]")
