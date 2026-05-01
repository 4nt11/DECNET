from __future__ import annotations

import os
import signal
import subprocess  # nosec B404
import sys
from typing import Optional

import typer

from . import utils as _utils
from .gating import _require_master_mode
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def swarmctl(
        port: int = typer.Option(
            8770, "--port",
            envvar="DECNET_SWARMCTL_PORT",
            help="Port for the swarm controller. Defaults to [swarm] swarmctl-port from /etc/decnet/decnet.ini, else 8770.",
        ),
        host: str = typer.Option(
            "127.0.0.1", "--host",
            envvar="DECNET_SWARMCTL_HOST",
            help="Bind address for the swarm controller. Defaults to [swarm] swarmctl-host from /etc/decnet/decnet.ini, else 127.0.0.1.",
        ),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
        no_listener: bool = typer.Option(False, "--no-listener", help="Do not auto-spawn the syslog-TLS listener alongside swarmctl"),
        tls: bool = typer.Option(False, "--tls", help="Serve over HTTPS with mTLS (required for cross-host worker heartbeats)"),
        cert: Optional[str] = typer.Option(None, "--cert", help="BYOC: path to TLS server cert (PEM). Auto-issues from the DECNET CA if omitted."),
        key: Optional[str] = typer.Option(None, "--key", help="BYOC: path to TLS server private key (PEM)."),
        client_ca: Optional[str] = typer.Option(None, "--client-ca", help="CA bundle used to verify worker client certs. Defaults to the DECNET CA."),
    ) -> None:
        """Run the DECNET SWARM controller (master-side, separate process from `decnet api`).

        By default, `decnet swarmctl` auto-spawns `decnet listener` as a fully-
        detached sibling process so the master starts accepting forwarder
        connections on 6514 without a second manual invocation. The listener
        survives swarmctl restarts and crashes — if it dies on its own,
        restart it manually with `decnet listener --daemon …`. Pass
        --no-listener to skip.

        Pass ``--tls`` to serve over HTTPS with mutual-TLS enforcement. By
        default the server cert is auto-issued from the DECNET CA under
        ``~/.decnet/swarmctl/`` so enrolled workers (which already ship that
        CA's ``ca.crt``) trust it out of the box. BYOC via ``--cert``/``--key``
        if you need a publicly-trusted or externally-managed cert.
        """
        _require_master_mode("swarmctl")
        if daemon:
            log.info("swarmctl daemonizing host=%s port=%d", host, port)
            _utils._daemonize()

        if not no_listener:
            listener_host = os.environ.get("DECNET_LISTENER_HOST", "0.0.0.0")  # nosec B104
            listener_port = int(os.environ.get("DECNET_SWARM_SYSLOG_PORT", "6514"))
            lst_argv = [
                sys.executable, "-m", "decnet", "listener",
                "--host", listener_host,
                "--port", str(listener_port),
                "--daemon",
            ]
            try:
                pid = _utils._spawn_detached(lst_argv, _utils._pid_dir() / "listener.pid")
                log.info("swarmctl auto-spawned listener pid=%d bind=%s:%d",
                         pid, listener_host, listener_port)
                console.print(f"[dim]Auto-spawned listener (pid {pid}) on {listener_host}:{listener_port}.[/]")
            except Exception as e:  # noqa: BLE001
                log.warning("swarmctl could not auto-spawn listener: %s", e)
                console.print(f"[yellow]listener auto-spawn skipped: {e}[/]")

        log.info("swarmctl command invoked host=%s port=%d tls=%s", host, port, tls)
        scheme = "https" if tls else "http"
        console.print(f"[green]Starting DECNET SWARM controller on {scheme}://{host}:{port}...[/]")
        _cmd = [sys.executable, "-m", "uvicorn", "decnet.web.swarm_api:app",
                "--host", host, "--port", str(port)]
        if tls:
            from decnet.swarm import pki as _pki
            if cert and key:
                cert_path, key_path = cert, key
            elif cert or key:
                console.print("[red]--cert and --key must be provided together.[/]")
                raise typer.Exit(code=2)
            else:
                auto_cert, auto_key, _auto_ca = _pki.ensure_swarmctl_cert(host)
                cert_path, key_path = str(auto_cert), str(auto_key)
                console.print(f"[dim]Auto-issued swarmctl server cert → {cert_path}[/]")
            ca_path = client_ca or str(_pki.DEFAULT_CA_DIR / "ca.crt")
            _cmd += [
                "--ssl-keyfile", key_path,
                "--ssl-certfile", cert_path,
                "--ssl-ca-certs", ca_path,
                "--ssl-cert-reqs", "2",
            ]
        try:
            proc = subprocess.Popen(_cmd, start_new_session=True)  # nosec B603 B404
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
            console.print("[red]Failed to start swarmctl. Ensure 'uvicorn' is installed in the current environment.[/]")
