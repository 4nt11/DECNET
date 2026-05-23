# SPDX-License-Identifier: AGPL-3.0-or-later
"""``decnet canary`` — HTTP + DNS callback receiver for canary tokens.

Two entry points share this module:

* ``decnet canary`` — runs the worker process. Mirrors the shape of
  :mod:`decnet.cli.webhook`. Invoked by the ``decnet-canary.service``
  systemd unit so its argv must stay stable.
* ``decnet canary-install-toolchain`` — provisions the Node side of
  the fingerprint-canary obfuscator. Idempotent; safe to call from
  the API service unit's ``ExecStartPre``.

Not master-only — any host that hosts deckies can run its own
canary worker (the bus events stay local; the webhook worker on
each host fans them out to SIEMs independently per the design
in ``development/let-s-move-to-the-enumerated-pike.md``).
"""
from __future__ import annotations

import shutil
import subprocess  # nosec B404 — npm exec is the whole point of the toolchain installer
from pathlib import Path

import typer

from . import utils as _utils
from .utils import console, log

_TOOLCHAIN_TIMEOUT_S = 180


def register(app: typer.Typer) -> None:
    @app.command(name="canary")
    def canary_cmd(
        daemon: bool = typer.Option(
            False, "--daemon", "-d", help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Run the canary HTTP + DNS callback receiver."""
        import asyncio

        from decnet.canary.worker import run

        if daemon:
            log.info("canary daemonizing")
            _utils._daemonize()

        log.info("canary starting")
        console.print("[bold cyan]Canary callback receiver starting[/]")

        try:
            asyncio.run(run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Canary worker stopped.[/]")

    @app.command(name="canary-install-toolchain")
    def canary_install_toolchain(
        npm_bin: str = typer.Option(
            "npm", "--npm-bin", help="Path to the npm executable. Defaults to PATH lookup.",
        ),
    ) -> None:
        """Install the Node-side toolchain used by fingerprint canaries.

        Runs ``npm install --omit=dev`` under the installed ``decnet/canary/``
        directory so the obfuscator's helper script can ``require()``
        ``javascript-obfuscator`` at mint time. Requires Node >= 18.

        Idempotent: re-running on an already-installed tree is fast
        (npm short-circuits when ``node_modules/`` is up-to-date).
        """
        import decnet.canary as _canary_pkg
        canary_dir = Path(_canary_pkg.__file__).resolve().parent
        if not (canary_dir / "package.json").is_file():
            console.print(
                f"[red]canary package.json not found under {canary_dir}; "
                "wheel may be missing the JS toolchain payload.[/]"
            )
            raise typer.Exit(code=2)
        if shutil.which(npm_bin) is None:
            console.print(
                f"[red]npm executable {npm_bin!r} not found on PATH. "
                "Install Node >= 18 and re-run.[/]"
            )
            raise typer.Exit(code=2)
        console.print(
            f"[cyan]installing canary toolchain[/] in {canary_dir}",
        )
        try:
            proc = subprocess.run(  # nosec B603 — argv-form, no shell, fixed cwd, npm_bin checked above
                [npm_bin, "install", "--omit=dev", "--no-fund", "--no-audit"],
                cwd=str(canary_dir),
                capture_output=True, text=True,
                timeout=_TOOLCHAIN_TIMEOUT_S, check=False,
            )
        except subprocess.TimeoutExpired:
            console.print("[red]npm install timed out after 3 minutes[/]")
            raise typer.Exit(code=3) from None
        if proc.returncode != 0:
            console.print(
                f"[red]npm install failed rc={proc.returncode}[/]\n"
                f"{proc.stderr.strip()}"
            )
            raise typer.Exit(code=proc.returncode)
        console.print("[green]canary toolchain ready[/]")
