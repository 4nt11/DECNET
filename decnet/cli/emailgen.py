"""``decnet emailgen`` — second orchestrator worker.

Sibling of :mod:`decnet.cli.orchestrator`.  Two distinct CLI entrypoints
match the "workers are independent, never coupled" principle: a wedged
ollama call in emailgen does not stall the SSH-flavoured orchestrator,
and systemd supervises each loop separately.
"""
from __future__ import annotations

import os

import typer

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="emailgen")
    def emailgen_cmd(
        interval: int = typer.Option(
            300, "--interval", "-i",
            help="Seconds between fake-email generation ticks (default 5m)",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
        model: str = typer.Option(
            "", "--model", "-m",
            help="Ollama model override (defaults to $DECNET_EMAILGEN_MODEL "
                 "or 'llama3.1')",
        ),
    ) -> None:
        """Drip fake corporate emails into running IMAP/POP3 mail deckies."""
        import asyncio
        from decnet.orchestrator.emailgen import emailgen_worker
        from decnet.web.dependencies import repo

        if daemon:
            log.info("emailgen daemonizing interval=%d", interval)
            _utils._daemonize()

        # Honour the env var when the flag was left empty so systemd unit
        # files can configure the model centrally without per-host CLI
        # tweaks.  Empty -> let the worker apply its own default.
        resolved_model = model or os.environ.get("DECNET_EMAILGEN_MODEL", "")
        log.info(
            "emailgen starting interval=%d model=%s",
            interval, resolved_model or "default",
        )
        console.print(
            f"[bold cyan]Emailgen starting[/] (interval: {interval}s"
            f"{', model: ' + resolved_model if resolved_model else ''})"
        )

        async def _run() -> None:
            await repo.initialize()
            await emailgen_worker(
                repo, interval=interval, model=resolved_model or None,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Emailgen stopped.[/]")
