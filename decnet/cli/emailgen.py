"""``decnet emailgen ...`` — orchestrator-sibling email generator.

Sub-commands:

* ``decnet emailgen run``               — start the long-running worker
  (default when invoked with no sub-command, so the historical
  ``decnet emailgen`` invocation still works).
* ``decnet emailgen import-personas``   — validate a JSON file and
  install it as the host-wide global persona pool consumed by fleet
  (MACVLAN/IPVLAN) and SWARM-shard mail deckies.

The worker itself stays in :mod:`decnet.orchestrator.emailgen.worker`;
this module only owns the CLI surface.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import typer

from . import utils as _utils
from .gating import _require_master_mode
from .utils import console, log


def register(app: typer.Typer) -> None:
    emailgen_app = typer.Typer(
        name="emailgen",
        help=(
            "Drip persona-driven fake corporate email into running "
            "IMAP/POP3 mail deckies."
        ),
        invoke_without_command=True,
        no_args_is_help=False,
    )
    app.add_typer(emailgen_app, name="emailgen")

    @emailgen_app.callback()
    def _default(ctx: typer.Context) -> None:
        # Calling ``decnet emailgen`` with no sub-command defers to ``run``
        # so the documented (and shipped) invocation stays valid.
        if ctx.invoked_subcommand is None:
            ctx.invoke(emailgen_run)

    @emailgen_app.command("run")
    def emailgen_run(
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
        """Start the long-running email-generation worker."""
        # Defence-in-depth: the registration-time gate already hides
        # ``emailgen`` from Typer when DECNET_MODE=agent, but a direct
        # callable import would bypass that — block here too.
        _require_master_mode("emailgen run")
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

    @emailgen_app.command("import-personas")
    def emailgen_import_personas(
        path: Path = typer.Argument(
            ..., exists=True, file_okay=True, dir_okay=False, readable=True,
            help="JSON file containing a list of EmailPersona objects",
        ),
        output: Optional[Path] = typer.Option(
            None, "--output", "-o",
            help=(
                "Override the destination path. Defaults to the canonical "
                "global pool (DECNET_EMAILGEN_PERSONAS, /etc/decnet/"
                "email_personas.json, or ~/.decnet/email_personas.json)."
            ),
        ),
    ) -> None:
        """Validate + install a personas JSON file as the global pool.

        Use this when deploying with IMAP/POP3 services on fleet
        (MACVLAN/IPVLAN) or SWARM-shard mail deckies — those have no
        parent topology row, so they read this host-wide list.  MazeNET
        topology mail deckies use ``Topology.email_personas`` instead and
        this command does not touch them.
        """
        _require_master_mode("emailgen import-personas")
        from decnet.orchestrator.emailgen import global_pool
        from decnet.orchestrator.emailgen.personas import parse_personas

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Cannot read {path}:[/] {exc}")
            raise typer.Exit(code=1) from exc

        # Validate by parsing — we want operators to find out about
        # broken personas at import time, not at the next worker tick.
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            console.print(f"[red]Invalid JSON in {path}:[/] {exc}")
            raise typer.Exit(code=1) from exc
        if not isinstance(payload, list):
            console.print(
                f"[red]{path} must contain a JSON list of personas, "
                f"got {type(payload).__name__}[/]"
            )
            raise typer.Exit(code=1)

        personas = parse_personas(payload)
        if not personas:
            console.print(
                f"[red]No valid personas in {path}.[/] "
                "Check the schema (name, email, role, tone, mannerisms)."
            )
            raise typer.Exit(code=1)
        if len(personas) < 2:
            console.print(
                f"[yellow]Warning: only {len(personas)} valid persona(s) — "
                "the worker requires at least 2 to send mail; importing "
                "anyway in case more are added later.[/]"
            )

        dest = output or global_pool.resolve_path()
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Re-serialise from the parsed-and-validated objects rather than
        # copying the source file: drops invalid entries, normalises
        # whitespace, and gives operators a single canonical layout to
        # eyeball after the import.
        dest.write_text(
            json.dumps(
                [p.model_dump(exclude_none=False) for p in personas],
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        # Cache invalidation happens automatically on next ``load()``
        # via the mtime check, but reset the in-process cache too in
        # case the CLI process is the same as the worker (uncommon but
        # cheap to be correct about).
        global_pool.reset_cache()
        console.print(
            f"[green]Imported {len(personas)} personas to[/] {dest}"
        )
        if path != dest:
            log.info("emailgen import-personas src=%s dest=%s", path, dest)
