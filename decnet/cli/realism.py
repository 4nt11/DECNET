# SPDX-License-Identifier: AGPL-3.0-or-later
"""``decnet realism ...`` — content-engine maintenance commands.

After stage 5 of the realism migration, this is the only remaining
CLI surface from the realism library / former emailgen.  ``decnet
realism run`` does not exist (the orchestrator runs the unified
worker via ``decnet orchestrate``); the only sub-command is
``import-personas``, which validates + installs the host-wide global
persona pool consumed by fleet (MACVLAN/IPVLAN) and SWARM-shard
deckies.

Topology personas live on ``Topology.email_personas`` and are
managed via the dashboard or the topology API; this command does
not touch them.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from .gating import _require_master_mode
from .utils import console, log


def register(app: typer.Typer) -> None:
    realism_app = typer.Typer(
        name="realism",
        help=(
            "Maintain the realism content engine (persona pool import, "
            "future content-class tuning)."
        ),
    )
    app.add_typer(realism_app, name="realism")

    @realism_app.command("import-personas")
    def realism_import_personas(
        path: Path = typer.Argument(
            ..., exists=True, file_okay=True, dir_okay=False, readable=True,
            help="JSON file containing a list of EmailPersona objects",
        ),
        output: Optional[Path] = typer.Option(
            None, "--output", "-o",
            help=(
                "Override the destination path.  Defaults to the canonical "
                "global pool (DECNET_REALISM_PERSONAS, /etc/decnet/"
                "email_personas.json, or ~/.decnet/email_personas.json)."
            ),
        ),
    ) -> None:
        """Validate + install a personas JSON file as the global pool.

        Use this when deploying with IMAP/POP3 services on fleet
        (MACVLAN/IPVLAN) or SWARM-shard mail deckies — those have no
        parent topology row, so they read this host-wide list.
        MazeNET topology mail deckies use ``Topology.email_personas``
        instead and this command does not touch them.
        """
        _require_master_mode("realism import-personas")
        from decnet.realism import personas_pool as global_pool
        from decnet.realism.personas import parse_personas

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Cannot read {path}:[/] {exc}")
            raise typer.Exit(code=1) from exc

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
        dest.write_text(
            json.dumps(
                [p.model_dump(exclude_none=False) for p in personas],
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        global_pool.reset_cache()
        console.print(
            f"[green]Imported {len(personas)} personas to[/] {dest}"
        )
        if path != dest:
            log.info("realism import-personas src=%s dest=%s", path, dest)
