# SPDX-License-Identifier: AGPL-3.0-or-later
"""``decnet supervise <group>`` — host a co-resident group of workers in one
process, paying the import floor (and the DB connection pool) once instead of
once per worker. See ``development/RELEASE-1.1.md``.

Each worker keeps its own restart loop (see :mod:`decnet.supervisor`), so this
trades per-worker systemd granularity for RAM — a worker can always be pulled
back out to its own ``decnet <worker>`` unit by removing it from the group spec
below; nothing about the worker's own code changes.
"""
from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log

# Groups are intentionally a small static registry, not config — the membership
# is an architectural decision, not an operator knob.
_GROUPS = ("batch",)


async def _build_specs(group: str):
    """Return ``[(name, factory), ...]`` for *group*, lazy-importing only the
    workers it hosts and initializing the shared ``repo`` once.

    Factories return a fresh coroutine each call so :func:`supervise` can restart
    them. Intervals match the standalone units' defaults.
    # ponytail: defaults hardcoded to match the per-worker units; add CLI knobs
    # only if an operator actually needs to retune a consolidated group.
    """
    if group == "batch":
        from decnet.fleet.reconciler_worker import fleet_reconciler_worker
        from decnet.intel.worker import run_intel_loop
        from decnet.mutator import run_watch_loop
        from decnet.orchestrator import orchestrator_worker
        from decnet.web.dependencies import repo

        await repo.initialize()  # shared by every batch worker → one DB pool
        return [
            ("reconcile", lambda: fleet_reconciler_worker(repo, interval=30)),
            ("enrich", lambda: run_intel_loop(repo, poll_interval_secs=60.0, ttl_hours=24)),
            ("orchestrate", lambda: orchestrator_worker(repo, interval=60, llm_enabled=None)),
            ("mutate", lambda: run_watch_loop(repo)),
        ]
    raise ValueError(f"unknown supervise group: {group}")


def register(app: typer.Typer) -> None:
    @app.command(name="supervise")
    def supervise_cmd(
        group: str = typer.Argument(
            ..., help=f"Worker group to host. One of: {', '.join(_GROUPS)}"
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d", help="Detach to background as a daemon process"
        ),
    ) -> None:
        """Host a co-resident worker group in one process (shared import floor + DB pool)."""
        import asyncio

        from decnet.supervisor import run_group

        if group not in _GROUPS:
            console.print(
                f"[red]unknown group {group!r}; known groups: {', '.join(_GROUPS)}[/]"
            )
            raise typer.Exit(2)

        if daemon:
            log.info("supervise %s daemonizing", group)
            _utils._daemonize()

        log.info("supervise group=%s starting", group)
        console.print(f"[bold cyan]Supervisor starting[/] group={group}")

        async def _run() -> None:
            specs = await _build_specs(group)
            await run_group(specs)

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Supervisor stopped.[/]")
