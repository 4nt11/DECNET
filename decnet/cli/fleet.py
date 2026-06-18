# SPDX-License-Identifier: AGPL-3.0-or-later
"""``decnet fleet <name>`` — prefork supervisor (DECNET 1.2).

Imports the shared base floor ONCE in the master, then forks one child process
per worker (see :mod:`decnet.prefork`). Children share the floor via copy-on-write
(measured ~71 MB shared / ~1 MB private per idle child on CPython 3.14) while
keeping their OWN process and GIL — unlike ``decnet supervise``, which co-hosts
workers as asyncio tasks in one shared-GIL process.

Use ``fleet`` for workers that must stay process-isolated (heavy resident state,
sustained CPU) but shouldn't each re-import the world; use ``supervise`` for cheap
co-resident IO workers.

CONSOLIDATION COSTS (same shape as ``supervise``):
  * Forked children inherit the master's privileges — a fleet's systemd unit
    carries the UNION of its members' caps. So group by privilege profile, not
    convenience. The ``heavy`` fleet is DB-only (no docker socket, no raw net).
  * To share via CoW the master pre-imports each worker's module BEFORE forking,
    so its RSS is large — but that RSS is the shared floor, not per-child cost.
"""
from __future__ import annotations

import typer

from . import utils as _utils
from .utils import console, log

_FLEETS = ("heavy",)


def _build_fleet(name: str) -> dict:
    """Return ``{worker_name: entry_thunk}`` for *name*.

    Imports happen here, in the MASTER, before :func:`run_fleet` forks — that is
    what lets children share the imported code/objects via copy-on-write. Each
    thunk blocks running one worker; ``repo`` is initialized inside the child
    (post-fork) so every child opens its own pool, never a fork-inherited one.
    """
    import asyncio

    if name == "heavy":
        from decnet.profiler import attacker_profile_worker
        from decnet.ttp.worker import run_ttp_worker_loop
        from decnet.web.dependencies import repo

        # Importing the worker modules here (in the master) is what lets children
        # share their code via CoW. Heavy per-worker runtime state (ATT&CK bundle,
        # ML) still loads lazily in each child — warming it in the master to share
        # it too is a future optimization, gated on a live RSS measurement showing
        # the big object graph actually CoW-shares rather than refcount-dirtying.
        def _profiler() -> None:
            async def _go() -> None:
                await repo.initialize()
                await attacker_profile_worker(repo, interval=60)
            asyncio.run(_go())

        def _ttp() -> None:
            async def _go() -> None:
                await repo.initialize()
                await run_ttp_worker_loop(repo, poll_interval_secs=60.0)
            asyncio.run(_go())

        return {"profiler": _profiler, "ttp": _ttp}

    raise ValueError(f"unknown fleet: {name}")


def register(app: typer.Typer) -> None:
    @app.command(name="fleet")
    def fleet_cmd(
        name: str = typer.Argument(
            ..., help=f"Worker fleet to fork. One of: {', '.join(_FLEETS)}"
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d", help="Detach to background as a daemon process"
        ),
    ) -> None:
        """Prefork a worker fleet: shared base floor (CoW), one child process per worker."""
        from decnet.prefork import run_fleet

        if name not in _FLEETS:
            console.print(
                f"[red]unknown fleet {name!r}; known fleets: {', '.join(_FLEETS)}[/]"
            )
            raise typer.Exit(2)

        if daemon:
            log.info("fleet %s daemonizing", name)
            _utils._daemonize()

        log.info("fleet %s starting", name)
        console.print(f"[bold cyan]Fleet starting[/] {name} (prefork)")
        specs = _build_fleet(name)
        run_fleet(specs)
