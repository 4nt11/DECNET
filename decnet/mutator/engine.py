"""
Mutation Engine for DECNET.
Handles dynamic rotation of exposed honeypot services over time.
"""

import random
import time
from typing import Optional

from rich.console import Console

from decnet.archetypes import get_archetype
from decnet.fleet import all_service_names
from decnet.composer import write_compose
from decnet.config import DeckyConfig, DecnetConfig
from decnet.engine import _compose_with_retry
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced

from pathlib import Path
import anyio
import asyncio
from decnet.web.db.repository import BaseRepository

log = get_logger("mutator")
console = Console()


@_traced("mutator.mutate_decky")
async def mutate_decky(decky_name: str, repo: BaseRepository) -> bool:
    """
    Perform an Intra-Archetype Shuffle for a specific decky.
    Returns True if mutation succeeded, False otherwise.
    """
    log.debug("mutate_decky: start decky=%s", decky_name)
    state_dict = await repo.get_state("deployment")
    if state_dict is None:
        log.error("mutate_decky: no active deployment found in database")
        console.print("[red]No active deployment found in database.[/]")
        return False

    config = DecnetConfig(**state_dict["config"])
    compose_path = Path(state_dict["compose_path"])
    decky: Optional[DeckyConfig] = next((d for d in config.deckies if d.name == decky_name), None)

    if not decky:
        console.print(f"[red]Decky '{decky_name}' not found in state.[/]")
        return False

    if decky.archetype:
        try:
            arch = get_archetype(decky.archetype)
            svc_pool = list(arch.services)
        except ValueError:
            svc_pool = all_service_names()
    else:
        svc_pool = all_service_names()

    if not svc_pool:
        console.print(f"[yellow]No services available for mutating '{decky_name}'.[/]")
        return False

    current_services = set(decky.services)

    attempts = 0
    while True:
        count = random.randint(1, min(3, len(svc_pool)))  # nosec B311
        chosen = set(random.sample(svc_pool, count))  # nosec B311
        attempts += 1
        if chosen != current_services or attempts > 20:
            break

    decky.services = list(chosen)
    decky.last_mutated = time.time()

    # Save to DB
    await repo.set_state("deployment", {"config": config.model_dump(), "compose_path": str(compose_path)})

    # Still writes files for Docker to use
    write_compose(config, compose_path)

    log.info("mutation applied decky=%s services=%s", decky_name, ",".join(decky.services))
    console.print(f"[cyan]Mutating '{decky_name}' to services: {', '.join(decky.services)}[/]")

    try:
        # Wrap blocking call in thread
        await anyio.to_thread.run_sync(_compose_with_retry, "up", "-d", "--remove-orphans", compose_path)
    except Exception as e:
        log.error("mutation failed decky=%s error=%s", decky_name, e)
        console.print(f"[red]Failed to mutate '{decky_name}': {e}[/]")
        return False

    return True


@_traced("mutator.mutate_all")
async def mutate_all(repo: BaseRepository, force: bool = False) -> None:
    """
    Check all deckies and mutate those that are due.
    If force=True, mutates all deckies regardless of schedule.
    """
    log.debug("mutate_all: start force=%s", force)
    state_dict = await repo.get_state("deployment")
    if state_dict is None:
        log.error("mutate_all: no active deployment found")
        console.print("[red]No active deployment found.[/]")
        return

    config = DecnetConfig(**state_dict["config"])
    now = time.time()

    mutated_count = 0
    for decky in config.deckies:
        interval_mins = decky.mutate_interval or config.mutate_interval
        if interval_mins is None and not force:
            continue

        if force:
            due = True
        else:
            elapsed_secs = now - decky.last_mutated
            due = elapsed_secs >= (interval_mins * 60)

        if due:
            success = await mutate_decky(decky.name, repo=repo)
            if success:
                mutated_count += 1

    if mutated_count == 0 and not force:
        log.debug("mutate_all: no deckies due for mutation")
        console.print("[dim]No deckies are due for mutation.[/]")
    else:
        log.info("mutate_all: complete mutated_count=%d", mutated_count)


@_traced("mutator.reconcile_topologies")
async def reconcile_topologies(repo: BaseRepository) -> int:
    """Drain pending ``topology_mutations`` rows against live topologies.

    For every topology in ``active|degraded`` with at least one pending
    mutation, atomically claim the oldest via
    :meth:`BaseRepository.claim_next_mutation`, dispatch to the matching
    ``apply_<op>`` in :mod:`decnet.mutator.ops`, and write the outcome
    back (``applied`` or ``failed``).

    On ``MutationError`` the topology is flipped to ``degraded`` — the
    same state the future Healer will target — so operators can see that
    a requested change was rejected without the repo drifting into an
    inconsistent state.

    Returns the number of mutations drained this tick.
    """
    # Local imports keep the flat-fleet hot path free of MazeNET cost.
    from decnet.mutator.ops import MutationError, dispatch as _op_dispatch
    from decnet.topology.persistence import transition_status
    from decnet.topology.status import TopologyStatus, TopologyStatusError

    drained = 0
    for tid in await repo.list_live_topology_ids():
        while True:
            mut = await repo.claim_next_mutation(tid)
            if mut is None:
                break  # no more work for this topology this tick.
            try:
                await _op_dispatch(repo, tid, mut["op"], mut["payload"])
                await repo.mark_mutation_applied(mut["id"])
                drained += 1
                log.info(
                    "topology %s mutation %s applied op=%s",
                    tid, mut["id"], mut["op"],
                )
            except (MutationError, Exception) as exc:  # noqa: BLE001
                reason = f"{type(exc).__name__}: {exc}"
                await repo.mark_mutation_failed(mut["id"], reason)
                log.warning(
                    "topology %s mutation %s failed: %s",
                    tid, mut["id"], reason,
                )
                try:
                    await transition_status(
                        repo, tid, TopologyStatus.DEGRADED, reason=reason,
                    )
                except TopologyStatusError:
                    # Already degraded / in a state that can't degrade
                    # further — leave as is.
                    pass
                # Stop draining this topology on first failure so the
                # operator can inspect before a cascade.
                break
    return drained


@_traced("mutator.reconcile_agent_resyncs")
async def reconcile_agent_resyncs(repo: BaseRepository) -> int:
    """Re-push agent-targeted topologies flagged by the heartbeat handler.

    The heartbeat sets ``needs_resync=True`` when an agent's reported
    applied_version_hash diverges from master's expectation.  Here we
    re-run the agent branch of ``deploy_topology`` which pushes the
    current hydrated blob back down over mTLS and clears the flag on
    success.  Any push failure leaves the flag set so the next tick
    retries — it also logs loudly so ops can see that a specific agent
    is stuck.
    """
    from decnet.engine import deployer as _deployer

    try:
        pending = await repo.list_topologies_needing_resync()
    except NotImplementedError:
        return 0
    drained = 0
    for topo in pending:
        tid = topo["id"]
        try:
            await _deployer.resync_agent_topology(repo, tid)
            await repo.set_topology_resync(tid, False)
            drained += 1
            log.info("topology %s resynced to agent %s",
                     tid, topo.get("target_host_uuid"))
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "topology %s resync failed (will retry): %s", tid, exc,
            )
    return drained


@_traced("mutator.watch_loop")
async def run_watch_loop(repo: BaseRepository, poll_interval_secs: int = 10) -> None:
    """Run an infinite loop checking for deckies that need mutation.

    Two independent responsibilities, in strict order per tick:

    1. Flat-fleet service rotation (``mutate_all``) — runs every tick
       regardless of MazeNET state, preserving phase-1 timing.
    2. MazeNET live-mutation reconciliation — runs only when the cheap
       guard ``has_pending_topology_mutation`` (indexed composite
       lookup) returns True.  Zero-topology and idle-topology hosts pay
       exactly one indexed query per tick.
    """
    log.info("mutator watch loop started poll_interval_secs=%d", poll_interval_secs)
    console.print(f"[green]DECNET Mutator Watcher started (polling every {poll_interval_secs}s).[/]")
    try:
        while True:
            await mutate_all(force=False, repo=repo)
            # Gate reconciler on the O(log n) guard query — avoids
            # entering the dispatch body when there's nothing to do.
            try:
                if await repo.has_pending_topology_mutation():
                    await reconcile_topologies(repo)
            except NotImplementedError:
                # Backend without MazeNET support — nothing to reconcile.
                pass
            try:
                await reconcile_agent_resyncs(repo)
            except NotImplementedError:
                pass
            except Exception:
                log.exception("reconcile_agent_resyncs tick raised")
            await asyncio.sleep(poll_interval_secs)
    except KeyboardInterrupt:
        log.info("mutator watch loop stopped")
        console.print("\n[dim]Mutator watcher stopped.[/]")
