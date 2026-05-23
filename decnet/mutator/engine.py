# SPDX-License-Identifier: AGPL-3.0-or-later
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
import contextlib

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    publish_safely as _publish_safely,
    run_control_listener_signal as _run_control_listener_signal,
    run_health_heartbeat as _run_health_heartbeat,
)
from decnet.mutator.events import MutationTrigger, emit_decky_mutated
from decnet.web.db.repository import BaseRepository

log = get_logger("mutator")
console = Console()


def pick_new_services(decky: DeckyConfig) -> list[str] | None:
    """Pick a fresh service list for *decky* using its archetype pool
    (or the global pool when no archetype is set).  Returns ``None`` if
    no services are available to pick from.

    Pure: does not touch the repo, file system, or docker.  Shared by
    the mutator watch loop and the async API handler.
    """
    if decky.archetype:
        try:
            arch = get_archetype(decky.archetype)
            svc_pool = list(arch.services)
        except ValueError:
            svc_pool = all_service_names()
    else:
        svc_pool = all_service_names()

    if not svc_pool:
        return None

    current_services = set(decky.services)
    attempts = 0
    while True:
        count = random.randint(1, min(3, len(svc_pool)))  # nosec B311
        chosen = set(random.sample(svc_pool, count))  # nosec B311
        attempts += 1
        if chosen != current_services or attempts > 20:
            break
    return list(chosen)


@_traced("mutator.mutate_decky")
async def mutate_decky(
    decky_name: str,
    repo: BaseRepository,
    bus: BaseBus | None = None,
    trigger: MutationTrigger = "operator",
) -> bool:
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

    old_services = list(decky.services)
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

    log.info("mutation applied decky=%s services=%s", decky_name, ",".join(decky.services))
    console.print(f"[cyan]Mutating '{decky_name}' to services: {', '.join(decky.services)}[/]")

    # Swarm-resident deckies are reified on a remote worker; dispatch to its
    # agent /mutate rather than scribbling a compose file on the master.
    # Master-resident deckies (host_uuid is None, or unihost mode) keep the
    # local docker path.
    if config.mode == "swarm" and decky.host_uuid:
        try:
            from decnet.engine.deployer import _resolve_swarm_host
            from decnet.swarm.client import AgentClient

            host = await _resolve_swarm_host(repo, decky.host_uuid)
            async with AgentClient(host=host) as agent:
                await agent.mutate(decky.name, list(decky.services))
        except Exception as e:
            log.error("mutation failed decky=%s error=%s", decky_name, e)
            console.print(f"[red]Failed to mutate '{decky_name}': {e}[/]")
            return False
    else:
        # Still writes files for Docker to use
        write_compose(config, compose_path)
        try:
            cp = compose_path
            await anyio.to_thread.run_sync(
                lambda: _compose_with_retry("up", "-d", "--remove-orphans", compose_file=cp)
            )
        except Exception as e:
            log.error("mutation failed decky=%s error=%s", decky_name, e)
            console.print(f"[red]Failed to mutate '{decky_name}': {e}[/]")
            return False

    await emit_decky_mutated(
        bus,
        decky=decky_name,
        old_services=old_services,
        new_services=list(decky.services),
        trigger=trigger,
    )
    return True


@_traced("mutator.mutate_all")
async def mutate_all(
    repo: BaseRepository,
    force: bool = False,
    bus: BaseBus | None = None,
    only: set[str] | None = None,
) -> float | None:
    """Mutate all deckies that are due (or *only* the named ones).

    Returns the number of seconds until the next scheduled mutation, or
    ``None`` if no deployment exists / no decky has an interval set.  The
    watch loop uses this to adaptively sleep instead of hard-polling at a
    fixed cadence.

    A missing ``deployment`` state row is *not* an error any more — the
    host may simply not have run ``decnet deploy`` yet.  The watch loop
    edge-triggers the user-facing log for that state.
    """
    log.debug("mutate_all: start force=%s only=%s", force, only)
    state_dict = await repo.get_state("deployment")
    if state_dict is None:
        log.debug("mutate_all: no active deployment found")
        return None

    config = DecnetConfig(**state_dict["config"])
    now = time.time()

    # Trigger derivation: explicit force / targeted only-list come from
    # an operator action (CLI --all, API mutate-now, UI bus request).
    # Scheduled-interval ticks carry trigger=scheduled.
    trigger: MutationTrigger = "operator" if (force or only is not None) else "scheduled"

    mutated_count = 0
    next_due_in: float | None = None
    for decky in config.deckies:
        if only is not None and decky.name not in only:
            continue
        interval_mins = decky.mutate_interval or config.mutate_interval
        if interval_mins is None and not force:
            continue

        if force or only is not None:
            due = True
        else:
            if interval_mins is None:
                continue
            elapsed_secs = now - decky.last_mutated
            due = elapsed_secs >= (interval_mins * 60)
            remaining = (interval_mins * 60) - elapsed_secs
            if not due and (next_due_in is None or remaining < next_due_in):
                next_due_in = remaining

        if due:
            success = await mutate_decky(
                decky.name, repo=repo, bus=bus, trigger=trigger,
            )
            if success:
                mutated_count += 1

    if mutated_count:
        log.info("mutate_all: complete mutated_count=%d", mutated_count)
    else:
        log.debug("mutate_all: no deckies due for mutation")
    return next_due_in


@_traced("mutator.reconcile_topologies")
async def reconcile_topologies(
    repo: BaseRepository, bus: BaseBus | None = None,
) -> int:
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
            await _publish_safely(
                bus,
                _topics.topology_mutation(tid, _topics.MUTATION_APPLYING),
                {"mutation_id": mut["id"], "op": mut["op"], "payload": mut["payload"]},
                event_type=_topics.MUTATION_APPLYING,
            )
            try:
                await _op_dispatch(repo, tid, mut["op"], mut["payload"])
                await repo.mark_mutation_applied(mut["id"])
                drained += 1
                log.info(
                    "topology %s mutation %s applied op=%s",
                    tid, mut["id"], mut["op"],
                )
                await _publish_safely(
                    bus,
                    _topics.topology_mutation(tid, _topics.MUTATION_APPLIED),
                    {"mutation_id": mut["id"], "op": mut["op"]},
                    event_type=_topics.MUTATION_APPLIED,
                )
            except (MutationError, Exception) as exc:  # noqa: BLE001
                reason = f"{type(exc).__name__}: {exc}"
                await repo.mark_mutation_failed(mut["id"], reason)
                log.warning(
                    "topology %s mutation %s failed: %s",
                    tid, mut["id"], reason,
                )
                await _publish_safely(
                    bus,
                    _topics.topology_mutation(tid, _topics.MUTATION_FAILED),
                    {"mutation_id": mut["id"], "op": mut["op"], "reason": reason},
                    event_type=_topics.MUTATION_FAILED,
                )
                try:
                    await transition_status(
                        repo, tid, TopologyStatus.DEGRADED, reason=reason,
                    )
                    await _publish_safely(
                        bus,
                        _topics.topology_status(tid),
                        {"state": TopologyStatus.DEGRADED, "reason": reason},
                        event_type=_topics.TOPOLOGY_STATUS,
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
        tid = topo.id
        try:
            await _deployer.resync_agent_topology(repo, tid)
            await repo.set_topology_resync(tid, False)
            drained += 1
            log.info("topology %s resynced to agent %s",
                     tid, topo.target_host_uuid)
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

    # Connect to the bus for publish + wake-on-enqueue.  Failure here is
    # non-fatal: a mutator without a bus still works, it just runs at
    # poll-interval latency and doesn't push notifications to UI clients.
    bus: BaseBus | None = None
    wake = asyncio.Event()
    mutate_requests: set[str] = set()
    wake_tasks: list[asyncio.Task] = []
    heartbeat_task: asyncio.Task | None = None
    try:
        candidate = get_bus(client_name="mutator")
        await candidate.connect()
        bus = candidate
        wake_tasks.append(asyncio.create_task(_wake_on_enqueue(bus, wake)))
        wake_tasks.append(asyncio.create_task(
            _wake_on_mutate_request(bus, wake, mutate_requests),
        ))
        heartbeat_task = asyncio.create_task(
            _run_health_heartbeat(bus, "mutator"),
        )
        # Control listener: SIGTERM-based so the existing shutdown path
        # (cancel wake_tasks + heartbeat_task) runs unchanged.
        wake_tasks.append(asyncio.create_task(
            _run_control_listener_signal(bus, "mutator"),
        ))
    except Exception as exc:  # noqa: BLE001
        log.warning("mutator: bus unavailable, running in poll-only mode: %s", exc)

    # Edge-triggered "no deployment" state so we don't spam the console
    # every 10 seconds on a host that hasn't deployed yet.  Start as None
    # so the first observation fires exactly one line.
    deployment_present: bool | None = None

    try:
        while True:
            requested = mutate_requests.copy()
            mutate_requests.clear()

            next_due = await mutate_all(
                repo=repo,
                force=False,
                bus=bus,
                only=requested or None,
            )
            has_deployment = (
                next_due is not None or await repo.get_state("deployment") is not None
            )
            if has_deployment and deployment_present is not True:
                log.info("mutator: active deployment observed — entering normal cadence")
                console.print("[green]Active deployment observed.[/]")
                deployment_present = True
            elif not has_deployment and deployment_present is not False:
                log.info("mutator: no active deployment — idling until one lands")
                console.print("[dim]No active deployment; mutator idling.[/]")
                deployment_present = False

            # Gate reconciler on the O(log n) guard query — avoids
            # entering the dispatch body when there's nothing to do.
            try:
                if await repo.has_pending_topology_mutation():
                    await reconcile_topologies(repo, bus=bus)
            except NotImplementedError:
                # Backend without MazeNET support — nothing to reconcile.
                pass
            try:
                await reconcile_agent_resyncs(repo)
            except NotImplementedError:
                pass
            except Exception:
                log.exception("reconcile_agent_resyncs tick raised")

            # Adaptive sleep: wake at the earlier of (next decky due) or
            # (poll_interval_secs), bounded below by 1s so a thrashing
            # schedule can't spin the loop.  A bus wake (enqueue or
            # mutate_request) short-circuits the wait.
            if next_due is None or next_due > poll_interval_secs:
                timeout = float(poll_interval_secs)
            else:
                timeout = max(1.0, next_due)
            try:
                await asyncio.wait_for(wake.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            wake.clear()
    except KeyboardInterrupt:
        log.info("mutator watch loop stopped")
        console.print("\n[dim]Mutator watcher stopped.[/]")
    finally:
        for t in wake_tasks:
            t.cancel()
        if heartbeat_task is not None:
            heartbeat_task.cancel()
        for task in (*wake_tasks, heartbeat_task):
            if task is None:
                continue
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _wake_on_enqueue(bus: BaseBus, wake: asyncio.Event) -> None:
    """Flip *wake* every time a ``mutation.enqueued`` event lands.

    Subscribes to the wildcard ``topology.*.mutation.enqueued`` — a single
    subscription covers every topology on the host.  Runs until cancelled
    or the bus closes (NullBus yields nothing and returns immediately,
    which is fine: the poll-interval fallback still ticks).
    """
    pattern = f"{_topics.TOPOLOGY}.*.mutation.{_topics.MUTATION_ENQUEUED}"
    try:
        sub = bus.subscribe(pattern)
        async with sub:
            async for _event in sub:
                wake.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("mutator: wake subscriber died (%s); falling back to poll", exc)


async def _wake_on_mutate_request(
    bus: BaseBus,
    wake: asyncio.Event,
    pending: set[str],
) -> None:
    """Collect on-demand ``decky.<name>.mutate_request`` events.

    API/CLI/UI callers publish to ``decky.{name}.mutate_request`` to force
    an immediate mutation without waiting for the scheduled interval.  We
    stash the target decky name in *pending* so the next tick can feed it
    to ``mutate_all(only=...)``, then flip *wake* to short-circuit the
    sleep.  Payload is optional — the topic's second token is the name.
    """
    pattern = f"{_topics.DECKY}.*.{_topics.DECKY_MUTATE_REQUEST}"
    try:
        sub = bus.subscribe(pattern)
        async with sub:
            async for event in sub:
                topic = getattr(event, "topic", "") or ""
                parts = topic.split(".")
                name = parts[1] if len(parts) >= 3 else ""
                payload = getattr(event, "payload", None) or {}
                if not name and isinstance(payload, dict):
                    name = payload.get("name", "") or ""
                if name:
                    pending.add(name)
                    wake.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "mutator: mutate_request subscriber died (%s); falling back to poll",
            exc,
        )
