"""Live-mutation ops for active MazeNET topologies.

Each ``apply_<op>`` function consumes a claimed ``TopologyMutation``
payload, mutates the repo (and, best-effort, the underlying Docker
state), then re-runs :func:`decnet.topology.validate.validate` against
the post-apply hydrated view.  If validation errors appear, the op is
reported as failed and the caller flips the topology to ``degraded`` —
we never leave the repo in an invalid state.

Design notes
------------
* All ops are *repo-first*.  The reconciler's job is to converge Docker
  toward the repo's desired state, so persisting intent first keeps the
  system self-healing across master restarts.
* Docker calls are optional at the ops layer: the tests drive these
  functions directly against an in-memory repo, and the reconciler
  sidecar calls them in production where Docker is present.  Every
  Docker call is guarded so missing/unreachable Docker doesn't leave
  the DB half-mutated.
* Ops intentionally do NOT perform optimistic-concurrency checks — the
  enqueue step already carried the caller's ``expected_version``.  The
  reconciler is the sole writer from here on.
"""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Optional

from decnet.logging import get_logger
from decnet.topology.allocator import IPAllocator, reserved_subnets, SubnetAllocator
from decnet.topology.persistence import hydrate
from decnet.topology.validate import (
    check_names_unique,
    check_no_ip_collisions,
    check_no_subnet_overlap,
    check_service_config_shape,
    check_services_known,
    errors as _validation_errors,
)

# Post-apply validation intentionally excludes topology-shape rules
# (``check_all_lans_connected_to_dmz``, ``check_exactly_one_dmz``,
# ``check_no_orphan_deckies``) — those are legitimately transient
# during live editing (e.g. ``add_lan`` leaves the new LAN orphaned
# until the next ``attach_decky``).  The deployer's full ``validate()``
# pass still runs at redeploy time.  Invariants that MUST hold after
# every single op are kept here.
_POST_APPLY_CHECKS = (
    check_names_unique,
    check_no_ip_collisions,
    check_no_subnet_overlap,
    check_services_known,
    check_service_config_shape,
)

_log = get_logger("mutator.ops")


class MutationError(RuntimeError):
    """Raised by an ``apply_<op>`` when the requested change is illegal."""


OpFunc = Callable[[Any, str, dict[str, Any]], Awaitable[None]]


# ----------------------------------------------------------------- helpers


async def _hydrated(repo: Any, topology_id: str) -> dict[str, Any]:
    h = await hydrate(repo, topology_id)
    if h is None:
        raise MutationError(f"topology {topology_id!r} vanished mid-apply")
    return h


async def _assert_valid_after(repo: Any, topology_id: str) -> None:
    """Re-hydrate and check invariants; raise :class:`MutationError` on errors."""
    h = await _hydrated(repo, topology_id)
    issues: list = []
    for check in _POST_APPLY_CHECKS:
        issues.extend(check(h))
    bad = _validation_errors(issues)
    if bad:
        codes = ", ".join(sorted({i.code for i in bad}))
        raise MutationError(
            f"post-apply validation failed for {topology_id}: {codes}"
        )


def _lan_by_name(hydrated: dict[str, Any], name: str) -> Optional[dict]:
    return next((lan for lan in hydrated["lans"] if lan["name"] == name), None)


def _decky_by_name(hydrated: dict[str, Any], name: str) -> Optional[dict]:
    return next(
        (d for d in hydrated["deckies"] if d["decky_config"]["name"] == name),
        None,
    )


async def _materialise_lan_change(
    repo: Any,
    topology_id: str,
    *,
    created: Optional[tuple[str, str, bool]] = None,
    removed: Optional[str] = None,
) -> None:
    """Create or remove the docker bridge for a live LAN op + re-render compose.

    Called from ``apply_add_lan`` / ``apply_remove_lan`` after the DB
    write lands.  Skips when:

    * the topology is not active/degraded (a pending topology gets its
      networks created at deploy time),
    * the topology is pinned to a swarm agent (cross-host materialisation
      isn't implemented; the agent's apply_topology RPC re-renders the
      whole compose at next push),
    * the docker SDK / networking primitive raises (logged, not
      re-raised — the DB row is the source of truth).
    """
    topology = await repo.get_topology(topology_id)
    if topology is None:
        return
    status = topology.get("status")
    if status not in ("active", "degraded"):
        return
    if topology.get("target_host_uuid"):
        _log.info(
            "live LAN op skipped (agent-pinned topology=%s); next agent push will reconcile",
            topology_id,
        )
        return

    # Lazy imports — these pull in docker.py / network.py which both
    # require the docker SDK; keeping them out of module-import keeps
    # the mutator usable in test environments that stub docker.
    import docker
    from decnet.engine.deployer import _topology_compose_path
    from decnet.network import create_bridge_network, remove_bridge_network
    from decnet.topology.compose import _network_name, write_topology_compose

    client = docker.from_env()
    try:
        if created is not None:
            name, subnet, is_dmz = created
            net_name = _network_name(topology_id, name)
            try:
                create_bridge_network(
                    client, net_name, subnet, internal=not is_dmz,
                )
            except Exception as exc:  # noqa: BLE001
                _log.error(
                    "live add_lan: bridge create failed topology=%s lan=%s subnet=%s: %s",
                    topology_id, name, subnet, exc,
                )
                # Don't re-raise — the DB row is the source of truth.
                # Operator can retry by removing + re-adding the LAN.
        if removed is not None:
            net_name = _network_name(topology_id, removed)
            try:
                remove_bridge_network(client, net_name)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "live remove_lan: bridge remove failed topology=%s lan=%s: %s",
                    topology_id, removed, exc,
                )

        # Re-render compose so the file on disk matches the DB.  Even
        # when the bridge create above failed, a future redeploy will
        # try to bring the network back from the compose definition.
        hydrated = await hydrate(repo, topology_id)
        if hydrated is not None:
            try:
                write_topology_compose(
                    hydrated, _topology_compose_path(topology_id),
                )
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "live LAN op: compose re-render failed topology=%s: %s",
                    topology_id, exc,
                )
    except Exception as exc:  # noqa: BLE001 — outer net for any docker SDK failure
        _log.error(
            "live LAN materialisation crashed topology=%s: %s",
            topology_id, exc,
        )


def _decky_targets(decky_name: str, services: list[str]) -> list[str]:
    """Compose service names for one decky: base + each per-decky service.

    Skips ``fleet_singleton`` services — those run once fleet-wide and
    don't have a per-decky compose entry.  Mirrors the same filter
    applied at compose-render time
    (:mod:`decnet.topology.compose.generate_topology_compose`).
    """
    from decnet.services.registry import get_service
    targets = [decky_name]
    for svc_name in services:
        try:
            svc = get_service(svc_name)
        except KeyError:
            # Unknown service — leave it; the compose render won't emit
            # a fragment for it, so compose up will simply ignore the
            # name with a clear "no such service" error.  Surface that
            # rather than silently dropping it.
            targets.append(f"{decky_name}-{svc_name}")
            continue
        if svc.fleet_singleton:
            continue
        targets.append(f"{decky_name}-{svc_name}")
    return targets


async def _live_topology_or_none(
    repo: Any, topology_id: str,
) -> Optional[dict[str, Any]]:
    """Return the topology row only when it's eligible for live materialisation.

    Returns None (so callers can skip with a single ``if`` check) when:

    * the topology doesn't exist;
    * status is not ``active`` or ``degraded`` (pending topologies get
      everything materialised at deploy time);
    * the topology is pinned to a swarm agent (cross-host live editing
      is its own routing workstream).
    """
    topology = await repo.get_topology(topology_id)
    if topology is None:
        return None
    if topology.get("status") not in ("active", "degraded"):
        return None
    if topology.get("target_host_uuid"):
        _log.info(
            "live decky op skipped (agent-pinned topology=%s); "
            "next agent push will reconcile",
            topology_id,
        )
        return None
    return topology


async def _rerender_compose(repo: Any, topology_id: str) -> None:
    """Re-render the per-topology compose file from the current DB.

    Called after each materialisation step so the file on disk matches
    the topology rows.  Soft-fails: a render error is logged but
    doesn't poison the DB-side mutation.
    """
    from decnet.engine.deployer import _topology_compose_path
    from decnet.topology.compose import write_topology_compose
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        return
    try:
        write_topology_compose(hydrated, _topology_compose_path(topology_id))
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "live op: compose re-render failed topology=%s: %s",
            topology_id, exc,
        )


async def _materialise_decky_spawn(
    repo: Any, topology_id: str, decky_name: str, services: list[str],
) -> None:
    """compose up -d --no-deps --build for one decky (base + services).

    Re-renders compose first so the file lists the new decky.  No-op
    when the topology isn't eligible for live materialisation (see
    :func:`_live_topology_or_none`).  Best-effort: docker failure is
    logged, not re-raised — DB row is the source of truth.
    """
    if await _live_topology_or_none(repo, topology_id) is None:
        return
    import anyio
    from decnet.engine.deployer import (
        _compose_with_retry,
        _topology_compose_path,
    )
    await _rerender_compose(repo, topology_id)
    targets = _decky_targets(decky_name, services)
    compose_path = _topology_compose_path(topology_id)
    try:
        await anyio.to_thread.run_sync(
            lambda: _compose_with_retry(
                "up", "-d", "--no-deps", "--build", *targets,
                compose_file=compose_path,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "live add_decky: compose up failed topology=%s decky=%s: %s",
            topology_id, decky_name, exc,
        )


async def _materialise_decky_remove(
    repo: Any, topology_id: str, decky_name: str, services: list[str],
) -> None:
    """compose stop + rm -f for one decky's containers, then re-render."""
    if await _live_topology_or_none(repo, topology_id) is None:
        return
    import anyio
    from decnet.engine.deployer import _compose, _topology_compose_path

    targets = _decky_targets(decky_name, services)
    compose_path = _topology_compose_path(topology_id)
    # Stop + rm BEFORE re-rendering compose; the re-rendered file no
    # longer mentions the decky, so a stop run AFTER rendering would
    # find no service to act on.
    try:
        await anyio.to_thread.run_sync(
            lambda: _compose("stop", *targets, compose_file=compose_path),
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "live remove_decky: compose stop failed topology=%s decky=%s: %s",
            topology_id, decky_name, exc,
        )
    try:
        await anyio.to_thread.run_sync(
            lambda: _compose("rm", "-f", *targets, compose_file=compose_path),
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "live remove_decky: compose rm failed topology=%s decky=%s: %s",
            topology_id, decky_name, exc,
        )
    await _rerender_compose(repo, topology_id)


async def _materialise_decky_connect(
    repo: Any, topology_id: str,
    decky_name: str, lan_name: str, ipv4_address: str,
) -> None:
    """SDK ``network.connect`` to multi-home a running base container.

    Service containers share the base's netns via ``network_mode:
    service:<base>`` (see :mod:`decnet.topology.compose`), so attaching
    the base alone gives every service container the new interface for
    free — we don't need to iterate.
    """
    if await _live_topology_or_none(repo, topology_id) is None:
        return
    import docker
    from decnet.topology.compose import _container_name, _network_name

    net_name = _network_name(topology_id, lan_name)
    container_name = _container_name(topology_id, decky_name)
    try:
        client = docker.from_env()
        net = client.networks.get(net_name)
        container = client.containers.get(container_name)
        net.connect(container, ipv4_address=ipv4_address)
    except docker.errors.APIError as exc:
        # Idempotency — already on the network is fine.
        msg = str(exc).lower()
        if "already" in msg or "endpoint" in msg and "exists" in msg:
            _log.info(
                "live attach_decky: %s already on network %s — skipping",
                container_name, net_name,
            )
        else:
            _log.error(
                "live attach_decky: connect failed topology=%s decky=%s lan=%s: %s",
                topology_id, decky_name, lan_name, exc,
            )
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "live attach_decky: SDK call crashed topology=%s decky=%s lan=%s: %s",
            topology_id, decky_name, lan_name, exc,
        )
    await _rerender_compose(repo, topology_id)


async def _materialise_decky_disconnect(
    repo: Any, topology_id: str, decky_name: str, lan_name: str,
) -> None:
    """SDK ``network.disconnect`` to drop a multi-home edge."""
    if await _live_topology_or_none(repo, topology_id) is None:
        return
    import docker
    from decnet.topology.compose import _container_name, _network_name

    net_name = _network_name(topology_id, lan_name)
    container_name = _container_name(topology_id, decky_name)
    try:
        client = docker.from_env()
        net = client.networks.get(net_name)
        container = client.containers.get(container_name)
        net.disconnect(container)
    except docker.errors.APIError as exc:
        msg = str(exc).lower()
        if "not connected" in msg or "no such" in msg:
            _log.info(
                "live detach_decky: %s already off network %s — skipping",
                container_name, net_name,
            )
        else:
            _log.error(
                "live detach_decky: disconnect failed topology=%s decky=%s lan=%s: %s",
                topology_id, decky_name, lan_name, exc,
            )
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "live detach_decky: SDK call crashed topology=%s decky=%s lan=%s: %s",
            topology_id, decky_name, lan_name, exc,
        )
    await _rerender_compose(repo, topology_id)


async def _materialise_decky_services_diff(
    repo: Any, topology_id: str,
    decky_name: str,
    added: list[str],
    removed: list[str],
) -> None:
    """Add/remove per-service containers without touching siblings.

    Mirrors :mod:`decnet.engine.services_live`'s up/down pattern but
    without coupling the mutator to that module — service mutations
    routed via the mutator queue publish ``mutation.applied`` while the
    direct API publishes ``decky.<name>.service_added``; they share
    machinery, not control flow.
    """
    if not added and not removed:
        return
    if await _live_topology_or_none(repo, topology_id) is None:
        return
    import anyio
    from decnet.engine.deployer import (
        _compose, _compose_with_retry, _topology_compose_path,
    )
    await _rerender_compose(repo, topology_id)
    compose_path = _topology_compose_path(topology_id)
    add_targets = _decky_targets(decky_name, list(added))[1:]  # drop the base
    if add_targets:
        try:
            await anyio.to_thread.run_sync(
                lambda: _compose_with_retry(
                    "up", "-d", "--no-deps", "--build", *add_targets,
                    compose_file=compose_path,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "live update_decky add: compose up failed topology=%s decky=%s: %s",
                topology_id, decky_name, exc,
            )
    rm_targets = _decky_targets(decky_name, list(removed))[1:]
    for action_name, args in (("stop", ("stop",)), ("rm", ("rm", "-f"))):
        if not rm_targets:
            break
        try:
            await anyio.to_thread.run_sync(
                lambda args=args: _compose(*args, *rm_targets, compose_file=compose_path),
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "live update_decky %s failed topology=%s decky=%s: %s",
                action_name, topology_id, decky_name, exc,
            )


async def _materialise_decky_recreate_base(
    repo: Any, topology_id: str, decky_name: str,
) -> None:
    """Force-recreate just the base container (used for forwards_l3 flips).

    DESTRUCTIVE: kills any in-container state on the base.  Service
    containers re-attach via ``network_mode: service:<base>`` after the
    base is rebuilt.  Caller is responsible for gating this on an
    explicit operator-supplied ``force=true`` flag.
    """
    if await _live_topology_or_none(repo, topology_id) is None:
        return
    import anyio
    from decnet.engine.deployer import (
        _compose_with_retry, _topology_compose_path,
    )
    await _rerender_compose(repo, topology_id)
    compose_path = _topology_compose_path(topology_id)
    try:
        await anyio.to_thread.run_sync(
            lambda: _compose_with_retry(
                "up", "-d", "--no-deps", "--force-recreate", decky_name,
                compose_file=compose_path,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "live update_decky recreate_base failed topology=%s decky=%s: %s",
            topology_id, decky_name, exc,
        )


# ------------------------------------------------------------------- ops


async def apply_add_lan(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    """Add a new LAN to an active topology.

    ``payload`` keys:
        ``name``    — LAN name (required).
        ``subnet``  — ``/24`` CIDR (optional; auto-allocated if missing).
        ``is_dmz``  — bool, default False.
        ``x``,``y`` — layout coords, optional.
    """
    name = payload["name"]
    subnet = payload.get("subnet")
    is_dmz = bool(payload.get("is_dmz", False))

    if subnet is None:
        reserved = await reserved_subnets(repo)
        alloc = SubnetAllocator(base_prefix="172.16.0.0/12", reserved=reserved)
        subnet = alloc.next_free()

    await repo.add_lan(
        {
            "topology_id": topology_id,
            "name": name,
            "subnet": subnet,
            "is_dmz": is_dmz,
            "x": payload.get("x"),
            "y": payload.get("y"),
        }
    )

    # Live materialisation: when the topology is active/degraded, create
    # the docker bridge network now and re-render the per-topology
    # compose file so subsequent ``apply_add_decky`` writes a coherent
    # services map.  Pending topologies skip this — the next deploy
    # creates everything from scratch.  Agent-pinned topologies also
    # skip; live editing on agents is its own routing problem.
    await _materialise_lan_change(
        repo, topology_id, created=(name, subnet, is_dmz),
    )
    await _assert_valid_after(repo, topology_id)


async def apply_remove_lan(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    """Remove a LAN; refuses when any decky has it as its home LAN."""
    hydrated = await _hydrated(repo, topology_id)
    lan = _lan_by_name(hydrated, payload["name"])
    if lan is None:
        raise MutationError(f"LAN {payload['name']!r} not found")
    # Refuse if any decky's home (primary/first) LAN is this one.
    for d in hydrated["deckies"]:
        ips = d["decky_config"].get("ips_by_lan", {})
        if ips and next(iter(ips)) == lan["name"]:
            raise MutationError(
                f"LAN {lan['name']!r} is the home LAN of decky "
                f"{d['decky_config']['name']!r}; remove the decky first"
            )
    lan_name = lan["name"]
    # enforce_pending=False: the mutator queue is the live-editing
    # surface, gated on topology status by us before we got here.  The
    # repo's pending-only guard is for HTTP CRUD callers that mustn't
    # bypass it.
    await repo.delete_lan(lan["id"], enforce_pending=False)

    # Live materialisation symmetric to apply_add_lan: tear down the
    # docker bridge and re-render compose so a future redeploy doesn't
    # try to wire deckies into a network that no longer exists.
    await _materialise_lan_change(repo, topology_id, removed=lan_name)
    await _assert_valid_after(repo, topology_id)


async def apply_add_decky(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    """Create a brand-new decky and attach it to its home LAN.

    Used when the editor drags an archetype onto an active topology.
    ``apply_attach_decky`` requires an existing decky, so without this
    op there is no way to grow a live topology from the UI.

    ``payload`` keys:
        ``name``        — decky name (required, unique in topology).
        ``lan``         — home LAN name (required).
        ``services``    — list of service slugs (optional).
        ``archetype``   — slug string; stored in ``decky_config`` (optional).
        ``forwards_l3`` — bool; stored in ``decky_config`` (optional).
        ``ip``          — pinned IP inside the LAN; else auto-allocated.
        ``x``,``y``     — layout coords (optional).
    """
    name = payload["name"]
    hydrated = await _hydrated(repo, topology_id)
    if _decky_by_name(hydrated, name) is not None:
        raise MutationError(f"decky {name!r} already exists")
    lan = _lan_by_name(hydrated, payload["lan"])
    if lan is None:
        raise MutationError(f"LAN {payload['lan']!r} not found")

    ip = payload.get("ip")
    if ip is None:
        taken = {
            d["decky_config"]["ips_by_lan"].get(lan["name"])
            for d in hydrated["deckies"]
            if lan["name"] in d["decky_config"].get("ips_by_lan", {})
        }
        taken.discard(None)
        alloc = IPAllocator(subnet=lan["subnet"])
        for t in taken:
            if t:
                alloc.reserve(t)
        ip = alloc.next_free()

    decky_config: dict[str, Any] = {
        "name": name,
        "ips_by_lan": {lan["name"]: ip},
    }
    if "archetype" in payload:
        decky_config["archetype"] = payload["archetype"]
    forwards_l3 = bool(payload.get("forwards_l3", False))
    if forwards_l3:
        decky_config["forwards_l3"] = True

    services_list = list(payload.get("services", []))
    decky_uuid = await repo.add_topology_decky(
        {
            "topology_id": topology_id,
            "name": name,
            "services": services_list,
            "decky_config": decky_config,
            "x": payload.get("x"),
            "y": payload.get("y"),
        }
    )
    await repo.add_topology_edge(
        {
            "topology_id": topology_id,
            "decky_uuid": decky_uuid,
            "lan_id": lan["id"],
            "is_bridge": False,
            "forwards_l3": forwards_l3,
        }
    )
    # Live materialisation: spawn the new decky's containers without
    # touching siblings.  Skips on pending / agent-pinned topologies —
    # see _live_topology_or_none.
    await _materialise_decky_spawn(repo, topology_id, name, services_list)
    await _assert_valid_after(repo, topology_id)


async def apply_attach_decky(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    """Attach an existing decky to an additional LAN (bridge edge).

    ``payload`` keys:
        ``decky``   — decky name.
        ``lan``     — LAN name.
        ``ip``      — optional pinned IP; else allocated inside the LAN.
        ``forwards_l3`` — bool, default False.
    """
    hydrated = await _hydrated(repo, topology_id)
    lan = _lan_by_name(hydrated, payload["lan"])
    decky = _decky_by_name(hydrated, payload["decky"])
    if lan is None:
        raise MutationError(f"LAN {payload['lan']!r} not found")
    if decky is None:
        raise MutationError(f"decky {payload['decky']!r} not found")

    # Guard against re-attaching.
    for e in hydrated["edges"]:
        if e["decky_uuid"] == decky["uuid"] and e["lan_id"] == lan["id"]:
            raise MutationError(
                f"decky {decky['decky_config']['name']!r} already on "
                f"LAN {lan['name']!r}"
            )

    ip = payload.get("ip")
    if ip is None:
        taken = {
            d["decky_config"]["ips_by_lan"].get(lan["name"])
            for d in hydrated["deckies"]
            if lan["name"] in d["decky_config"].get("ips_by_lan", {})
        }
        taken.discard(None)
        alloc = IPAllocator(subnet=lan["subnet"])
        for t in taken:
            if t:
                alloc.reserve(t)
        ip = alloc.next_free()

    new_cfg = dict(decky["decky_config"])
    new_cfg["ips_by_lan"] = {**new_cfg.get("ips_by_lan", {}), lan["name"]: ip}
    forwards_l3 = bool(payload.get("forwards_l3", False))
    if forwards_l3:
        new_cfg["forwards_l3"] = True

    await repo.update_topology_decky(
        decky["uuid"], {"decky_config": new_cfg}
    )
    # Adding a second edge makes the decky multi-homed (a bridge decky).
    await repo.add_topology_edge(
        {
            "topology_id": topology_id,
            "decky_uuid": decky["uuid"],
            "lan_id": lan["id"],
            "is_bridge": True,
            "forwards_l3": forwards_l3,
        }
    )
    # Live materialisation: SDK network.connect on the base container.
    # Service containers share the base's netns via network_mode:
    # service:<base>, so they inherit the new interface — only the base
    # needs the connect.
    await _materialise_decky_connect(
        repo, topology_id,
        decky_name=decky["decky_config"]["name"],
        lan_name=lan["name"],
        ipv4_address=ip,
    )
    await _assert_valid_after(repo, topology_id)


async def apply_detach_decky(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    """Detach a decky from one of its non-home LANs."""
    hydrated = await _hydrated(repo, topology_id)
    lan = _lan_by_name(hydrated, payload["lan"])
    decky = _decky_by_name(hydrated, payload["decky"])
    if lan is None or decky is None:
        raise MutationError("decky or LAN not found")

    ips_by_lan = decky["decky_config"].get("ips_by_lan", {})
    if not ips_by_lan:
        raise MutationError("decky has no LAN memberships")
    home_lan = next(iter(ips_by_lan))
    if home_lan == lan["name"]:
        raise MutationError(
            f"cannot detach home LAN {home_lan!r}; use remove_decky"
        )

    edge = next(
        (
            e
            for e in hydrated["edges"]
            if e["decky_uuid"] == decky["uuid"] and e["lan_id"] == lan["id"]
        ),
        None,
    )
    if edge is None:
        raise MutationError(
            f"decky not attached to LAN {lan['name']!r}"
        )

    new_cfg = dict(decky["decky_config"])
    new_ips = dict(new_cfg.get("ips_by_lan", {}))
    new_ips.pop(lan["name"], None)
    new_cfg["ips_by_lan"] = new_ips

    await repo.update_topology_decky(
        decky["uuid"], {"decky_config": new_cfg}
    )
    await repo.delete_topology_edge(edge["id"], enforce_pending=False)
    # Live materialisation: SDK network.disconnect on the base
    # container.  Service containers automatically lose visibility into
    # the LAN because they share the base's netns.
    await _materialise_decky_disconnect(
        repo, topology_id,
        decky_name=decky["decky_config"]["name"],
        lan_name=lan["name"],
    )
    await _assert_valid_after(repo, topology_id)


async def apply_remove_decky(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    hydrated = await _hydrated(repo, topology_id)
    decky = _decky_by_name(hydrated, payload["decky"])
    if decky is None:
        raise MutationError(f"decky {payload['decky']!r} not found")
    decky_name = decky["decky_config"]["name"]
    services_list = list(decky.get("services") or [])
    await repo.delete_topology_decky(decky["uuid"], enforce_pending=False)
    # Live materialisation: stop + rm -f the decky's containers.  We
    # capture decky_name + services BEFORE the delete so the helper
    # has the targets even though the row is gone.
    await _materialise_decky_remove(
        repo, topology_id, decky_name, services_list,
    )
    await _assert_valid_after(repo, topology_id)


async def apply_update_decky(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    """Update decky config — services, service_config, forwards_l3, coords.

    ``payload`` keys:
        ``decky``         — decky name.
        ``patch``         — dict merged into existing ``decky_config``.
        ``services``      — replacement top-level services list.
        ``x``,``y``       — layout coords.
        ``force``         — opt-in for destructive recreates (currently
                            required when ``forwards_l3`` flips on a
                            live topology — see below).

    Live materialisation strategy:

    * **services changed** → diff old vs new; ``compose up -d`` for
      added, ``compose stop`` + ``rm -f`` for removed.  Mirrors the
      direct API path (services_live) without coupling.
    * **forwards_l3 flipped** → port publishing changes, which docker
      can only apply at container-create time.  Requires recreating
      the base — destructive (kills in-container state, drops active
      sessions).  Gated on ``payload['force'] is True``; otherwise we
      raise ``MutationError`` so a half-thinking operator doesn't
      stomp a live decky.
    * **only coords (x/y)** → DB-only.  No docker work.
    """
    hydrated = await _hydrated(repo, topology_id)
    decky = _decky_by_name(hydrated, payload["decky"])
    if decky is None:
        raise MutationError(f"decky {payload['decky']!r} not found")

    # Capture pre-state so we can compute the diff after the DB write.
    old_services = list(decky.get("services") or [])
    old_cfg = decky.get("decky_config") or {}
    old_forwards_l3 = bool(old_cfg.get("forwards_l3", False))

    patch: dict[str, Any] = {}
    new_decky_config = old_cfg
    if payload.get("patch"):
        new_decky_config = {**old_cfg, **payload["patch"]}
        patch["decky_config"] = new_decky_config
    new_services = old_services
    if "services" in payload:
        new_services = list(payload["services"])
        patch["services"] = new_services
    for key in ("x", "y"):
        if key in payload:
            patch[key] = payload[key]
    if not patch:
        return

    new_forwards_l3 = bool(new_decky_config.get("forwards_l3", False))
    forwards_l3_flipped = new_forwards_l3 != old_forwards_l3

    # Pre-check the destructive flip BEFORE any DB write, so a refused
    # mutation leaves zero side-effects.
    is_live = (await _live_topology_or_none(repo, topology_id)) is not None
    if is_live and forwards_l3_flipped and not bool(payload.get("force")):
        raise MutationError(
            f"forwards_l3 flip on live decky "
            f"{decky['decky_config']['name']!r} requires force=true; "
            "this will recreate the base container and drop in-container state"
        )

    await repo.update_topology_decky(decky["uuid"], patch)

    # Materialisation — only when the topology is actually live.
    # _live_topology_or_none was already called above; calling the
    # individual helpers re-checks (cheap) so they stay self-contained.
    decky_name = decky["decky_config"]["name"]
    added = sorted(set(new_services) - set(old_services))
    removed = sorted(set(old_services) - set(new_services))
    if added or removed:
        await _materialise_decky_services_diff(
            repo, topology_id, decky_name, added, removed,
        )
    if forwards_l3_flipped:
        # force was checked above; reaching here means the operator
        # opted in.  recreate_base re-renders compose first so the
        # rebuilt base picks up the new `ports:` block.
        await _materialise_decky_recreate_base(
            repo, topology_id, decky_name,
        )

    await _assert_valid_after(repo, topology_id)


async def apply_update_lan(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    """Update LAN fields — subnet, is_dmz, coords, rename.

    Guard rail: ``subnet`` and ``is_dmz`` are pinned at deploy time.
    Live deckies bind to the bridge with IPs allocated from the old
    subnet (and ``is_dmz`` flips swap the bridge's ``internal=False``
    flag, which docker can't change on a network with active
    containers).  Reject those mutations on active/degraded topologies
    rather than rewriting the DB into an incoherent state.

    Coord-only updates (``x``/``y``) are layout-only; let them through
    unconditionally.  Renames pass through too — the bridge's docker
    name is keyed off ``_network_name(topology_id, lan_name)``, so a
    rename would also need a rebuild — but rename isn't currently a
    code path on active topologies; if the operator hits it we still
    write the row and let the next deploy reconcile.
    """
    hydrated = await _hydrated(repo, topology_id)
    lan = _lan_by_name(hydrated, payload["name"])
    if lan is None:
        raise MutationError(f"LAN {payload['name']!r} not found")
    fields = {k: v for k, v in payload.get("patch", {}).items()}
    for key in ("x", "y"):
        if key in payload:
            fields[key] = payload[key]
    if not fields:
        return

    topology = await repo.get_topology(topology_id)
    is_live = bool(topology) and topology.get("status") in ("active", "degraded")
    if is_live:
        hostile = {"subnet", "is_dmz"} & fields.keys()
        if hostile:
            raise MutationError(
                f"cannot change {sorted(hostile)} on a deployed LAN; "
                f"teardown + redeploy required"
            )

    await repo.update_lan(lan["id"], fields)
    await _assert_valid_after(repo, topology_id)


# Keep the dispatch table in one place so the engine and CLI stay in
# sync without cross-imports.
DISPATCH: dict[str, OpFunc] = {
    "add_lan": apply_add_lan,
    "remove_lan": apply_remove_lan,
    "add_decky": apply_add_decky,
    "attach_decky": apply_attach_decky,
    "detach_decky": apply_detach_decky,
    "remove_decky": apply_remove_decky,
    "update_decky": apply_update_decky,
    "update_lan": apply_update_lan,
}


async def dispatch(
    repo: Any,
    topology_id: str,
    op: str,
    payload_raw: str | dict[str, Any],
) -> None:
    """Decode payload JSON (if a string) and run the matching op."""
    if isinstance(payload_raw, str):
        payload = json.loads(payload_raw) if payload_raw else {}
    else:
        payload = payload_raw
    try:
        fn = DISPATCH[op]
    except KeyError as e:
        raise MutationError(f"unknown op: {op!r}") from e
    await fn(repo, topology_id, payload)


__all__ = [
    "DISPATCH",
    "MutationError",
    "dispatch",
    "apply_add_lan",
    "apply_remove_lan",
    "apply_add_decky",
    "apply_attach_decky",
    "apply_detach_decky",
    "apply_remove_decky",
    "apply_update_decky",
    "apply_update_lan",
]
