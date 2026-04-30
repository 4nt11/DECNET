"""Add/remove a single service on a deployed decky without full redeploy.

The ``_compose()`` wrapper in :mod:`decnet.engine.deployer` already
supports per-service targeting (``up --no-deps -d <svc>``,
``stop <svc>``, ``rm -f <svc>``).  What was missing was the
orchestration: regenerate the compose file (so future redeploys reflect
the change), persist the new ``services`` list, and run the targeted
compose command.

Two scopes:

* **Topology** — source of truth is the ``topology_deckies`` table; the
  compose file is per-topology (``decnet-topology-<id8>-compose.yml``).
* **Fleet** — source of truth is ``decnet-state.json`` (with the
  ``fleet_deckies`` table mirroring it); compose is the unihost
  ``decnet-compose.yml``.

Both publish ``decky.<name>.service.added`` /
``decky.<name>.service.removed`` on the bus.  The new topic constants
are documented in ``wiki-checkout/Service-Bus.md``.
"""
from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path
from typing import Any, Literal, Optional

import anyio

from decnet.bus import topics
from decnet.logging import get_logger
from decnet.services.base import BaseService
from decnet.services.registry import get_service
from decnet.topology.persistence import hydrate
from decnet.web.db.repository import BaseRepository

# Heavy imports (composer/deployer pull in decnet.network → docker) are
# deferred to call-sites via the ``_compose`` / ``_topology_compose_path``
# / ``_load_state`` indirection helpers below.  Mirrors the lazy-import
# pattern in decnet.canary.planter for the same reason.


def _compose(*args: str, compose_file: Optional[Path] = None, env=None) -> None:
    """Indirection so tests can ``monkeypatch.setattr(services_live, '_compose', ...)``.

    Real implementation lives in :mod:`decnet.engine.deployer`; we
    import-and-delegate at call time to keep this module's import graph
    clean (see module docstring above).
    """
    from decnet.engine.deployer import _compose as _real_compose
    if compose_file is None:
        _real_compose(*args, env=env)
    else:
        _real_compose(*args, compose_file=compose_file, env=env)


def _topology_compose_path(topology_id: str) -> Path:
    from decnet.engine.deployer import _topology_compose_path as _real_path
    return _real_path(topology_id)


def _write_topology_compose(hydrated, path: Path) -> Path:
    from decnet.topology.compose import write_topology_compose
    return write_topology_compose(hydrated, path)


def _load_state():
    from decnet.config import load_state as _real_load_state
    return _real_load_state()


def _save_state(config, compose_path) -> None:
    from decnet.config import save_state as _real_save_state
    _real_save_state(config, compose_path)


def _write_compose(config, compose_path) -> None:
    from decnet.composer import write_compose as _real_write_compose
    _real_write_compose(config, compose_path)


def _get_bus():
    from decnet.bus.factory import get_bus
    return get_bus()


# --------------------------- swarm propagation helpers ---------------------------
#
# Service mutations (add/remove/update_config) on a deployed decky used to run
# the master's local docker-compose only.  For swarm fleet deckies the master
# has no containers; for agent-targeted topologies the master only writes a
# compose file the worker never sees.  These helpers replay the change to the
# worker so the env actually lands.
#
# Lazy imports keep this module's import graph clean (composer/swarm pull in
# decnet.network → docker, mirroring the pattern used elsewhere in this file).


async def _fleet_decky_host_uuid(repo: BaseRepository, decky_name: str) -> Optional[str]:
    """Return ``host_uuid`` if a fleet decky lives on a swarm worker, else None."""
    shards = await repo.list_decky_shards()
    for s in shards:
        if s.get("decky_name") == decky_name:
            return s.get("host_uuid")
    return None


async def _redispatch_fleet_shard(repo: BaseRepository, host_uuid: str) -> None:
    """Re-push the host's full shard to its worker agent.

    Uses the same code path as POST /swarm/deploy: load master state, filter
    to the host's deckies, hand to AgentClient.deploy via dispatch_decnet_config.
    The agent regenerates compose and recreates only the changed containers.
    Idempotent for unchanged deckies.
    """
    from decnet.web.router.swarm.api_deploy_swarm import dispatch_decnet_config

    state = _load_state()
    if state is None:
        log.warning("redispatch_fleet_shard: no fleet state on master; skipping")
        return
    config, _compose_path = state
    host_deckies = [d for d in config.deckies if getattr(d, "host_uuid", None) == host_uuid]
    if not host_deckies:
        log.warning(
            "redispatch_fleet_shard: master state has no deckies for host=%s; skipping",
            host_uuid,
        )
        return
    filtered = config.model_copy(update={"deckies": host_deckies})
    await dispatch_decnet_config(filtered, repo)


async def _resync_agent_topology(repo: BaseRepository, topology_id: str) -> None:
    """If the topology is agent-pinned, push the latest hydrated blob to the worker."""
    from decnet.engine.deployer import resync_agent_topology

    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        return
    if not hydrated.get("topology", {}).get("target_host_uuid"):
        return  # unihost topology — local compose is authoritative
    await resync_agent_topology(repo, topology_id)


log = get_logger("engine.services_live")

DeckyKind = Literal["fleet", "topology"]


class ServiceMutationError(ValueError):
    """Raised for caller-correctable failures (unknown service, idempotency
    violation, missing decky).  The API layer maps subclasses / message
    contents to 4xx codes; everything else surfaces as 500.
    """


def _validate_service_for_per_decky(name: str) -> BaseService:
    """Return the registered service or raise ``ServiceMutationError``.

    ``fleet_singleton`` services run once per fleet (e.g. an LLMNR
    responder), not per-decky — we reject the per-decky add/remove
    request rather than silently producing a no-op compose entry.
    """
    try:
        svc = get_service(name)
    except KeyError as exc:
        raise ServiceMutationError(f"unknown service {name!r}") from exc
    if svc.fleet_singleton:
        raise ServiceMutationError(
            f"service {name!r} is fleet_singleton; not addable per-decky"
        )
    return svc


async def _publish(topic: str, payload: dict[str, Any]) -> None:
    """Best-effort bus publish — same shape as the canary planter's helper."""
    try:
        bus = _get_bus()
        await bus.connect()
        await bus.publish(topic, payload)
        await bus.close()
    except Exception as e:  # noqa: BLE001
        log.warning("services_live bus publish failed topic=%s err=%s", topic, e)


# ---------------------------------------------------------- topology path


async def _topology_decky(
    repo: BaseRepository, topology_id: str, decky_name: str,
) -> dict[str, Any]:
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        raise ServiceMutationError(f"topology {topology_id!r} not found")
    for d in hydrated["deckies"]:
        cfg = d.get("decky_config") or {}
        name = cfg.get("name") or d.get("name")
        if name == decky_name:
            return d
    raise ServiceMutationError(
        f"decky {decky_name!r} is not in topology {topology_id!r}"
    )


async def _rerender_topology_compose(
    repo: BaseRepository, topology_id: str,
) -> Path:
    """Re-hydrate + re-render the per-topology compose file.

    Called after a successful DB update so future deploys reflect the
    change; without this the file would still describe the old service
    set and a subsequent ``up -d`` would resurrect the removed service.
    """
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:  # pragma: no cover — narrow race
        raise ServiceMutationError(
            f"topology {topology_id!r} disappeared mid-mutation"
        )
    path = _topology_compose_path(topology_id)
    _write_topology_compose(hydrated, path)
    return path


async def _add_topology_service(
    repo: BaseRepository,
    topology_id: str,
    decky_name: str,
    service_name: str,
    initial_config: dict | None = None,
) -> list[str]:
    decky = await _topology_decky(repo, topology_id, decky_name)
    services: list[str] = list(decky.get("services") or [])
    if service_name in services:
        raise ServiceMutationError(
            f"service {service_name!r} already on decky {decky_name!r}"
        )
    services.append(service_name)
    update: dict[str, Any] = {"services": services}
    # If the caller supplied initial config, fold it into decky_config
    # BEFORE compose regen so the first ``up`` materialises the env on
    # the new container — no follow-up apply needed.
    if initial_config:
        cfg_blob = dict(decky.get("decky_config") or {})
        sc = dict(cfg_blob.get("service_config") or {})
        sc[service_name] = initial_config
        cfg_blob["service_config"] = sc
        update["decky_config"] = cfg_blob
    await repo.update_topology_decky(decky["uuid"], update)

    compose_path = await _rerender_topology_compose(repo, topology_id)
    if await _topology_is_agent_pinned(repo, topology_id):
        # Agent-pinned: the master's local compose has nothing to up.
        # Push the new hydrated blob to the worker.
        await _resync_agent_topology(repo, topology_id)
    else:
        target = f"{decky_name}-{service_name}"
        # Run compose in a worker thread so the API event loop stays
        # responsive — same pattern as engine/deployer.deploy_topology.
        await anyio.to_thread.run_sync(
            lambda: _compose(
                "up", "-d", "--no-deps", "--build", target,
                compose_file=compose_path,
            ),
        )
    return services


async def _topology_is_agent_pinned(repo: BaseRepository, topology_id: str) -> bool:
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        return False
    return bool(hydrated.get("topology", {}).get("target_host_uuid"))


async def _remove_topology_service(
    repo: BaseRepository,
    topology_id: str,
    decky_name: str,
    service_name: str,
) -> list[str]:
    decky = await _topology_decky(repo, topology_id, decky_name)
    services: list[str] = list(decky.get("services") or [])
    if service_name not in services:
        raise ServiceMutationError(
            f"service {service_name!r} not on decky {decky_name!r}"
        )
    services = [s for s in services if s != service_name]
    target = f"{decky_name}-{service_name}"
    compose_path = _topology_compose_path(topology_id)
    agent_pinned = await _topology_is_agent_pinned(repo, topology_id)
    if not agent_pinned:
        # Stop + rm before persisting + re-rendering so a half-completed
        # mutation leaves the operator a clear state to retry from
        # (container still running; DB still says service is on).
        await anyio.to_thread.run_sync(
            lambda: _compose("stop", target, compose_file=compose_path),
        )
        await anyio.to_thread.run_sync(
            lambda: _compose("rm", "-f", target, compose_file=compose_path),
        )
    await repo.update_topology_decky(decky["uuid"], {"services": services})
    await _rerender_topology_compose(repo, topology_id)
    if agent_pinned:
        # Worker tears down the removed service when it diffs the
        # incoming hydrated blob against its current state.
        await _resync_agent_topology(repo, topology_id)
    return services


# ---------------------------------------------------------- fleet path


def _fleet_state_or_raise() -> tuple[Any, Path]:
    state = _load_state()
    if state is None:
        raise ServiceMutationError(
            "no fleet state on disk — run `decnet up` first"
        )
    return state


def _fleet_find_decky(config: Any, decky_name: str) -> Any:
    for d in config.deckies:
        if d.name == decky_name:
            return d
    raise ServiceMutationError(f"fleet decky {decky_name!r} not found")


async def _persist_fleet_change(
    repo: BaseRepository, decky: Any, services: list[str], compose_path: Path,
) -> None:
    """Persist the mutation to JSON state, compose file, and the DB row."""
    config, _ = _load_state()  # type: ignore[misc] — checked earlier
    target = _fleet_find_decky(config, decky.name)
    target.services = services
    _save_state(config, compose_path)
    _write_compose(config, compose_path)
    # Mirror to the DB row so DB-only consumers (dashboard, API) see the
    # change without waiting for the reconciler.
    from decnet.web.db.models import LOCAL_HOST_SENTINEL
    await repo.upsert_fleet_decky({
        "host_uuid": getattr(decky, "host_uuid", None) or LOCAL_HOST_SENTINEL,
        "name": decky.name,
        "services": services,
        "decky_config": target.model_dump(mode="json"),
        "decky_ip": decky.ip,
        "state": "running",
    })


async def _add_fleet_service(
    repo: BaseRepository,
    decky_name: str,
    service_name: str,
    initial_config: dict | None = None,
) -> list[str]:
    config, compose_path = _fleet_state_or_raise()
    decky = _fleet_find_decky(config, decky_name)
    services: list[str] = list(decky.services or [])
    if service_name in services:
        raise ServiceMutationError(
            f"service {service_name!r} already on decky {decky_name!r}"
        )
    services.append(service_name)
    if initial_config:
        # Same path as _update_fleet_service_config: stash the validated
        # cfg on the decky model so the compose write picks it up.
        sc = dict(getattr(decky, "service_config", None) or {})
        sc[service_name] = initial_config
        decky.service_config = sc
    await _persist_fleet_change(repo, decky, services, compose_path)
    swarm_host_uuid = await _fleet_decky_host_uuid(repo, decky_name)
    if swarm_host_uuid:
        # Master has no container for this decky — re-push the host's
        # shard so the worker materialises the new service.
        await _redispatch_fleet_shard(repo, swarm_host_uuid)
    else:
        target = f"{decky_name}-{service_name}"
        await anyio.to_thread.run_sync(
            lambda: _compose(
                "up", "-d", "--no-deps", "--build", target,
                compose_file=compose_path,
            ),
        )
    return services


async def _remove_fleet_service(
    repo: BaseRepository, decky_name: str, service_name: str,
) -> list[str]:
    config, compose_path = _fleet_state_or_raise()
    decky = _fleet_find_decky(config, decky_name)
    services: list[str] = list(decky.services or [])
    if service_name not in services:
        raise ServiceMutationError(
            f"service {service_name!r} not on decky {decky_name!r}"
        )
    services = [s for s in services if s != service_name]
    target = f"{decky_name}-{service_name}"
    swarm_host_uuid = await _fleet_decky_host_uuid(repo, decky_name)
    if not swarm_host_uuid:
        # Local: stop+rm before persist so the operator has a clear retry
        # state if compose fails halfway. Swarm: skip — the worker's compose
        # will handle the removal when the redispatched config drops the
        # service from the decky.
        await anyio.to_thread.run_sync(
            lambda: _compose("stop", target, compose_file=compose_path),
        )
        await anyio.to_thread.run_sync(
            lambda: _compose("rm", "-f", target, compose_file=compose_path),
        )
    await _persist_fleet_change(repo, decky, services, compose_path)
    if swarm_host_uuid:
        await _redispatch_fleet_shard(repo, swarm_host_uuid)
    return services


# ---------------------------------------------------------- public api


async def add_service(
    repo: BaseRepository,
    *,
    decky_kind: DeckyKind,
    decky_name: str,
    service_name: str,
    topology_id: Optional[str] = None,
    config: dict | None = None,
) -> list[str]:
    """Add *service_name* to a deployed decky.

    Validates the service registry (rejects unknown / fleet_singleton
    names) and the optional ``config`` against the service's schema,
    persists the change, regenerates the compose file, runs
    ``up -d --no-deps --build <decky>-<service>`` in a worker thread,
    and publishes ``decky.<name>.service.added`` on the bus.

    ``config`` is the same dict shape PUT/POST .../config accepts; it's
    coerced via ``BaseService.validate_cfg`` before any state write so
    a 400-class failure leaves zero side-effects.

    Returns the post-mutation services list.
    """
    svc = _validate_service_for_per_decky(service_name)
    initial_config = svc.validate_cfg(config) if config else {}
    if decky_kind == "topology":
        if not topology_id:
            raise ServiceMutationError(
                "decky_kind=topology requires topology_id",
            )
        services = await _add_topology_service(
            repo, topology_id, decky_name, service_name,
            initial_config=initial_config,
        )
    elif decky_kind == "fleet":
        services = await _add_fleet_service(
            repo, decky_name, service_name,
            initial_config=initial_config,
        )
    else:  # pragma: no cover — Literal narrows
        raise ServiceMutationError(f"unknown decky_kind {decky_kind!r}")

    await _publish(
        topics.decky(decky_name, topics.DECKY_SERVICE_ADDED),
        {
            "decky_name": decky_name,
            "service_name": service_name,
            "topology_id": topology_id,
            "services": services,
        },
    )
    log.info(
        "services_live.add decky=%s topology=%s service=%s",
        decky_name, topology_id, service_name,
    )
    return services


async def update_service_config(
    repo: BaseRepository,
    *,
    decky_kind: DeckyKind,
    decky_name: str,
    service_name: str,
    cfg: dict,
    apply: bool = False,
    topology_id: Optional[str] = None,
) -> dict:
    """Persist ``cfg`` as the new ``service_config[service_name]`` for a decky.

    The submitted dict is validated against the service's
    ``config_schema`` (unknown keys dropped, types coerced) BEFORE any
    DB write, so a 400-class failure leaves zero side-effects.

    ``apply=False`` (Save):  only the DB row + compose file are updated.
                             The running container keeps its old env.
    ``apply=True``  (Apply): same persistence, then a force-recreate of
                             ``<decky>-<service>`` so the container picks
                             up the new env.  Destructive: drops any
                             in-container session state on that service.

    Returns the post-mutation validated cfg.
    """
    svc = _validate_service_for_per_decky(service_name)
    validated = svc.validate_cfg(cfg)
    if decky_kind == "topology":
        if not topology_id:
            raise ServiceMutationError(
                "decky_kind=topology requires topology_id",
            )
        await _update_topology_service_config(
            repo, topology_id, decky_name, service_name, validated, apply=apply,
        )
    elif decky_kind == "fleet":
        await _update_fleet_service_config(
            repo, decky_name, service_name, validated, apply=apply,
        )
    else:  # pragma: no cover
        raise ServiceMutationError(f"unknown decky_kind {decky_kind!r}")

    await _publish(
        topics.decky(decky_name, topics.DECKY_SERVICE_CONFIG_CHANGED),
        {
            "decky_name": decky_name,
            "service_name": service_name,
            "topology_id": topology_id,
            "service_config": validated,
            "recreated": bool(apply),
        },
    )
    log.info(
        "services_live.update_config decky=%s topology=%s service=%s apply=%s",
        decky_name, topology_id, service_name, apply,
    )
    return validated


async def _update_topology_service_config(
    repo: BaseRepository,
    topology_id: str,
    decky_name: str,
    service_name: str,
    validated: dict,
    *,
    apply: bool,
) -> None:
    decky = await _topology_decky(repo, topology_id, decky_name)
    if service_name not in (decky.get("services") or []):
        raise ServiceMutationError(
            f"service {service_name!r} not on decky {decky_name!r}"
        )
    cfg_blob = dict(decky.get("decky_config") or {})
    sc = dict(cfg_blob.get("service_config") or {})
    sc[service_name] = validated
    cfg_blob["service_config"] = sc
    await repo.update_topology_decky(decky["uuid"], {"decky_config": cfg_blob})
    compose_path = await _rerender_topology_compose(repo, topology_id)
    if apply:
        if await _topology_is_agent_pinned(repo, topology_id):
            await _resync_agent_topology(repo, topology_id)
        else:
            target = f"{decky_name}-{service_name}"
            await anyio.to_thread.run_sync(
                lambda: _compose(
                    "up", "-d", "--no-deps", "--force-recreate", "--build", target,
                    compose_file=compose_path,
                ),
            )


async def _update_fleet_service_config(
    repo: BaseRepository,
    decky_name: str,
    service_name: str,
    validated: dict,
    *,
    apply: bool,
) -> None:
    config, compose_path = _fleet_state_or_raise()
    decky = _fleet_find_decky(config, decky_name)
    if service_name not in (decky.services or []):
        raise ServiceMutationError(
            f"service {service_name!r} not on decky {decky_name!r}"
        )
    sc = dict(getattr(decky, "service_config", None) or {})
    sc[service_name] = validated
    decky.service_config = sc
    _save_state(config, compose_path)
    _write_compose(config, compose_path)
    from decnet.web.db.models import LOCAL_HOST_SENTINEL
    await repo.upsert_fleet_decky({
        "host_uuid": getattr(decky, "host_uuid", None) or LOCAL_HOST_SENTINEL,
        "name": decky.name,
        "services": list(decky.services or []),
        "decky_config": decky.model_dump(mode="json"),
        "decky_ip": decky.ip,
        "state": "running",
    })
    if apply:
        swarm_host_uuid = await _fleet_decky_host_uuid(repo, decky_name)
        if swarm_host_uuid:
            await _redispatch_fleet_shard(repo, swarm_host_uuid)
        else:
            target = f"{decky_name}-{service_name}"
            # Docker Compose tracks the previous container by ID. If that
            # container was already removed (or renamed during a prior failed
            # deploy), --force-recreate fails with "No such container". Pre-
            # remove by name so Compose starts from a clean slate.
            await anyio.to_thread.run_sync(
                lambda: subprocess.run(  # nosec B603 B607
                    ["docker", "rm", "-f", target],
                    capture_output=True,
                ),
            )
            await anyio.to_thread.run_sync(
                lambda: _compose(
                    "up", "-d", "--no-deps", "--force-recreate", "--build", target,
                    compose_file=compose_path,
                ),
            )


async def remove_service(
    repo: BaseRepository,
    *,
    decky_kind: DeckyKind,
    decky_name: str,
    service_name: str,
    topology_id: Optional[str] = None,
) -> list[str]:
    """Remove *service_name* from a deployed decky.

    Stops + removes the service container, persists the new services
    list, re-renders the compose file (so the next ``up -d`` doesn't
    bring it back), and publishes ``decky.<name>.service.removed``.

    Returns the post-mutation services list.
    """
    if decky_kind == "topology":
        if not topology_id:
            raise ServiceMutationError(
                "decky_kind=topology requires topology_id",
            )
        services = await _remove_topology_service(
            repo, topology_id, decky_name, service_name,
        )
    elif decky_kind == "fleet":
        services = await _remove_fleet_service(repo, decky_name, service_name)
    else:  # pragma: no cover
        raise ServiceMutationError(f"unknown decky_kind {decky_kind!r}")

    await _publish(
        topics.decky(decky_name, topics.DECKY_SERVICE_REMOVED),
        {
            "decky_name": decky_name,
            "service_name": service_name,
            "topology_id": topology_id,
            "services": services,
        },
    )
    log.info(
        "services_live.remove decky=%s topology=%s service=%s",
        decky_name, topology_id, service_name,
    )
    return services
