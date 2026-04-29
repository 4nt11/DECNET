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
    await repo.delete_lan(lan["id"])

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

    decky_uuid = await repo.add_topology_decky(
        {
            "topology_id": topology_id,
            "name": name,
            "services": list(payload.get("services", [])),
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
    await repo.delete_topology_edge(edge["id"])
    await _assert_valid_after(repo, topology_id)


async def apply_remove_decky(
    repo: Any, topology_id: str, payload: dict[str, Any]
) -> None:
    hydrated = await _hydrated(repo, topology_id)
    decky = _decky_by_name(hydrated, payload["decky"])
    if decky is None:
        raise MutationError(f"decky {payload['decky']!r} not found")
    await repo.delete_topology_decky(decky["uuid"])
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
    """
    hydrated = await _hydrated(repo, topology_id)
    decky = _decky_by_name(hydrated, payload["decky"])
    if decky is None:
        raise MutationError(f"decky {payload['decky']!r} not found")
    patch: dict[str, Any] = {}
    if payload.get("patch"):
        merged = dict(decky["decky_config"])
        merged.update(payload["patch"])
        patch["decky_config"] = merged
    if "services" in payload:
        patch["services"] = list(payload["services"])
    for key in ("x", "y"):
        if key in payload:
            patch[key] = payload[key]
    if not patch:
        return
    await repo.update_topology_decky(decky["uuid"], patch)
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
