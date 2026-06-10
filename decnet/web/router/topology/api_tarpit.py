# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST/GET/DELETE /api/v1/topologies/{topology_id}/deckies/{decky_name}/tarpit

Same tc netem logic as the fleet tarpit, but scoped to a MazeNET topology.
Container name is resolved via resolve_decky_container so the SSH-suffix /
decnet_t_ convention is handled transparently.

Auth: require_admin for write operations, require_viewer for GET.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Path

from decnet.decky_io.resolve import resolve_decky_container
from decnet.logging import get_logger
from decnet.network import get_container_pid, get_container_veth
from decnet.web.db.models import (
    MessageResponse,
    TarpitEnableRequest,
    TarpitRuleResponse,
    TarpitStatusResponse,
)
from decnet.web.dependencies import repo, require_admin, require_viewer
from decnet.web.router.deckies.api_tarpit import (
    _apply_tarpit,
    _get_active_connections,
    _remove_tarpit,
)

log = get_logger("api.topology.tarpit")

_TOPO_RE = r"^[a-zA-Z0-9\-]{1,64}$"
_DECKY_RE = r"^[a-z0-9\-]{1,64}$"

router = APIRouter(
    prefix="/{topology_id}/deckies/{decky_name}/tarpit",
    tags=["Topologies"],
)


def _db_key(topology_id: str, decky_name: str) -> str:
    """Namespace topology tarpit rules away from fleet rules."""
    return f"t:{topology_id}:{decky_name}"


@router.post(
    "",
    response_model=MessageResponse,
    status_code=201,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky not found in topology"},
        409: {"description": "tc command failed (qdisc already exists or container unreachable)"},
    },
)
async def api_enable_tarpit(
    topology_id: str = Path(..., pattern=_TOPO_RE),
    decky_name: str = Path(..., pattern=_DECKY_RE),
    req: TarpitEnableRequest = ...,  # type: ignore[assignment]
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    try:
        container = await resolve_decky_container(repo, decky_name, topology_id=topology_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        veth = await asyncio.to_thread(get_container_veth, container)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        await asyncio.to_thread(_apply_tarpit, veth, req.ports, req.delay_ms)
    except RuntimeError as exc:
        log.warning(
            "tarpit enable failed topology=%s decky=%s: %s",
            topology_id, decky_name, exc, exc_info=True,
        )
        raise HTTPException(status_code=409, detail="tarpit command failed") from exc

    db_key = _db_key(topology_id, decky_name)
    ports_json = json.dumps(req.ports)
    await repo.set_tarpit_rule({
        "decky_name": db_key,
        "ports": ports_json,
        "delay_ms": req.delay_ms,
        "created_by": admin.get("uuid", "unknown"),
    })
    await repo.add_log({
        "decky": decky_name,
        "service": "tarpit",
        "event_type": "tarpit_enabled",
        "attacker_ip": "0.0.0.0",  # nosec B104
        "raw_line": (
            f"tarpit enabled topology={topology_id} decky={decky_name}"
            f" ports={req.ports} delay={req.delay_ms}ms"
            f" by={admin.get('uuid', 'unknown')}"
        ),
        "fields": json.dumps({
            "topology_id": topology_id,
            "ports": req.ports,
            "delay_ms": req.delay_ms,
            "veth": veth,
            "container": container,
            "operator": admin.get("uuid"),
        }),
    })
    log.info(
        "tarpit enabled topology=%s decky=%s ports=%s delay_ms=%d veth=%s by=%s",
        topology_id, decky_name, req.ports, req.delay_ms, veth, admin.get("uuid"),
    )
    return MessageResponse(message="tarpit active")


@router.get(
    "",
    response_model=TarpitStatusResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "No active tarpit rule for this decky"},
    },
)
async def api_get_tarpit(
    topology_id: str = Path(..., pattern=_TOPO_RE),
    decky_name: str = Path(..., pattern=_DECKY_RE),
    _viewer: dict = Depends(require_viewer),
) -> TarpitStatusResponse:
    db_key = _db_key(topology_id, decky_name)
    rule = await repo.get_tarpit_rule(db_key)
    if rule is None:
        raise HTTPException(status_code=404, detail="No active tarpit rule for this decky")

    conns: list[dict] = []
    try:
        container = await resolve_decky_container(repo, decky_name, topology_id=topology_id)
        pid = await asyncio.to_thread(get_container_pid, container)
        raw_conns = await asyncio.to_thread(_get_active_connections, pid, rule["ports"])
        for c in raw_conns:
            conns.append({"ip": c["ip"], "port": c["port"]})
    except LookupError:
        pass

    return TarpitStatusResponse(
        rule=TarpitRuleResponse(**{**rule, "decky_name": decky_name}),
        active_connections=conns,
    )


@router.delete(
    "",
    response_model=MessageResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky container not found"},
        409: {"description": "tc teardown failed"},
    },
)
async def api_disable_tarpit(
    topology_id: str = Path(..., pattern=_TOPO_RE),
    decky_name: str = Path(..., pattern=_DECKY_RE),
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    try:
        container = await resolve_decky_container(repo, decky_name, topology_id=topology_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        veth = await asyncio.to_thread(get_container_veth, container)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        await asyncio.to_thread(_remove_tarpit, veth)
    except RuntimeError as exc:
        log.warning(
            "tarpit disable failed topology=%s decky=%s: %s",
            topology_id, decky_name, exc, exc_info=True,
        )
        raise HTTPException(status_code=409, detail="tarpit command failed") from exc

    db_key = _db_key(topology_id, decky_name)
    await repo.delete_tarpit_rule(db_key)
    await repo.add_log({
        "decky": decky_name,
        "service": "tarpit",
        "event_type": "tarpit_disabled",
        "attacker_ip": "0.0.0.0",  # nosec B104
        "raw_line": (
            f"tarpit disabled topology={topology_id} decky={decky_name}"
            f" by={admin.get('uuid', 'unknown')}"
        ),
        "fields": json.dumps({
            "topology_id": topology_id,
            "veth": veth,
            "container": container,
            "operator": admin.get("uuid"),
        }),
    })
    log.info(
        "tarpit disabled topology=%s decky=%s veth=%s by=%s",
        topology_id, decky_name, veth, admin.get("uuid"),
    )
    return MessageResponse(message="tarpit removed")
