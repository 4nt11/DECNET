"""POST/GET/DELETE /api/v1/deckies/{decky_name}/tarpit — per-decky tc netem tarpit.

Applies port-selective traffic delay on the host veth paired to the target
decky container using tc qdisc (HTB + netem).  Requires CAP_NET_ADMIN on
the API process (provided by decnet-api.service AmbientCapabilities).

Auth: ``require_admin`` for write operations, ``require_viewer`` for GET.
"""
from __future__ import annotations

import asyncio
import json
import socket
import subprocess  # nosec B404

from fastapi import APIRouter, Depends, HTTPException, Path

from decnet.logging import get_logger
from decnet.network import get_container_pid, get_container_veth
from decnet.web.db.models import (
    MessageResponse,
    TarpitEnableRequest,
    TarpitRuleResponse,
    TarpitStatusResponse,
)
from decnet.web.dependencies import repo, require_admin, require_viewer

log = get_logger("api.deckies.tarpit")

router = APIRouter(prefix="/deckies/{decky_name}/tarpit", tags=["Deckies"])

_DECKY_RE = r"^[a-z0-9\-]{1,64}$"


def _tc(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = ["tc", *args]
    return subprocess.run(cmd, capture_output=True, text=True)  # nosec B603 B404


def _apply_tarpit(veth: str, ports: list[int], delay_ms: int) -> None:
    """Build tc qdisc + class + netem + per-port filters on veth."""
    steps = [
        ["qdisc", "add", "dev", veth, "root", "handle", "1:", "htb"],
        ["class", "add", "dev", veth, "parent", "1:", "classid", "1:1",
         "htb", "rate", "1gbit"],
        ["qdisc", "add", "dev", veth, "parent", "1:1", "handle", "10:",
         "netem", "delay", f"{delay_ms}ms"],
    ]
    for args in steps:
        r = _tc(*args)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())

    for port in ports:
        r = _tc(
            "filter", "add", "dev", veth,
            "protocol", "ip", "parent", "1:", "prio", "1",
            "u32", "match", "ip", "dport", str(port), "0xffff",
            "flowid", "1:1",
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())


def _remove_tarpit(veth: str) -> bool:
    """Tear down the qdisc tree.  Returns False if nothing was there."""
    r = _tc("qdisc", "del", "dev", veth, "root")
    if r.returncode != 0:
        if "Cannot find" in r.stderr or "No such" in r.stderr:
            return False
        raise RuntimeError(r.stderr.strip())
    return True


def _get_active_connections(pid: int, ports: list[int]) -> list[dict]:
    """Read /proc/{pid}/net/tcp and return active connections on tarpitted ports."""
    try:
        with open(f"/proc/{pid}/net/tcp") as f:
            content = f.read()
    except OSError:
        return []

    conns: list[dict] = []
    for line in content.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local_hex, rem_hex, state = parts[1], parts[2], parts[3]
        if state != "01":
            continue
        local_port = int(local_hex.split(":")[1], 16)
        if local_port not in ports:
            continue
        rem_ip_hex = rem_hex.split(":")[0]
        try:
            ip = socket.inet_ntoa(bytes.fromhex(rem_ip_hex)[::-1])
        except (ValueError, OSError):
            continue
        if ip != "0.0.0.0":  # nosec B104
            conns.append({"ip": ip, "port": local_port})
    return conns


@router.post(
    "",
    response_model=MessageResponse,
    status_code=201,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky not found in active deployment"},
        409: {"description": "tc command failed (qdisc already exists or veth unreachable)"},
    },
)
async def api_enable_tarpit(
    decky_name: str = Path(..., pattern=_DECKY_RE),
    req: TarpitEnableRequest = ...,  # type: ignore[assignment]
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    try:
        veth = await asyncio.to_thread(get_container_veth, decky_name)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        await asyncio.to_thread(_apply_tarpit, veth, req.ports, req.delay_ms)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    ports_json = json.dumps(req.ports)
    await repo.set_tarpit_rule({
        "decky_name": decky_name,
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
            f"tarpit enabled decky={decky_name} ports={req.ports} delay={req.delay_ms}ms"
            f" by={admin.get('uuid', 'unknown')}"
        ),
        "fields": json.dumps({
            "ports": req.ports,
            "delay_ms": req.delay_ms,
            "veth": veth,
            "operator": admin.get("uuid"),
        }),
    })
    log.info(
        "tarpit enabled decky=%s ports=%s delay_ms=%d veth=%s by=%s",
        decky_name, req.ports, req.delay_ms, veth, admin.get("uuid"),
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
    decky_name: str = Path(..., pattern=_DECKY_RE),
    viewer: dict = Depends(require_viewer),
) -> TarpitStatusResponse:
    rule = await repo.get_tarpit_rule(decky_name)
    if rule is None:
        raise HTTPException(status_code=404, detail="No active tarpit rule for this decky")

    conns: list[dict] = []
    try:
        pid = await asyncio.to_thread(get_container_pid, decky_name)
        raw_conns = await asyncio.to_thread(_get_active_connections, pid, rule["ports"])
        for c in raw_conns:
            conns.append({"ip": c["ip"], "port": c["port"]})
    except LookupError:
        pass

    return TarpitStatusResponse(
        rule=TarpitRuleResponse(**rule),
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
    decky_name: str = Path(..., pattern=_DECKY_RE),
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    try:
        veth = await asyncio.to_thread(get_container_veth, decky_name)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        await asyncio.to_thread(_remove_tarpit, veth)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await repo.delete_tarpit_rule(decky_name)
    await repo.add_log({
        "decky": decky_name,
        "service": "tarpit",
        "event_type": "tarpit_disabled",
        "attacker_ip": "0.0.0.0",  # nosec B104
        "raw_line": (
            f"tarpit disabled decky={decky_name}"
            f" by={admin.get('uuid', 'unknown')}"
        ),
        "fields": json.dumps({"veth": veth, "operator": admin.get("uuid")}),
    })
    log.info("tarpit disabled decky=%s veth=%s by=%s", decky_name, veth, admin.get("uuid"))
    return MessageResponse(message="tarpit removed")
