"""POST /swarm/heartbeat — agent→master liveness + decky snapshot refresh.

Workers call this every ~30 s with the output of ``executor.status()``.
The master bumps ``SwarmHost.last_heartbeat`` and re-upserts each
``DeckyShard`` with the fresh ``DeckyConfig`` snapshot + runtime-derived
state so the dashboard stays current without a master-pull probe.

Security: CA-signed mTLS is necessary but not sufficient — a
decommissioned worker's still-valid cert must not resurrect ghost
shards. We pin the presented peer cert's SHA-256 to the
``client_cert_fingerprint`` stored for the claimed ``host_uuid``.
Mismatch (or decommissioned host) → 403.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ValidationError

from decnet.config import DeckyConfig
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo

log = get_logger("swarm.heartbeat")

router = APIRouter()


class HeartbeatRequest(BaseModel):
    host_uuid: str
    agent_version: Optional[str] = None
    status: dict[str, Any]
    topology: Optional[dict[str, Any]] = None


def _extract_peer_fingerprint(scope: dict[str, Any]) -> Optional[str]:
    """Pull the peer cert's SHA-256 fingerprint from an ASGI scope.

    Tries two extraction paths because uvicorn has historically stashed
    the TLS peer cert in different scope keys across versions:

    1. Primary: ``scope["extensions"]["tls"]["client_cert_chain"][0]``
       (uvicorn ≥ 0.30 ASGI TLS extension).
    2. Fallback: the transport object's ``ssl_object.getpeercert(binary_form=True)``
       (older uvicorn builds + some other servers).

    Returns the lowercase hex SHA-256 of the DER-encoded cert, or None
    when neither path yields bytes. The endpoint fails closed on None.
    """
    peer_der: Optional[bytes] = None
    source = "none"

    try:
        chain = scope.get("extensions", {}).get("tls", {}).get("client_cert_chain")
        if chain:
            peer_der = chain[0]
            source = "primary"
    except (AttributeError, KeyError, TypeError):
        # scope["extensions"]["tls"] structure varies across uvicorn versions
        peer_der = None

    if peer_der is None:
        transport = scope.get("transport")
        try:
            ssl_obj = transport.get_extra_info("ssl_object") if transport else None
            if ssl_obj is not None:
                peer_der = ssl_obj.getpeercert(binary_form=True)
                if peer_der:
                    source = "fallback"
        except (AttributeError, OSError):
            # transport may not be an SSL transport, or the handshake may be incomplete
            peer_der = None

    if not peer_der:
        log.debug("heartbeat: peer cert extraction failed via none")
        return None

    log.debug("heartbeat: peer cert extraction succeeded via %s", source)
    return hashlib.sha256(peer_der).hexdigest().lower()


async def _verify_peer_matches_host(
    request: Request, host_uuid: str, repo: BaseRepository
) -> dict[str, Any]:
    host = await repo.get_swarm_host_by_uuid(host_uuid)
    if host is None:
        raise HTTPException(status_code=404, detail="unknown host")
    fp = _extract_peer_fingerprint(request.scope)
    if fp is None:
        raise HTTPException(status_code=403, detail="peer cert unavailable")
    expected = (host.get("client_cert_fingerprint") or "").lower()
    if not expected or fp != expected:
        raise HTTPException(status_code=403, detail="cert fingerprint mismatch")
    return host


async def _reconcile_topology_report(
    repo: BaseRepository,
    host_uuid: str,
    reported: Optional[dict[str, Any]],
) -> None:
    """Compare the agent's reported applied_version_hash against what
    master expects for any topology pinned to *host_uuid*.

    Sets ``needs_resync=True`` when:
    - master has an ACTIVE topology targeted here but the agent reports
      a different hash, OR
    - master has an ACTIVE topology targeted here but the agent reports
      no topology at all (fresh boot / wiped cache).

    The actual re-push is handled by the mutator reconcile loop so the
    heartbeat endpoint stays cheap.
    """
    from decnet.topology.hashing import canonical_hash
    from decnet.topology.persistence import hydrate
    from decnet.topology.status import TopologyStatus

    try:
        topos = await repo.list_topologies(status=TopologyStatus.ACTIVE)
    except Exception:
        # Non-fatal: reconcile is best-effort; the host stays alive regardless
        log.exception("heartbeat: could not list active topologies")
        return
    mine = [t for t in topos if t.get("target_host_uuid") == host_uuid]
    if not mine:
        return

    reported_id = (reported or {}).get("topology_id")
    reported_hash = (reported or {}).get("applied_version_hash")

    for topo in mine:
        tid = topo["id"]
        if topo.get("needs_resync"):
            continue
        expected: Optional[str] = None
        if reported_id == tid and reported_hash:
            try:
                hydrated = await hydrate(repo, tid)
            except Exception:
                # Non-fatal: skip this topology; mutator reconcile loop will retry
                log.exception("heartbeat: hydrate failed tid=%s", tid)
                continue
            if hydrated is None:
                continue
            expected = canonical_hash(hydrated)
            if expected == reported_hash:
                continue
        # Either mismatch or agent reports no/other topology — flag it.
        try:
            await repo.set_topology_resync(tid, True)
            log.info(
                "heartbeat: flagged topology %s for resync (host=%s "
                "reported_id=%s reported_hash=%s expected=%s)",
                tid, host_uuid, reported_id, reported_hash, expected,
            )
        except Exception:
            # Non-fatal: mutator reconcile loop will detect the mismatch again next heartbeat
            log.exception("heartbeat: failed to flag resync tid=%s", tid)


@router.post(
    "/heartbeat",
    status_code=204,
    tags=["Swarm Health"],
    responses={
        400: {"description": "Bad Request (malformed JSON body)"},
        403: {"description": "Peer cert missing, or its fingerprint does not match the host's pinned cert"},
        404: {"description": "host_uuid is not enrolled"},
        422: {"description": "Request body validation error"},
    },
)
async def heartbeat(
    req: HeartbeatRequest,
    request: Request,
    repo: BaseRepository = Depends(get_repo),
) -> None:
    await _verify_peer_matches_host(request, req.host_uuid, repo)

    now = datetime.now(timezone.utc)
    await repo.update_swarm_host(
        req.host_uuid,
        {"status": "active", "last_heartbeat": now},
    )

    await _reconcile_topology_report(repo, req.host_uuid, req.topology)

    status_body = req.status or {}
    if not status_body.get("deployed"):
        return

    runtime = status_body.get("runtime") or {}
    for decky_dict in status_body.get("deckies") or []:
        try:
            d = DeckyConfig(**decky_dict)
        except (ValidationError, TypeError):
            log.exception("heartbeat: skipping malformed decky payload host=%s", req.host_uuid)
            continue
        rstate = runtime.get(d.name) or {}
        is_up = bool(rstate.get("running"))
        await repo.upsert_decky_shard(
            {
                "decky_name": d.name,
                "host_uuid": req.host_uuid,
                "services": json.dumps(d.services),
                "decky_config": d.model_dump_json(),
                "decky_ip": d.ip,
                "state": "running" if is_up else "degraded",
                "last_error": None,
                "last_seen": now,
                "updated_at": now,
            }
        )
