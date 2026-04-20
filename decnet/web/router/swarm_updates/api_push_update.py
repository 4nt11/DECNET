"""POST /swarm-updates/push — fan a tarball of the master's tree to workers.

Mirrors the ``decnet swarm update`` CLI flow: build the tarball once,
dispatch concurrently, collect per-host statuses. Returns HTTP 200 even
when individual hosts failed — the operator reads per-host ``status``.
"""
from __future__ import annotations

import asyncio
import pathlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.swarm.tar_tree import detect_git_sha, tar_working_tree
from decnet.swarm.updater_client import UpdaterClient
from decnet.web.db.models import PushUpdateRequest, PushUpdateResponse, PushUpdateResult
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm_updates.push")

router = APIRouter()


def _master_tree_root() -> pathlib.Path:
    """Resolve the master's install tree to tar.

    Walks up from this file: ``decnet/web/router/swarm_updates/`` → 3 parents
    lands on the repo root. Matches the layout shipped via ``pip install -e .``
    and the dev checkout at ``~/Tools/DECNET``.
    """
    return pathlib.Path(__file__).resolve().parents[4]


def _classify_update(status_code: int) -> str:
    if status_code == 200:
        return "updated"
    if status_code == 409:
        return "rolled-back"
    return "failed"


async def _resolve_targets(
    repo: BaseRepository,
    req: PushUpdateRequest,
) -> list[dict[str, Any]]:
    if req.all == bool(req.host_uuids):
        raise HTTPException(
            status_code=400,
            detail="Specify exactly one of host_uuids or all=true.",
        )
    rows = await repo.list_swarm_hosts()
    rows = [r for r in rows if r.get("updater_cert_fingerprint")]
    if req.all:
        targets = [r for r in rows if r.get("status") != "decommissioned"]
    else:
        wanted = set(req.host_uuids or [])
        targets = [r for r in rows if r["uuid"] in wanted]
        missing = wanted - {r["uuid"] for r in targets}
        if missing:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown or updater-less host(s): {sorted(missing)}",
            )
    if not targets:
        raise HTTPException(
            status_code=404,
            detail="No targets: no enrolled hosts have an updater bundle.",
        )
    return targets


async def _push_one(
    host: dict[str, Any],
    tarball: bytes,
    sha: str,
    include_self: bool,
) -> PushUpdateResult:
    try:
        async with UpdaterClient(host=host) as u:
            r = await u.update(tarball, sha=sha)
            body = r.json() if r.content else {}
            status = _classify_update(r.status_code)
            stderr = body.get("stderr") if isinstance(body, dict) else None

            if include_self and r.status_code == 200:
                # Agent first, updater second — a broken updater push must never
                # strand the fleet on an old agent.
                try:
                    rs = await u.update_self(tarball, sha=sha)
                    self_ok = rs.status_code in (200, 0)  # 0 = connection dropped (expected)
                except Exception as exc:  # noqa: BLE001
                    # Connection drop on update-self is expected and not an error.
                    self_ok = _is_expected_connection_drop(exc)
                    if not self_ok:
                        return PushUpdateResult(
                            host_uuid=host["uuid"], host_name=host["name"],
                            status="self-failed", http_status=r.status_code, sha=sha,
                            detail=f"agent updated OK but self-update failed: {exc}",
                            stderr=stderr,
                        )
                status = "self-updated" if self_ok else "self-failed"

            return PushUpdateResult(
                host_uuid=host["uuid"], host_name=host["name"],
                status=status, http_status=r.status_code, sha=sha,
                detail=body.get("error") or body.get("probe") if isinstance(body, dict) else None,
                stderr=stderr,
            )
    except Exception as exc:  # noqa: BLE001
        log.exception("swarm_updates.push failed host=%s", host.get("name"))
        return PushUpdateResult(
            host_uuid=host["uuid"], host_name=host["name"],
            status="failed",
            detail=f"{type(exc).__name__}: {exc}",
        )


def _is_expected_connection_drop(exc: BaseException) -> bool:
    """update-self re-execs the updater mid-response; httpx raises on the drop."""
    import httpx
    return isinstance(exc, (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError))


@router.post(
    "/push",
    response_model=PushUpdateResponse,
    tags=["Swarm Updates"],
    responses={
        400: {"description": "Bad Request (malformed JSON body or conflicting host_uuids/all flags)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "No matching target hosts or no updater-capable hosts enrolled"},
        422: {"description": "Request body validation error"},
    },
)
async def api_push_update(
    req: PushUpdateRequest,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> PushUpdateResponse:
    targets = await _resolve_targets(repo, req)
    tree_root = _master_tree_root()
    # Both `detect_git_sha` (shells out) and `tar_working_tree` (walks the repo
    # + gzips a few MB) are synchronous CPU+I/O. Running them directly on the
    # event loop blocks every other request until the tarball is built — the
    # dashboard freezes on /swarm-updates push. Offload to a worker thread.
    sha = await asyncio.to_thread(detect_git_sha, tree_root)
    tarball = await asyncio.to_thread(tar_working_tree, tree_root, extra_excludes=req.exclude)
    log.info(
        "swarm_updates.push sha=%s tarball=%d hosts=%d include_self=%s",
        sha or "(not a git repo)", len(tarball), len(targets), req.include_self,
    )
    results = await asyncio.gather(
        *(_push_one(h, tarball, sha, req.include_self) for h in targets)
    )
    return PushUpdateResponse(
        sha=sha,
        tarball_bytes=len(tarball),
        results=list(results),
    )
