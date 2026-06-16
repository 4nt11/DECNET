# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /swarm-updates/push-self — push only to workers' /update-self.

Use case: the agent is fine but the updater itself needs an upgrade (e.g.
a fix to ``executor.py``). Uploading only ``/update-self`` avoids a
redundant agent restart on healthy workers.

No auto-rollback: the updater re-execs itself on success, so a broken
push leaves the worker on the old code — verified by polling ``/health``
after the request returns.
"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends

from decnet.logging import get_logger
from decnet.swarm.tar_tree import detect_git_sha, tar_working_tree
from decnet.swarm.updater_client import UpdaterClient
from decnet.web.db.models import PushUpdateRequest, PushUpdateResponse, PushUpdateResult
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

from .api_push_update import _is_expected_connection_drop, _master_tree_root, _resolve_targets

log = get_logger("swarm_updates.push_self")

router = APIRouter()


async def _push_self_one(host: dict[str, Any], tarball: bytes, sha: str) -> PushUpdateResult:
    try:
        async with UpdaterClient(host=host) as u:
            try:
                r = await u.update_self(tarball, sha=sha)
                http_status = r.status_code
                body = r.json() if r.content else {}
                ok = http_status == 200
                detail = (body.get("error") or body.get("probe")) if isinstance(body, dict) else None
                stderr = body.get("stderr") if isinstance(body, dict) else None
            except Exception as exc:  # noqa: BLE001
                # Connection drops during self-update are expected — the updater
                # re-execs itself mid-response.
                if _is_expected_connection_drop(exc):
                    return PushUpdateResult(
                        host_uuid=host["uuid"], host_name=host["name"],
                        status="self-updated", sha=sha,
                        detail="updater re-exec dropped connection (expected)",
                    )
                raise
        return PushUpdateResult(
            host_uuid=host["uuid"], host_name=host["name"],
            status="self-updated" if ok else "self-failed",
            http_status=http_status, sha=sha,
            detail=detail, stderr=stderr,
        )
    except Exception:  # noqa: BLE001
        log.exception("swarm_updates.push_self failed host=%s", host.get("name"))
        return PushUpdateResult(
            host_uuid=host["uuid"], host_name=host["name"],
            status="self-failed",
            detail="transport failure",
        )


@router.post(
    "/push-self",
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
async def api_push_update_self(
    req: PushUpdateRequest,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> PushUpdateResponse:
    targets = await _resolve_targets(repo, req)
    tree_root = _master_tree_root()
    # Offload sync I/O (git shell-out + tar+gzip of the repo) so the event
    # loop stays responsive while the tarball is being built.
    sha = await asyncio.to_thread(detect_git_sha, tree_root)
    tarball = await asyncio.to_thread(tar_working_tree, tree_root, extra_excludes=req.exclude)
    log.info(
        "swarm_updates.push_self sha=%s tarball=%d hosts=%d",
        sha or "(not a git repo)", len(tarball), len(targets),
    )
    results = await asyncio.gather(
        *(_push_self_one(h, tarball, sha) for h in targets)
    )
    return PushUpdateResponse(
        sha=sha,
        tarball_bytes=len(tarball),
        results=list(results),
    )
