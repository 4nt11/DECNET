"""GET /swarm-updates/hosts — per-host updater health + release slots.

Fans out an ``UpdaterClient.health()`` probe to every enrolled host that
has an updater bundle. Each probe is isolated: a single unreachable host
never fails the whole list (that's normal partial-failure behaviour for
a fleet view).
"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends

from decnet.logging import get_logger
from decnet.swarm.updater_client import UpdaterClient
from decnet.web.db.models import HostReleaseInfo, HostReleasesResponse
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm_updates.list")

router = APIRouter()


def _extract_shas(releases: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """Pick the (current, previous) SHA from the updater's releases list.

    The updater reports releases as ``[{"slot": "active"|"prev", "sha": ...,
    ...}]`` in no guaranteed order, so pull by slot name rather than index.
    """
    current = next((r.get("sha") for r in releases if r.get("slot") == "active"), None)
    previous = next((r.get("sha") for r in releases if r.get("slot") == "prev"), None)
    return current, previous


async def _probe_host(host: dict[str, Any]) -> HostReleaseInfo:
    try:
        async with UpdaterClient(host=host) as u:
            body = await u.health()
    except Exception as exc:  # noqa: BLE001
        return HostReleaseInfo(
            host_uuid=host["uuid"],
            host_name=host["name"],
            address=host["address"],
            reachable=False,
            detail=f"{type(exc).__name__}: {exc}",
        )
    releases = body.get("releases") or []
    current, previous = _extract_shas(releases)
    return HostReleaseInfo(
        host_uuid=host["uuid"],
        host_name=host["name"],
        address=host["address"],
        reachable=True,
        agent_status=body.get("agent_status") or body.get("status"),
        current_sha=current,
        previous_sha=previous,
        releases=releases,
    )


@router.get(
    "/hosts",
    response_model=HostReleasesResponse,
    tags=["Swarm Updates"],
)
async def api_list_host_releases(
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> HostReleasesResponse:
    rows = await repo.list_swarm_hosts()
    # Only hosts actually capable of receiving updates — decommissioned
    # hosts and agent-only enrollments are filtered out.
    targets = [
        r for r in rows
        if r.get("status") != "decommissioned" and r.get("updater_cert_fingerprint")
    ]
    if not targets:
        return HostReleasesResponse(hosts=[])
    results = await asyncio.gather(*(_probe_host(h) for h in targets))
    return HostReleasesResponse(hosts=list(results))
