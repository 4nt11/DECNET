"""Remote updates DTOs (master → worker /updater fan-out)."""
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field as PydanticField


# --- Remote Updates (master → worker /updater) DTOs ---
# Powers the dashboard's Remote Updates page. The master dashboard calls
# these (auth-gated) endpoints; internally they fan out to each worker's
# updater daemon over mTLS via UpdaterClient.

class HostReleaseInfo(BaseModel):
    host_uuid: str
    host_name: str
    address: str
    reachable: bool
    # These fields mirror the updater's /health payload when reachable; they
    # are all Optional so an unreachable host still serializes cleanly.
    agent_status: Optional[str] = None
    current_sha: Optional[str] = None
    previous_sha: Optional[str] = None
    releases: list[dict[str, Any]] = PydanticField(default_factory=list)
    detail: Optional[str] = None  # populated when unreachable


class HostReleasesResponse(BaseModel):
    hosts: list[HostReleaseInfo]


class PushUpdateRequest(BaseModel):
    host_uuids: Optional[list[str]] = PydanticField(
        default=None,
        description="Target specific hosts; mutually exclusive with 'all'.",
    )
    all: bool = PydanticField(default=False, description="Target every non-decommissioned host with an updater bundle.")
    include_self: bool = PydanticField(
        default=False,
        description="After a successful /update, also push /update-self to upgrade the updater itself.",
    )
    exclude: list[str] = PydanticField(
        default_factory=list,
        description="Additional tarball exclude globs (on top of the built-in defaults).",
    )


class PushUpdateResult(BaseModel):
    host_uuid: str
    host_name: str
    # updated = /update 200. rolled-back = /update 409 (auto-recovered).
    # failed = transport error or non-200/409 response. self-updated = /update-self succeeded.
    status: Literal["updated", "rolled-back", "failed", "self-updated", "self-failed"]
    http_status: Optional[int] = None
    sha: Optional[str] = None
    detail: Optional[str] = None
    stderr: Optional[str] = None


class PushUpdateResponse(BaseModel):
    sha: str
    tarball_bytes: int
    results: list[PushUpdateResult]


class RollbackRequest(BaseModel):
    host_uuid: str = PydanticField(..., description="Host to roll back to its previous release slot.")


class RollbackResponse(BaseModel):
    host_uuid: str
    host_name: str
    status: Literal["rolled-back", "failed"]
    http_status: Optional[int] = None
    detail: Optional[str] = None
