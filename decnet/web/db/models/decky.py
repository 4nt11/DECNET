"""DTOs for cross-cutting decky operations (file drops, etc.).

These don't bind to a single table — fleet deckies and MazeNET
(topology) deckies share the request shape, with ``topology_id``
discriminating.  Following ``feedback_models_single_source`` we put
the request/response shapes alongside the rest of the API contracts
under ``decnet.web.db.models``.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field as PydanticField, field_validator


class DeckyFileDropRequest(BaseModel):
    """Drop arbitrary bytes at an absolute path inside a decky container.

    ``content_b64`` is the base64-encoded payload.  Binary-safe.

    ``mode`` defaults to ``0o644`` (octal int).  ``mtime_offset`` is a
    seconds offset from now applied via ``touch -d`` so realistic-aged
    files don't all stamp at wall-clock-now.
    """
    decky_name: str = PydanticField(..., min_length=1)
    topology_id: Optional[str] = None
    path: str = PydanticField(..., min_length=1)
    content_b64: str
    mode: int = 0o644
    mtime_offset: int = 0

    @field_validator("path")
    @classmethod
    def _abs_no_traversal(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path must be absolute (start with '/')")
        # Defense in depth: even though we run as root inside the
        # container, ``..`` segments make the on-disk location depend
        # on the cwd at exec-time and surprise both operators and the
        # auditor reading the placement_path field later.
        for seg in v.split("/"):
            if seg == "..":
                raise ValueError("path must not contain '..' segments")
        return v


class DeckyServiceAddRequest(BaseModel):
    """Add a single service to an already-deployed decky.

    The service must be registered (see :mod:`decnet.services.registry`)
    and must NOT be ``fleet_singleton`` — those run once fleet-wide,
    not per-decky.  Validation happens server-side in the engine layer
    and surfaces as 422.

    ``config`` carries optional initial per-service config (same shape as
    DeckyServiceConfigRequest.config) so the freshly-added container
    comes up with the operator's env from the start, no follow-up Apply
    needed.  Empty dict = build with defaults.
    """
    name: str = PydanticField(..., min_length=1)
    config: dict[str, Any] = PydanticField(default_factory=dict)


class DeckyServicesResponse(BaseModel):
    """Post-mutation services list, returned by the live add/remove API.

    Lets the dashboard reflect the new shape without a follow-up GET.
    """
    decky_name: str
    topology_id: Optional[str] = None
    services: list[str]


class ServiceConfigFieldDTO(BaseModel):
    """Serialized form of ``decnet.services.base.ServiceConfigField``.

    The Inspector form (Fleet + MazeNET) renders inputs from this metadata.
    """
    key: str
    label: str
    type: str
    default: Optional[Any] = None
    secret: bool = False
    help: Optional[str] = None
    enum: Optional[list[str]] = None
    placeholder: Optional[str] = None


class ServiceSchemaResponse(BaseModel):
    """Per-service config schema returned by GET /services/{name}/schema."""
    name: str
    ports: list[int]
    fleet_singleton: bool = False
    fields: list[ServiceConfigFieldDTO] = PydanticField(default_factory=list)


class DeckyServiceConfigRequest(BaseModel):
    """Body for PUT/POST per-service config endpoints.

    The dict is validated against the service's ``config_schema``
    server-side: unknown keys are silently dropped, declared keys are
    coerced to their declared type, and out-of-range values raise 400.
    """
    config: dict[str, Any] = PydanticField(default_factory=dict)


class DeckyServiceConfigResponse(BaseModel):
    """Post-validation config + apply state for the form to re-sync from."""
    decky_name: str
    service_name: str
    topology_id: Optional[str] = None
    config: dict[str, Any] = PydanticField(default_factory=dict)
    recreated: bool = False


class DeckyFileDeleteRequest(BaseModel):
    """Best-effort ``rm -f`` of an absolute path inside a decky container."""
    decky_name: str = PydanticField(..., min_length=1)
    topology_id: Optional[str] = None
    path: str = PydanticField(..., min_length=1)

    @field_validator("path")
    @classmethod
    def _abs_no_traversal(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path must be absolute (start with '/')")
        for seg in v.split("/"):
            if seg == "..":
                raise ValueError("path must not contain '..' segments")
        return v
