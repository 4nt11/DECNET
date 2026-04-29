"""DTOs for cross-cutting decky operations (file drops, etc.).

These don't bind to a single table — fleet deckies and MazeNET
(topology) deckies share the request shape, with ``topology_id``
discriminating.  Following ``feedback_models_single_source`` we put
the request/response shapes alongside the rest of the API contracts
under ``decnet.web.db.models``.
"""
from __future__ import annotations

from typing import Optional

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
