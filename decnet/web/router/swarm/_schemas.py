"""Request/response models shared across the swarm router endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from decnet.config import DecnetConfig


class EnrollRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    address: str = Field(..., description="IP or DNS the master uses to reach the worker")
    agent_port: int = Field(default=8765, ge=1, le=65535)
    sans: list[str] = Field(
        default_factory=list,
        description="Extra SANs (IPs / hostnames) to embed in the worker cert",
    )
    notes: Optional[str] = None


class EnrolledBundle(BaseModel):
    """Cert bundle returned to the operator — must be delivered to the worker."""

    host_uuid: str
    name: str
    address: str
    agent_port: int
    fingerprint: str
    ca_cert_pem: str
    worker_cert_pem: str
    worker_key_pem: str


class SwarmHostView(BaseModel):
    uuid: str
    name: str
    address: str
    agent_port: int
    status: str
    last_heartbeat: Optional[datetime] = None
    client_cert_fingerprint: str
    enrolled_at: datetime
    notes: Optional[str] = None


class DeployRequest(BaseModel):
    config: DecnetConfig
    dry_run: bool = False
    no_cache: bool = False


class TeardownRequest(BaseModel):
    host_uuid: str | None = Field(
        default=None,
        description="If set, tear down only this worker; otherwise tear down all hosts",
    )
    decky_id: str | None = None


class HostResult(BaseModel):
    host_uuid: str
    host_name: str
    ok: bool
    detail: Any | None = None


class DeployResponse(BaseModel):
    results: list[HostResult]


class HostHealth(BaseModel):
    host_uuid: str
    name: str
    address: str
    reachable: bool
    detail: Any | None = None


class CheckResponse(BaseModel):
    results: list[HostHealth]
