"""Master-side HTTP client for the worker's self-updater daemon.

Sibling of ``AgentClient``: same mTLS identity (same DECNET CA, same
master client cert) but targets the updater's port (default 8766) and
speaks the multipart upload protocol the updater's ``/update`` endpoint
expects.

Kept as its own module — not a subclass of ``AgentClient`` — because the
timeouts and failure semantics are genuinely different: pip install +
agent probe can take a minute on a slow VM, and ``/update-self`` drops
the connection on purpose (the updater re-execs itself mid-response).
"""
from __future__ import annotations

import ssl
from typing import Any, Optional

import httpx

from decnet.logging import get_logger
from decnet.swarm.client import MasterIdentity, ensure_master_identity

log = get_logger("swarm.updater_client")

_TIMEOUT_UPDATE = httpx.Timeout(connect=10.0, read=180.0, write=120.0, pool=5.0)
_TIMEOUT_CONTROL = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)


class UpdaterClient:
    """Async client targeting a worker's ``decnet updater`` daemon."""

    def __init__(
        self,
        host: dict[str, Any] | None = None,
        *,
        address: Optional[str] = None,
        updater_port: int = 8766,
        identity: Optional[MasterIdentity] = None,
    ):
        if host is not None:
            self._address = host["address"]
            self._host_name = host.get("name")
        else:
            if address is None:
                raise ValueError("UpdaterClient requires host dict or address")
            self._address = address
            self._host_name = None
        self._port = updater_port
        self._identity = identity or ensure_master_identity()
        self._client: Optional[httpx.AsyncClient] = None

    def _build_client(self, timeout: httpx.Timeout) -> httpx.AsyncClient:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            str(self._identity.cert_path), str(self._identity.key_path),
        )
        ctx.load_verify_locations(cafile=str(self._identity.ca_cert_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        return httpx.AsyncClient(
            base_url=f"https://{self._address}:{self._port}",
            verify=ctx,
            timeout=timeout,
        )

    async def __aenter__(self) -> "UpdaterClient":
        self._client = self._build_client(_TIMEOUT_CONTROL)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _require(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("UpdaterClient used outside `async with` block")
        return self._client

    # --------------------------------------------------------------- RPCs

    async def health(self) -> dict[str, Any]:
        r = await self._require().get("/health")
        r.raise_for_status()
        return r.json()

    async def releases(self) -> dict[str, Any]:
        r = await self._require().get("/releases")
        r.raise_for_status()
        return r.json()

    async def update(self, tarball: bytes, sha: str = "") -> httpx.Response:
        """POST /update. Returns the Response so the caller can distinguish
        200 / 409 / 500 — each means something different.
        """
        self._require().timeout = _TIMEOUT_UPDATE
        try:
            r = await self._require().post(
                "/update",
                files={"tarball": ("tree.tgz", tarball, "application/gzip")},
                data={"sha": sha},
            )
        finally:
            self._require().timeout = _TIMEOUT_CONTROL
        return r

    async def update_self(self, tarball: bytes, sha: str = "") -> httpx.Response:
        """POST /update-self. The updater re-execs itself, so the connection
        usually drops mid-response; that's not an error. Callers should then
        poll /health until the new SHA appears.
        """
        self._require().timeout = _TIMEOUT_UPDATE
        try:
            r = await self._require().post(
                "/update-self",
                files={"tarball": ("tree.tgz", tarball, "application/gzip")},
                data={"sha": sha, "confirm_self": "true"},
            )
        finally:
            self._require().timeout = _TIMEOUT_CONTROL
        return r

    async def rollback(self) -> httpx.Response:
        return await self._require().post("/rollback")
