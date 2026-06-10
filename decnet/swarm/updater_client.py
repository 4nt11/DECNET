# SPDX-License-Identifier: AGPL-3.0-or-later
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

import asyncio
import hashlib
import socket
import ssl
from typing import Any, Optional

import httpx

from decnet.logging import get_logger
from decnet.swarm.client import (
    FingerprintMismatchError,
    MasterIdentity,
    ensure_master_identity,
)

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
        verify_hostname: Optional[bool] = None,
    ):
        if verify_hostname is None:
            from decnet.env import DECNET_VERIFY_HOSTNAME
            verify_hostname = DECNET_VERIFY_HOSTNAME
        self._verify_hostname = verify_hostname
        if host is not None:
            self._address = host["address"]
            self._host_name = host.get("name")
            # SHA-256 of the worker's UPDATER leaf cert, recorded at enroll
            # time (api_enroll_host.py writes ``updater_cert_fingerprint``).
            # This is a distinct identity from the agent cert AgentClient
            # pins — the updater channel pip-installs code as root, so it
            # gets its own pin against its own cert.
            fp = host.get("updater_cert_fingerprint")
            self._expected_fingerprint = fp.lower() if isinstance(fp, str) else None
        else:
            if address is None:
                raise ValueError("UpdaterClient requires host dict or address")
            self._address = address
            self._host_name = None
            self._expected_fingerprint = None
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
        ctx.check_hostname = self._verify_hostname
        return httpx.AsyncClient(
            base_url=f"https://{self._address}:{self._port}",
            verify=ctx,
            timeout=timeout,
        )

    def _fetch_peer_fingerprint(self) -> str:
        """Open a throwaway TLS connection to the updater port and return the
        SHA-256 hex of the leaf cert it presents. Mirrors
        ``AgentClient._fetch_peer_fingerprint`` exactly."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            str(self._identity.cert_path), str(self._identity.key_path),
        )
        ctx.load_verify_locations(cafile=str(self._identity.ca_cert_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = self._verify_hostname
        sock = socket.create_connection((self._address, self._port), timeout=10.0)
        try:
            server_hostname = self._address if self._verify_hostname else None
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        if not der:
            raise FingerprintMismatchError(
                f"{self._address}:{self._port}", self._expected_fingerprint or "", ""
            )
        return hashlib.sha256(der).hexdigest().lower()

    async def _verify_pin(self) -> None:
        """Fail closed unless the updater leaf cert SHA-256 matches the pin.

        Unlike ``AgentClient`` (which falls through to CA-only when no pin is
        recorded), the updater channel pip-installs code as root — so a host
        with NO recorded ``updater_cert_fingerprint`` is rejected outright
        rather than accepted on CA validity alone. A missing pin means the
        host was never enrolled with an updater identity; we refuse to drive
        code into it."""
        if not self._expected_fingerprint:
            raise FingerprintMismatchError(
                f"{self._address}:{self._port}",
                "<no updater_cert_fingerprint recorded for host>",
                "",
            )
        actual = await asyncio.to_thread(self._fetch_peer_fingerprint)
        if actual != self._expected_fingerprint:
            raise FingerprintMismatchError(
                f"{self._address}:{self._port}",
                self._expected_fingerprint,
                actual,
            )

    async def __aenter__(self) -> "UpdaterClient":
        self._client = self._build_client(_TIMEOUT_CONTROL)
        try:
            await self._verify_pin()
        except BaseException:
            await self._client.aclose()
            self._client = None
            raise
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
        sha256 = hashlib.sha256(tarball).hexdigest()
        self._require().timeout = _TIMEOUT_UPDATE
        try:
            r = await self._require().post(
                "/update",
                files={"tarball": ("tree.tgz", tarball, "application/gzip")},
                data={"sha": sha, "sha256": sha256},
            )
        finally:
            self._require().timeout = _TIMEOUT_CONTROL
        return r

    async def update_self(self, tarball: bytes, sha: str = "") -> httpx.Response:
        """POST /update-self. The updater re-execs itself, so the connection
        usually drops mid-response; that's not an error. Callers should then
        poll /health until the new SHA appears.
        """
        sha256 = hashlib.sha256(tarball).hexdigest()
        self._require().timeout = _TIMEOUT_UPDATE
        try:
            r = await self._require().post(
                "/update-self",
                files={"tarball": ("tree.tgz", tarball, "application/gzip")},
                data={"sha": sha, "sha256": sha256, "confirm_self": "true"},
            )
        finally:
            self._require().timeout = _TIMEOUT_CONTROL
        return r

    async def rollback(self) -> httpx.Response:
        return await self._require().post("/rollback")
