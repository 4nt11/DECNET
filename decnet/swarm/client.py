"""Master-side HTTP client that talks to a worker's DECNET agent.

All traffic is mTLS: the master presents a cert issued by its own CA (which
workers trust) and the master validates the worker's cert against the same
CA.  In practice the "client cert" the master shows is just another cert
signed by itself — the master is both the CA and the sole control-plane
client.

Usage:

    async with AgentClient(host) as agent:
        await agent.deploy(config)
        status = await agent.status()

The ``host`` is a SwarmHost dict returned by the repository.
"""
from __future__ import annotations

import pathlib
import ssl
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from decnet.config import DecnetConfig
from decnet.logging import get_logger
from decnet.swarm import pki

log = get_logger("swarm.client")

# How long a single HTTP operation can take.  Deploy is the long pole —
# docker compose up pulls images, builds contexts, etc.  Tune via env in a
# later iteration if the default proves too short.
_TIMEOUT_DEPLOY = httpx.Timeout(connect=10.0, read=600.0, write=30.0, pool=5.0)
_TIMEOUT_CONTROL = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
# Topology apply pulls images + runs compose on the agent — same ball-park
# as a fleet deploy.  Teardown is faster but still long enough we can't
# reuse the control timeout.
_TIMEOUT_TOPOLOGY_APPLY = httpx.Timeout(connect=10.0, read=600.0, write=30.0, pool=5.0)
_TIMEOUT_TOPOLOGY_TEARDOWN = httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=5.0)


@dataclass(frozen=True)
class MasterIdentity:
    """Paths to the master's own mTLS client bundle.

    The master uses ONE master-client cert to talk to every worker.  It is
    signed by the DECNET CA (same CA that signs worker certs).  Stored
    under ``~/.decnet/ca/master/`` by ``ensure_master_identity``.
    """
    key_path: pathlib.Path
    cert_path: pathlib.Path
    ca_cert_path: pathlib.Path


def ensure_master_identity(
    ca_dir: pathlib.Path = pki.DEFAULT_CA_DIR,
) -> MasterIdentity:
    """Create (or load) the master's own client cert.

    Called once by the swarm controller on startup and by the CLI before
    any master→worker call.  Idempotent.
    """
    ca = pki.ensure_ca(ca_dir)
    master_dir = ca_dir / "master"
    bundle = pki.load_worker_bundle(master_dir)
    if bundle is None:
        issued = pki.issue_worker_cert(ca, "decnet-master", ["127.0.0.1", "decnet-master"])
        pki.write_worker_bundle(issued, master_dir)
    return MasterIdentity(
        key_path=master_dir / "worker.key",
        cert_path=master_dir / "worker.crt",
        ca_cert_path=master_dir / "ca.crt",
    )


class AgentClient:
    """Thin async wrapper around the worker agent's HTTP API."""

    def __init__(
        self,
        host: dict[str, Any] | None = None,
        *,
        address: Optional[str] = None,
        agent_port: Optional[int] = None,
        identity: Optional[MasterIdentity] = None,
        verify_hostname: bool = False,
    ):
        """Either pass a SwarmHost dict, or explicit address/port.

        ``verify_hostname`` stays False by default because the worker's
        cert SAN is populated from the operator-supplied address list, not
        from modern TLS hostname-verification semantics.  The mTLS client
        cert + CA pinning are what authenticate the peer.
        """
        if host is not None:
            self._address = host["address"]
            self._port = int(host.get("agent_port") or 8765)
            self._host_uuid = host.get("uuid")
            self._host_name = host.get("name")
        else:
            if address is None or agent_port is None:
                raise ValueError(
                    "AgentClient requires either a host dict or address+agent_port"
                )
            self._address = address
            self._port = int(agent_port)
            self._host_uuid = None
            self._host_name = None

        self._identity = identity or ensure_master_identity()
        self._verify_hostname = verify_hostname
        self._client: Optional[httpx.AsyncClient] = None

    # --------------------------------------------------------------- lifecycle

    def _build_client(self, timeout: httpx.Timeout) -> httpx.AsyncClient:
        # Build the SSL context manually — httpx.create_ssl_context layers on
        # purpose/ALPN/default-CA logic that doesn't compose with private-CA
        # mTLS in all combinations.  A bare SSLContext is predictable.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            str(self._identity.cert_path), str(self._identity.key_path)
        )
        ctx.load_verify_locations(cafile=str(self._identity.ca_cert_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Pin by CA + cert chain, not by DNS — workers enroll with arbitrary
        # SANs (IPs, hostnames) and we don't want to force operators to keep
        # those in sync with whatever URL the master happens to use.
        ctx.check_hostname = self._verify_hostname
        return httpx.AsyncClient(
            base_url=f"https://{self._address}:{self._port}",
            verify=ctx,
            timeout=timeout,
        )

    async def __aenter__(self) -> "AgentClient":
        self._client = self._build_client(_TIMEOUT_CONTROL)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("AgentClient used outside `async with` block")
        return self._client

    # ----------------------------------------------------------------- RPCs

    async def health(self) -> dict[str, Any]:
        resp = await self._require_client().get("/health")
        resp.raise_for_status()
        return resp.json()

    async def status(self) -> dict[str, Any]:
        resp = await self._require_client().get("/status")
        resp.raise_for_status()
        return resp.json()

    async def deploy(
        self,
        config: DecnetConfig,
        *,
        dry_run: bool = False,
        no_cache: bool = False,
    ) -> dict[str, Any]:
        body = {
            "config": config.model_dump(mode="json"),
            "dry_run": dry_run,
            "no_cache": no_cache,
        }
        # Swap in a long-deploy timeout for this call only.
        old = self._require_client().timeout
        self._require_client().timeout = _TIMEOUT_DEPLOY
        try:
            resp = await self._require_client().post("/deploy", json=body)
        finally:
            self._require_client().timeout = old
        resp.raise_for_status()
        return resp.json()

    async def teardown(self, decky_id: Optional[str] = None) -> dict[str, Any]:
        resp = await self._require_client().post(
            "/teardown", json={"decky_id": decky_id}
        )
        resp.raise_for_status()
        return resp.json()

    async def self_destruct(self) -> dict[str, Any]:
        """Trigger the worker to stop services and wipe its install."""
        resp = await self._require_client().post("/self-destruct")
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------ topology

    async def apply_topology(
        self,
        hydrated: dict[str, Any],
        version_hash: str,
    ) -> dict[str, Any]:
        """Push a hydrated topology to the agent for local materialisation.

        The agent independently computes ``canonical_hash(hydrated)`` and
        returns 400 if it disagrees with *version_hash* — that's how we
        catch serialisation drift before half-creating bridges.
        """
        old = self._require_client().timeout
        self._require_client().timeout = _TIMEOUT_TOPOLOGY_APPLY
        try:
            resp = await self._require_client().post(
                "/topology/apply",
                json={"hydrated": hydrated, "version_hash": version_hash},
            )
        finally:
            self._require_client().timeout = old
        resp.raise_for_status()
        return resp.json()

    async def teardown_topology(self, topology_id: str) -> dict[str, Any]:
        """Ask the agent to dismantle the named topology."""
        old = self._require_client().timeout
        self._require_client().timeout = _TIMEOUT_TOPOLOGY_TEARDOWN
        try:
            resp = await self._require_client().post(
                "/topology/teardown",
                json={"topology_id": topology_id},
            )
        finally:
            self._require_client().timeout = old
        resp.raise_for_status()
        return resp.json()

    async def get_topology_state(self) -> dict[str, Any]:
        """Snapshot of the agent's applied topology + live docker state."""
        resp = await self._require_client().get("/topology/state")
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------- diagnostics

    def __repr__(self) -> str:
        return (
            f"AgentClient(name={self._host_name!r}, "
            f"address={self._address!r}, port={self._port})"
        )
