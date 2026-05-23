# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end test: AgentClient talks to a live worker agent over mTLS.

Spins up uvicorn in-process on an ephemeral port with real cert files on
disk.  Confirms:

1. The health endpoint works when the client presents a CA-signed cert.
2. An impostor client (cert signed by a different CA) is rejected at TLS
   time.
"""
from __future__ import annotations

import asyncio
import pathlib
import socket
import threading
import time

import ssl

import httpx
import pytest
import uvicorn

from decnet.agent.app import app as agent_app
from decnet.swarm import client as swarm_client
from decnet.swarm import pki


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_agent(
    tmp_path: pathlib.Path, port: int
) -> tuple[uvicorn.Server, threading.Thread, swarm_client.MasterIdentity]:
    """Provision a CA, sign a worker cert + a master cert, start uvicorn."""
    ca_dir = tmp_path / "ca"
    pki.ensure_ca(ca_dir)

    # Worker bundle
    worker_dir = tmp_path / "agent"
    pki.write_worker_bundle(
        pki.issue_worker_cert(pki.load_ca(ca_dir), "worker-test", ["127.0.0.1"]),
        worker_dir,
    )

    # Master identity (used by AgentClient as a client cert)
    master_id = swarm_client.ensure_master_identity(ca_dir)

    config = uvicorn.Config(
        agent_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        ssl_keyfile=str(worker_dir / "worker.key"),
        ssl_certfile=str(worker_dir / "worker.crt"),
        ssl_ca_certs=str(worker_dir / "ca.crt"),
        # 2 == ssl.CERT_REQUIRED
        ssl_cert_reqs=2,
    )
    server = uvicorn.Server(config)

    def _run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.serve())
        loop.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    # Wait for server to be listening
    deadline = time.time() + 5
    while time.time() < deadline:
        if server.started:
            return server, thread, master_id
        time.sleep(0.05)
    raise RuntimeError("agent did not start within 5s")


@pytest.mark.asyncio
async def test_client_health_roundtrip(tmp_path: pathlib.Path) -> None:
    port = _free_port()
    server, thread, master_id = _start_agent(tmp_path, port)
    try:
        async with swarm_client.AgentClient(
            address="127.0.0.1", agent_port=port, identity=master_id
        ) as agent:
            body = await agent.health()
            assert body == {"status": "ok"}
            snap = await agent.status()
            assert "deployed" in snap
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_fingerprint_pin_accepts_matching_cert(tmp_path: pathlib.Path) -> None:
    """AgentClient with the correct expected fingerprint connects normally."""
    port = _free_port()
    server, thread, master_id = _start_agent(tmp_path, port)
    try:
        worker_cert_pem = (tmp_path / "agent" / "worker.crt").read_bytes()
        expected = pki.fingerprint(worker_cert_pem)
        host = {
            "uuid": "h1",
            "name": "worker-test",
            "address": "127.0.0.1",
            "agent_port": port,
            "client_cert_fingerprint": expected,
        }
        async with swarm_client.AgentClient(host=host, identity=master_id) as agent:
            assert await agent.health() == {"status": "ok"}
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_fingerprint_pin_rejects_mismatch(tmp_path: pathlib.Path) -> None:
    """A wrong expected fingerprint must raise FingerprintMismatchError."""
    port = _free_port()
    server, thread, master_id = _start_agent(tmp_path, port)
    try:
        host = {
            "uuid": "h1",
            "name": "worker-test",
            "address": "127.0.0.1",
            "agent_port": port,
            "client_cert_fingerprint": "0" * 64,
        }
        with pytest.raises(swarm_client.FingerprintMismatchError):
            async with swarm_client.AgentClient(host=host, identity=master_id):
                pass
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_impostor_client_cannot_connect(tmp_path: pathlib.Path) -> None:
    """A client whose cert was issued by a DIFFERENT CA must be rejected."""
    port = _free_port()
    server, thread, _master_id = _start_agent(tmp_path, port)
    try:
        evil_ca = pki.generate_ca("Evil CA")
        evil_dir = tmp_path / "evil"
        pki.write_worker_bundle(
            pki.issue_worker_cert(evil_ca, "evil-master", ["127.0.0.1"]), evil_dir
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(str(evil_dir / "worker.crt"), str(evil_dir / "worker.key"))
        ctx.load_verify_locations(cafile=str(evil_dir / "ca.crt"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        async with httpx.AsyncClient(
            base_url=f"https://127.0.0.1:{port}", verify=ctx, timeout=5.0
        ) as ac:
            with pytest.raises(
                (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)
            ):
                await ac.get("/health")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
