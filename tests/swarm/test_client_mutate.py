"""Roundtrip test for AgentClient.mutate() through a live in-process
agent over mTLS.  Mirrors test_client_agent_roundtrip's harness."""
from __future__ import annotations

import asyncio
import pathlib
import socket
import threading
import time

import pytest
import uvicorn

from decnet.agent.app import app as agent_app
from decnet.config import DeckyConfig, DecnetConfig
from decnet.swarm import client as swarm_client
from decnet.swarm import pki


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_agent(tmp_path: pathlib.Path, port: int):
    ca_dir = tmp_path / "ca"
    pki.ensure_ca(ca_dir)
    worker_dir = tmp_path / "agent"
    pki.write_worker_bundle(
        pki.issue_worker_cert(pki.load_ca(ca_dir), "worker-test", ["127.0.0.1"]),
        worker_dir,
    )
    master_id = swarm_client.ensure_master_identity(ca_dir)
    config = uvicorn.Config(
        agent_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        ssl_keyfile=str(worker_dir / "worker.key"),
        ssl_certfile=str(worker_dir / "worker.crt"),
        ssl_ca_certs=str(worker_dir / "ca.crt"),
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
    deadline = time.time() + 5
    while time.time() < deadline:
        if server.started:
            return server, thread, master_id
        time.sleep(0.05)
    raise RuntimeError("agent did not start within 5s")


@pytest.mark.asyncio
async def test_client_mutate_dry_run_roundtrip(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drive the real agent /mutate handler over mTLS in dry_run mode so we
    don't need docker. Asserts that the client POSTs the right body and
    parses the worker's response.
    """
    cfg = DecnetConfig(
        mode="swarm",
        interface="eth0",
        subnet="10.66.0.0/24",
        gateway="10.66.0.1",
        deckies=[
            DeckyConfig(
                name="decky-01",
                ip="10.66.0.10",
                services=["ssh"],
                distro="debian",
                base_image="debian:bookworm-slim",
                hostname="d01",
            ),
        ],
    )
    monkeypatch.setattr(
        "decnet.config.load_state",
        lambda: (cfg, tmp_path / "decnet-compose.yml"),
    )

    port = _free_port()
    server, thread, master_id = _start_agent(tmp_path, port)
    try:
        async with swarm_client.AgentClient(
            address="127.0.0.1", agent_port=port, identity=master_id,
        ) as agent:
            body = await agent.mutate(
                "decky-01", ["http", "ftp"], dry_run=True,
            )
        assert body == {
            "status": "dry_run",
            "decky_id": "decky-01",
            "services": ["http", "ftp"],
        }
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_client_mutate_unknown_decky_404(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = DecnetConfig(
        mode="swarm",
        interface="eth0",
        subnet="10.66.0.0/24",
        gateway="10.66.0.1",
        deckies=[
            DeckyConfig(
                name="decky-01",
                ip="10.66.0.10",
                services=["ssh"],
                distro="debian",
                base_image="debian:bookworm-slim",
                hostname="d01",
            ),
        ],
    )
    monkeypatch.setattr(
        "decnet.config.load_state",
        lambda: (cfg, tmp_path / "decnet-compose.yml"),
    )

    port = _free_port()
    server, thread, master_id = _start_agent(tmp_path, port)
    try:
        import httpx
        async with swarm_client.AgentClient(
            address="127.0.0.1", agent_port=port, identity=master_id,
        ) as agent:
            # Only dry_run can surface 404 synchronously; the live path is
            # 202 fire-and-forget and would surface failure via the
            # heartbeat lifecycle delta.
            with pytest.raises(httpx.HTTPStatusError) as ei:
                await agent.mutate("ghost", ["ssh"], dry_run=True)
            assert ei.value.response.status_code == 404
    finally:
        server.should_exit = True
        thread.join(timeout=5)
