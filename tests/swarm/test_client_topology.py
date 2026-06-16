# SPDX-License-Identifier: AGPL-3.0-or-later
"""AgentClient topology methods — unit tests with a mock httpx transport.

Avoids the full uvicorn+mTLS setup used by the roundtrip test; we just
need to prove the client emits the right verb/path/body and surfaces
HTTP errors the way the caller expects.
"""
from __future__ import annotations

import json

import httpx
import pytest

from decnet.swarm.client import AgentClient, MasterIdentity


class _StubIdentity:
    """Satisfies the MasterIdentity shape without requiring real files."""


def _client_with_transport(handler) -> AgentClient:
    """Build an AgentClient whose internal httpx client is backed by
    :class:`httpx.MockTransport`.  Bypasses _build_client so no real
    cert IO happens."""
    identity = MasterIdentity(
        key_path="/nope/key",  # type: ignore[arg-type]
        cert_path="/nope/cert",  # type: ignore[arg-type]
        ca_cert_path="/nope/ca",  # type: ignore[arg-type]
    )
    client = AgentClient(
        address="127.0.0.1",
        agent_port=8765,
        identity=identity,
    )
    client._client = httpx.AsyncClient(
        base_url="https://127.0.0.1:8765",
        transport=httpx.MockTransport(handler),
    )
    return client


@pytest.mark.anyio
async def test_apply_topology_sends_body() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"status": "applied", "version_hash": "h"}
        )

    agent = _client_with_transport(handler)
    try:
        out = await agent.apply_topology({"topology": {"id": "t1"}}, "h")
    finally:
        await agent._client.aclose()

    assert out == {"status": "applied", "version_hash": "h"}
    assert captured["url"].endswith("/topology/apply")
    assert captured["body"] == {
        "hydrated": {"topology": {"id": "t1"}},
        "version_hash": "h",
    }


@pytest.mark.anyio
async def test_apply_topology_raises_on_409() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": "already applied"})

    agent = _client_with_transport(handler)
    try:
        with pytest.raises(httpx.HTTPStatusError) as ei:
            await agent.apply_topology({"topology": {"id": "t2"}}, "h")
        assert ei.value.response.status_code == 409
    finally:
        await agent._client.aclose()


@pytest.mark.anyio
async def test_teardown_topology_sends_body() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"status": "torn_down", "topology_id": "t1"})

    agent = _client_with_transport(handler)
    try:
        out = await agent.teardown_topology("t1")
    finally:
        await agent._client.aclose()

    assert out["status"] == "torn_down"
    assert captured["body"] == {"topology_id": "t1"}
    assert captured["url"].endswith("/topology/teardown")


@pytest.mark.anyio
async def test_get_topology_state_returns_snapshot() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(
            200,
            json={
                "topology_id": "t1",
                "applied_version_hash": "h",
                "applied_at": 1,
                "last_error": None,
                "observed": {"bridges": [], "containers": []},
            },
        )

    agent = _client_with_transport(handler)
    try:
        snap = await agent.get_topology_state()
    finally:
        await agent._client.aclose()
    assert snap["topology_id"] == "t1"
    assert snap["applied_version_hash"] == "h"
