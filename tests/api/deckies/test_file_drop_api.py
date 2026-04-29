"""End-to-end coverage for /api/v1/deckies/files via the live FastAPI app.

The docker subprocess is stubbed; everything else (DB, repo, auth)
runs for real.
"""
from __future__ import annotations

import asyncio
import base64
from unittest.mock import patch

import httpx
import pytest


_BASE = "/api/v1/deckies/files"


class _FakeProc:
    def __init__(self, rc: int = 0, stderr: bytes = b"") -> None:
        self.returncode = rc
        self._stderr = stderr

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return b"", self._stderr

    def kill(self) -> None:  # pragma: no cover
        pass


def _patch_subprocess_capture(rc: int = 0, stderr: bytes = b""):
    captured: list[list[str]] = []

    async def _fake(*argv, **kw):
        captured.append(list(argv))
        return _FakeProc(rc, stderr)

    return patch.object(asyncio, "create_subprocess_exec", _fake), captured


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _hydrate_returning(deckies: list[dict]):
    async def _fake(_repo, _topo_id):
        return {
            "topology": {"id": _topo_id},
            "lans": [], "edges": [], "deckies": deckies,
        }
    return _fake


# ---------------- POST: drop file -----------------------------------------


@pytest.mark.asyncio
async def test_drop_file_on_fleet_decky_uses_ssh_container(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    patcher, captured = _patch_subprocess_capture()
    body_b64 = base64.b64encode(b"hello world").decode()
    with patcher:
        res = await client.post(
            _BASE,
            json={
                "decky_name": "web1",
                "path": "/root/note.txt",
                "content_b64": body_b64,
            },
            headers=_hdr(auth_token),
        )
    assert res.status_code == 201, res.text
    # docker exec -i web1-ssh sh -c <script>
    assert captured and captured[0][3] == "web1-ssh"


@pytest.mark.asyncio
async def test_drop_file_on_topology_decky_with_ssh_service(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate",
        _hydrate_returning([{
            "uuid": "u1", "name": "web1",
            "decky_config": {"name": "web1"},
            "services": ["ssh", "http"],
        }]),
    )
    patcher, captured = _patch_subprocess_capture()
    with patcher:
        res = await client.post(
            _BASE,
            json={
                "decky_name": "web1",
                "topology_id": "abcdef0123456789",
                "path": "/etc/synthetic.conf",
                "content_b64": base64.b64encode(b"x").decode(),
            },
            headers=_hdr(auth_token),
        )
    assert res.status_code == 201, res.text
    assert captured[0][3] == "web1-ssh"


@pytest.mark.asyncio
async def test_drop_file_on_topology_decky_without_ssh_uses_base_container(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate",
        _hydrate_returning([{
            "uuid": "u1", "name": "router",
            "decky_config": {"name": "router"},
            "services": ["dns"],
        }]),
    )
    patcher, captured = _patch_subprocess_capture()
    with patcher:
        res = await client.post(
            _BASE,
            json={
                "decky_name": "router",
                "topology_id": "fedcba9876543210",
                "path": "/etc/synthetic.conf",
                "content_b64": base64.b64encode(b"x").decode(),
            },
            headers=_hdr(auth_token),
        )
    assert res.status_code == 201, res.text
    assert captured[0][3] == "decnet_t_fedcba98_router"


@pytest.mark.asyncio
async def test_drop_file_404_when_topology_unknown(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _none(_repo, _topo_id):
        return None
    monkeypatch.setattr("decnet.topology.persistence.hydrate", _none)
    res = await client.post(
        _BASE,
        json={
            "decky_name": "web1", "topology_id": "ghost",
            "path": "/etc/x.conf",
            "content_b64": base64.b64encode(b"x").decode(),
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_drop_file_422_for_relative_path(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.post(
        _BASE,
        json={
            "decky_name": "web1",
            "path": "etc/x.conf",
            "content_b64": base64.b64encode(b"x").decode(),
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_drop_file_422_for_traversal(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.post(
        _BASE,
        json={
            "decky_name": "web1",
            "path": "/etc/../root/.ssh/authorized_keys",
            "content_b64": base64.b64encode(b"x").decode(),
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_drop_file_400_on_bad_base64(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.post(
        _BASE,
        json={
            "decky_name": "web1",
            "path": "/etc/x.conf",
            "content_b64": "%%%not-base64%%%",
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_drop_file_409_when_docker_exec_fails(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    patcher, _captured = _patch_subprocess_capture(
        rc=1, stderr=b"container not running",
    )
    with patcher:
        res = await client.post(
            _BASE,
            json={
                "decky_name": "web1",
                "path": "/etc/x.conf",
                "content_b64": base64.b64encode(b"x").decode(),
            },
            headers=_hdr(auth_token),
        )
    assert res.status_code == 409


# ---------------- DELETE --------------------------------------------------


@pytest.mark.asyncio
async def test_delete_file_round_trip(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    patcher, captured = _patch_subprocess_capture()
    with patcher:
        res = await client.request(
            "DELETE", _BASE,
            json={"decky_name": "web1", "path": "/etc/x.conf"},
            headers=_hdr(auth_token),
        )
    assert res.status_code == 200, res.text
    # docker exec web1-ssh sh -c "rm -f /etc/x.conf"
    assert captured[0][2] == "web1-ssh"
    assert "rm -f /etc/x.conf" in captured[0][5]


# ---------------- auth ----------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_drop_rejected(
    client: httpx.AsyncClient,
) -> None:
    res = await client.post(_BASE, json={
        "decky_name": "web1", "path": "/x",
        "content_b64": base64.b64encode(b"x").decode(),
    })
    assert res.status_code in (401, 403)
