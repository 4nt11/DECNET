# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end coverage for /api/v1/canary/* via the live FastAPI app.

The planter's docker-exec call is patched so we don't need a real
docker daemon; everything else (DB, repo, instrumenters, generators,
storage) runs for real.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest


_BASE = "/api/v1/canary"


class _FakeProc:
    def __init__(self, rc: int = 0, stderr: bytes = b"") -> None:
        self.returncode = rc
        self._stderr = stderr

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return b"", self._stderr

    def kill(self) -> None:  # pragma: no cover
        pass


def _patch_subprocess(rc: int = 0, stderr: bytes = b""):
    async def _fake(*argv, **kw):  # noqa: ANN001
        return _FakeProc(rc, stderr)
    return patch.object(asyncio, "create_subprocess_exec", _fake)


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------- blob upload ---------------------------------------------


@pytest.mark.asyncio
async def test_blob_upload_dedupes(
    client: httpx.AsyncClient, auth_token: str, tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    files = {"file": ("notes.txt", b"hello canary", "text/plain")}
    res = await client.post(f"{_BASE}/blobs", files=files, headers=_hdr(auth_token))
    assert res.status_code == 201, res.text
    first = res.json()
    # Re-uploading the same bytes returns the same uuid.
    files2 = {"file": ("notes-rename.txt", b"hello canary", "text/plain")}
    res2 = await client.post(f"{_BASE}/blobs", files=files2, headers=_hdr(auth_token))
    assert res2.status_code == 201
    assert res2.json()["uuid"] == first["uuid"]


@pytest.mark.asyncio
async def test_blob_upload_rejects_empty(
    client: httpx.AsyncClient, auth_token: str, tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    files = {"file": ("empty.txt", b"", "text/plain")}
    res = await client.post(f"{_BASE}/blobs", files=files, headers=_hdr(auth_token))
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_blob_list_carries_token_count(
    client: httpx.AsyncClient, auth_token: str, tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    files = {"file": ("x.txt", b"some text", "text/plain")}
    blob = (await client.post(
        f"{_BASE}/blobs", files=files, headers=_hdr(auth_token),
    )).json()
    # Initially zero references.
    res = await client.get(f"{_BASE}/blobs", headers=_hdr(auth_token))
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1 and body["blobs"][0]["token_count"] == 0
    # Bind a token to bump the count.
    with _patch_subprocess(rc=0):
        tok_res = await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "web1", "kind": "http",
                "placement_path": "/etc/x.conf", "blob_uuid": blob["uuid"],
            },
            headers=_hdr(auth_token),
        )
    assert tok_res.status_code == 201, tok_res.text
    res = await client.get(f"{_BASE}/blobs", headers=_hdr(auth_token))
    assert res.json()["blobs"][0]["token_count"] == 1


@pytest.mark.asyncio
async def test_blob_delete_refuses_when_referenced(
    client: httpx.AsyncClient, auth_token: str, tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    files = {"file": ("x.txt", b"more text", "text/plain")}
    blob = (await client.post(
        f"{_BASE}/blobs", files=files, headers=_hdr(auth_token),
    )).json()
    with _patch_subprocess(rc=0):
        await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "web1", "kind": "http",
                "placement_path": "/etc/x.conf", "blob_uuid": blob["uuid"],
            },
            headers=_hdr(auth_token),
        )
    res = await client.delete(
        f"{_BASE}/blobs/{blob['uuid']}", headers=_hdr(auth_token),
    )
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_blob_delete_404_for_missing(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.delete(
        f"{_BASE}/blobs/00000000-0000-0000-0000-000000000000",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


# ---------------- token lifecycle ----------------------------------------


@pytest.mark.asyncio
async def test_create_token_requires_xor_blob_or_generator(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.post(
        f"{_BASE}/tokens",
        json={"decky_name": "w", "kind": "http", "placement_path": "/x"},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 400
    res = await client.post(
        f"{_BASE}/tokens",
        json={
            "decky_name": "w", "kind": "http", "placement_path": "/x",
            "generator": "aws_creds", "blob_uuid": "u",
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_create_token_rejects_relative_path(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.post(
        f"{_BASE}/tokens",
        json={
            "decky_name": "w", "kind": "http",
            "placement_path": "relative/path", "generator": "env_file",
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_create_token_with_unknown_generator(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.post(
        f"{_BASE}/tokens",
        json={
            "decky_name": "w", "kind": "http",
            "placement_path": "/x", "generator": "bogus",
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_create_token_with_missing_blob(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.post(
        f"{_BASE}/tokens",
        json={
            "decky_name": "w", "kind": "http",
            "placement_path": "/x",
            "blob_uuid": "00000000-0000-0000-0000-000000000000",
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_token_list_filter_by_decky(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    with _patch_subprocess(rc=0):
        for decky in ("web1", "web2"):
            await client.post(
                f"{_BASE}/tokens",
                json={
                    "decky_name": decky, "kind": "http",
                    "placement_path": "/x", "generator": "env_file",
                },
                headers=_hdr(auth_token),
            )
    res = await client.get(
        f"{_BASE}/tokens?decky_name=web1", headers=_hdr(auth_token),
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["tokens"][0]["decky_name"] == "web1"


@pytest.mark.asyncio
async def test_token_detail_404(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.get(
        f"{_BASE}/tokens/00000000-0000-0000-0000-000000000000",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_revoke_token_404(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.delete(
        f"{_BASE}/tokens/00000000-0000-0000-0000-000000000000",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_revoke_token_succeeds(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    with _patch_subprocess(rc=0):
        created = (await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "web1", "kind": "http",
                "placement_path": "/etc/x.env", "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )).json()
        res = await client.delete(
            f"{_BASE}/tokens/{created['uuid']}",
            headers=_hdr(auth_token),
        )
    assert res.status_code == 200, res.text
    detail = (await client.get(
        f"{_BASE}/tokens/{created['uuid']}", headers=_hdr(auth_token),
    )).json()
    assert detail["state"] == "revoked"


# ---------------- preview -------------------------------------------------


@pytest.mark.asyncio
async def test_preview_synthesised_token(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    with _patch_subprocess(rc=0):
        created = (await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "web1", "kind": "http",
                "placement_path": "/etc/x.env", "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )).json()
    res = await client.get(
        f"{_BASE}/tokens/{created['uuid']}/preview",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 200
    # Slug round-trips into the previewed bytes (env_file embeds it
    # in API_BASE_URL).
    assert created["callback_token"].encode() in res.content


@pytest.mark.asyncio
async def test_preview_404(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    res = await client.get(
        f"{_BASE}/tokens/00000000-0000-0000-0000-000000000000/preview",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


# ---------------- triggers list ------------------------------------------


@pytest.mark.asyncio
async def test_triggers_list_for_token(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    with _patch_subprocess(rc=0):
        created = (await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "web1", "kind": "http",
                "placement_path": "/etc/x.env", "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )).json()
    # No triggers yet.
    res = await client.get(
        f"{_BASE}/tokens/{created['uuid']}/triggers",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 200
    assert res.json()["total"] == 0
    # 404 for a missing token.
    res = await client.get(
        f"{_BASE}/tokens/00000000-0000-0000-0000-000000000000/triggers",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


# ---------------- topology (MazeNET) deckies ------------------------------


def _patch_subprocess_capture():
    """Subprocess patcher that records argv for assertion in tests."""
    captured: list[list[str]] = []

    async def _fake(*argv, **kw):  # noqa: ANN001
        captured.append(list(argv))
        return _FakeProc(rc=0)

    return patch.object(asyncio, "create_subprocess_exec", _fake), captured


def _hydrate_returning(deckies: list[dict]):
    async def _fake_hydrate(_repo, _topology_id):
        return {
            "topology": {"id": _topology_id},
            "lans": [],
            "deckies": deckies,
            "edges": [],
        }
    return _fake_hydrate


@pytest.mark.asyncio
async def test_create_token_on_topology_decky_with_ssh_resolves_ssh_container(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    topo_id = "abcdef0123456789"
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
            f"{_BASE}/tokens",
            json={
                "decky_name": "web1",
                "topology_id": topo_id,
                "kind": "http",
                "placement_path": "/etc/canary.env",
                "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["topology_id"] == topo_id
    # docker exec -i <container> sh -c <script>
    assert captured and captured[0][3] == "web1-ssh"


@pytest.mark.asyncio
async def test_create_token_on_topology_decky_without_ssh_uses_base_container(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    topo_id = "fedcba9876543210"
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
            f"{_BASE}/tokens",
            json={
                "decky_name": "router",
                "topology_id": topo_id,
                "kind": "http",
                "placement_path": "/etc/canary.env",
                "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )
    assert res.status_code == 201, res.text
    assert captured[0][3] == "decnet_t_fedcba98_router"


@pytest.mark.asyncio
async def test_create_token_404_when_topology_unknown(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _no_topology(_repo, _topology_id):
        return None
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate", _no_topology,
    )
    res = await client.post(
        f"{_BASE}/tokens",
        json={
            "decky_name": "web1",
            "topology_id": "ghost",
            "kind": "http",
            "placement_path": "/x.env",
            "generator": "env_file",
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_create_token_422_when_decky_not_in_topology(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate",
        _hydrate_returning([{
            "uuid": "u1", "name": "other",
            "decky_config": {"name": "other"},
            "services": [],
        }]),
    )
    res = await client.post(
        f"{_BASE}/tokens",
        json={
            "decky_name": "web1",
            "topology_id": "abcdef0123456789",
            "kind": "http",
            "placement_path": "/x.env",
            "generator": "env_file",
        },
        headers=_hdr(auth_token),
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_revoke_token_re_resolves_container_from_topology_id(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    topo_id = "11112222333344445555"
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate",
        _hydrate_returning([{
            "uuid": "u1", "name": "router",
            "decky_config": {"name": "router"},
            "services": [],
        }]),
    )
    # Create the token on a topology decky.
    create_patcher, _ = _patch_subprocess_capture()
    with create_patcher:
        res = await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "router",
                "topology_id": topo_id,
                "kind": "http",
                "placement_path": "/x.env",
                "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )
    assert res.status_code == 201
    token = res.json()
    # Revoke and assert the captured argv targets the topology base
    # container, not <name>-ssh.
    revoke_patcher, captured = _patch_subprocess_capture()
    with revoke_patcher:
        rev = await client.delete(
            f"{_BASE}/tokens/{token['uuid']}", headers=_hdr(auth_token),
        )
    assert rev.status_code == 200, rev.text
    assert captured and captured[0][2] == "decnet_t_11112222_router"


@pytest.mark.asyncio
async def test_list_tokens_filters_by_topology_id(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    topo_id = "topotopotopotopo"
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate",
        _hydrate_returning([{
            "uuid": "u1", "name": "web1",
            "decky_config": {"name": "web1"},
            "services": ["ssh"],
        }]),
    )
    # Create one fleet token (no topology_id) and one topology token.
    with _patch_subprocess(rc=0):
        await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "fleet1", "kind": "http",
                "placement_path": "/etc/a.env", "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )
        await client.post(
            f"{_BASE}/tokens",
            json={
                "decky_name": "web1", "topology_id": topo_id,
                "kind": "http", "placement_path": "/etc/b.env",
                "generator": "env_file",
            },
            headers=_hdr(auth_token),
        )
    # Filter to topology tokens only.
    res = await client.get(
        f"{_BASE}/tokens", params={"topology_id": topo_id},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 200
    body = res.json()
    decky_names = {t["decky_name"] for t in body["tokens"]}
    assert decky_names == {"web1"}
    assert all(t["topology_id"] == topo_id for t in body["tokens"])


# ---------------- auth ----------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_writes_rejected(
    client: httpx.AsyncClient,
) -> None:
    for path, method in [
        (f"{_BASE}/tokens", "POST"),
        (f"{_BASE}/blobs", "POST"),
    ]:
        res = await client.request(
            method, path, json={}, files={} if method == "POST" else None,
        )
        # Either 401 from the auth dep or 422 from missing body — the
        # important property is "not anonymous".
        assert res.status_code in (401, 403, 422), f"{path} {method} -> {res.status_code}"
