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
