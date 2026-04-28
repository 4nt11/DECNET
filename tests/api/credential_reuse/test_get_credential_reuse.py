"""Read-only ``/credential-reuse`` API tests.

Mirrors ``tests/api/credentials/test_get_credentials.py`` for the
JWT-gated list + detail endpoints. The endpoints are read-only — no
body parsing, so no 400 contract per ``feedback_schemathesis_400``.
"""
from __future__ import annotations

import hashlib

import httpx
import pytest
from hypothesis import given, settings, strategies as st

from ..conftest import _FUZZ_SETTINGS


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


async def _seed_reuse(repo, sha: str = None, secret_kind: str = "plaintext"):
    """Seed two credential rows then upsert a CredentialReuse row.

    The repo's upsert_credential_reuse recomputes target_count from the
    underlying credentials table, so both seeds matter.
    """
    sha = sha or _sha256("hunter2")
    base = {
        "attacker_ip": "10.0.0.5",
        "service": "ssh",
        "principal": "root",
        "secret_kind": secret_kind,
        "secret_sha256": sha,
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {},
    }
    await repo.upsert_credential({**base, "decky_name": "d1", "service": "ssh"})
    await repo.upsert_credential({**base, "decky_name": "d2", "service": "ftp"})
    await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind=secret_kind, principal="root",
        attacker_uuid=None, attacker_ip="10.0.0.5",
        decky="d1", service="ssh", attempt_count=1,
    )
    row = await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind=secret_kind, principal="root",
        attacker_uuid=None, attacker_ip="10.0.0.5",
        decky="d2", service="ftp", attempt_count=1,
    )
    return row["id"]


# ─── /credential-reuse (list) ────────────────────────────────────────────────


@pytest.mark.anyio
async def test_list_credential_reuse_empty(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    resp = await client.get(
        "/api/v1/credential-reuse",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["data"] == []
    assert body["limit"] == 50
    assert body["offset"] == 0


@pytest.mark.anyio
async def test_list_credential_reuse_returns_seeded_row(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    from decnet.web.dependencies import repo
    reuse_id = await _seed_reuse(repo)

    resp = await client.get(
        "/api/v1/credential-reuse",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert len(body["data"]) == 1
    row = body["data"][0]
    assert row["id"] == reuse_id
    assert row["target_count"] == 2
    assert row["secret_kind"] == "plaintext"
    # JSON list columns are decoded for the API consumer.
    assert isinstance(row["deckies"], list)
    assert sorted(row["deckies"]) == ["d1", "d2"]


@pytest.mark.anyio
async def test_list_credential_reuse_pagination(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    resp = await client.get(
        "/api/v1/credential-reuse?limit=1&offset=0",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["limit"] == 1
    assert resp.json()["offset"] == 0


@pytest.mark.anyio
async def test_list_credential_reuse_secret_kind_filter(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    from decnet.web.dependencies import repo
    await _seed_reuse(repo, sha=_sha256("p1"), secret_kind="plaintext")
    await _seed_reuse(repo, sha=_sha256("h1"), secret_kind="ntlm_hash")

    resp = await client.get(
        "/api/v1/credential-reuse",
        params={"secret_kind": "ntlm_hash"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["data"][0]["secret_kind"] == "ntlm_hash"


@pytest.mark.anyio
async def test_list_credential_reuse_min_target_count_filter(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    from decnet.web.dependencies import repo
    await _seed_reuse(repo)
    # min_target_count=99 — nothing should match.
    resp = await client.get(
        "/api/v1/credential-reuse",
        params={"min_target_count": 99},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


@pytest.mark.anyio
async def test_list_credential_reuse_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    resp = await client.get("/api/v1/credential-reuse")
    assert resp.status_code == 401


# ─── /credential-reuse/{id} (detail) ─────────────────────────────────────────


@pytest.mark.anyio
async def test_get_credential_reuse_by_id(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    from decnet.web.dependencies import repo
    reuse_id = await _seed_reuse(repo)

    resp = await client.get(
        f"/api/v1/credential-reuse/{reuse_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    row = resp.json()
    assert row["id"] == reuse_id
    assert row["target_count"] == 2
    assert isinstance(row["deckies"], list)


@pytest.mark.anyio
async def test_get_credential_reuse_404_for_unknown_id(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    resp = await client.get(
        "/api/v1/credential-reuse/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_get_credential_reuse_detail_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    resp = await client.get(
        "/api/v1/credential-reuse/00000000-0000-0000-0000-000000000000"
    )
    assert resp.status_code == 401


# ─── fuzz ────────────────────────────────────────────────────────────────────


@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    limit=st.integers(min_value=-2000, max_value=5000),
    offset=st.integers(min_value=-2000, max_value=5000),
    min_target_count=st.integers(min_value=-50, max_value=2147483700),
    secret_kind=st.one_of(st.none(), st.text(max_size=64)),
)
async def test_fuzz_list_credential_reuse(
    client: httpx.AsyncClient,
    auth_token: str,
    limit: int,
    offset: int,
    min_target_count: int,
    secret_kind,
) -> None:
    params: dict = {
        "limit": limit, "offset": offset, "min_target_count": min_target_count,
    }
    if secret_kind is not None:
        params["secret_kind"] = secret_kind
    try:
        resp = await client.get(
            "/api/v1/credential-reuse",
            params=params,
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code in (200, 422)
    except UnicodeEncodeError:
        pass
