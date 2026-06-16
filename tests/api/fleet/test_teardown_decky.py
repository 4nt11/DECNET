# SPDX-License-Identifier: AGPL-3.0-or-later
"""DELETE /deckies/{name} — single-decky teardown.

The handler must:
1. Reject anonymous callers (401) and non-admins (403).
2. 404 when no active deployment exists, or the named decky isn't in it.
3. 422 when decky_name fails the path pattern.
4. On the happy path: drop the decky's fleet_deckies row AND prune it from
   decnet-state.json (so the reconciler can't resurrect it), leaving the rest
   of the fleet intact; deleting the last decky clears state entirely.

Under DECNET_CONTRACT_TEST the engine teardown (docker) is skipped; the
handler still removes the fleet_deckies row and prunes state, which is what
these tests assert.
"""
from __future__ import annotations

import httpx
import pytest

from decnet.config import load_state
from decnet.web.dependencies import repo


@pytest.fixture(autouse=True)
def contract_test_mode(monkeypatch):
    monkeypatch.setenv("DECNET_CONTRACT_TEST", "true")


@pytest.mark.anyio
async def test_unauthenticated_returns_401(client: httpx.AsyncClient):
    resp = await client.delete("/api/v1/deckies/test-decky-1")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_viewer_forbidden_403(client, viewer_token, mock_state_file, mock_fleet_deckies):
    resp = await client.delete(
        "/api/v1/deckies/test-decky-1",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_no_deployment_returns_404(client, auth_token):
    # patch_state_file (autouse) points STATE_FILE at an empty tmp path with no
    # file written, so load_state() returns None.
    resp = await client.delete(
        "/api/v1/deckies/test-decky-1",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 404
    assert "deployment" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_unknown_decky_returns_404(client, auth_token, mock_state_file):
    resp = await client.delete(
        "/api/v1/deckies/does-not-exist",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 404
    assert "does-not-exist" in resp.json()["detail"]


@pytest.mark.anyio
async def test_invalid_name_returns_422(client, auth_token, mock_state_file):
    resp = await client.delete(
        "/api/v1/deckies/Bad_Name",  # uppercase + underscore violate the pattern
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_delete_removes_decky_and_prunes_state(
    client, auth_token, mock_state_file, mock_fleet_deckies,
):
    """Deleting one decky drops its fleet_deckies row and prunes it from
    decnet-state.json, leaving the rest of the fleet intact."""
    resp = await client.delete(
        "/api/v1/deckies/test-decky-1",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 204, resp.text

    # fleet_deckies row gone (the store the UI reads), sibling untouched.
    names = {r["name"] for r in await repo.list_fleet_deckies()}
    assert names == {"test-decky-2"}

    # decnet-state.json pruned so the reconciler can't resurrect it.
    loaded = load_state()
    assert loaded is not None
    assert {d.name for d in loaded[0].deckies} == {"test-decky-2"}


@pytest.mark.anyio
async def test_delete_last_decky_clears_state(
    client, auth_token, mock_state_file, mock_fleet_deckies,
):
    """Tearing down the final decky clears state entirely rather than
    persisting an invalid empty-fleet config (DecnetConfig.deckies min_length=1)."""
    for name in ("test-decky-1", "test-decky-2"):
        resp = await client.delete(
            f"/api/v1/deckies/{name}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code == 204, resp.text

    assert await repo.list_fleet_deckies() == []
    assert load_state() is None
