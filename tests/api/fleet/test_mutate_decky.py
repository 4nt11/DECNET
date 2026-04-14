"""
Tests for the mutate decky API endpoint.
"""

import pytest
import httpx
from unittest.mock import patch


class TestMutateDecky:
    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client: httpx.AsyncClient):
        resp = await client.post("/api/v1/deckies/decky-01/mutate")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_successful_mutation(self, client: httpx.AsyncClient, auth_token: str, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("DECNET_CONTRACT_TEST", raising=False)
        with patch("decnet.web.router.fleet.api_mutate_decky.mutate_decky", return_value=True):
            resp = await client.post(
                "/api/v1/deckies/decky-01/mutate",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 200
        assert "Successfully mutated" in resp.json()["message"]

    @pytest.mark.asyncio
    async def test_failed_mutation_returns_404(self, client: httpx.AsyncClient, auth_token: str, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("DECNET_CONTRACT_TEST", raising=False)
        with patch("decnet.web.router.fleet.api_mutate_decky.mutate_decky", return_value=False):
            resp = await client.post(
                "/api/v1/deckies/decky-01/mutate",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_decky_name_returns_422(self, client: httpx.AsyncClient, auth_token: str):
        resp = await client.post(
            "/api/v1/deckies/INVALID NAME!!/mutate",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code == 422
