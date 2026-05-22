"""
Tests for the mutate decky API endpoint — now 202 fire-and-forget.

The handler must:
1. Reject anonymous callers (401).
2. 404 when no active deployment exists.
3. 404 when the named decky isn't in the current state.
4. 422 when decky_name pattern fails validation.
5. On the happy path, create a DeckyLifecycle row, spawn a background
   task, return 202 with the row's id.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest


class TestMutateDecky:
    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client: httpx.AsyncClient):
        resp = await client.post("/api/v1/deckies/decky-01/mutate")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_no_deployment_returns_404(
        self, client: httpx.AsyncClient, auth_token: str,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.delenv("DECNET_CONTRACT_TEST", raising=False)
        with patch(
            "decnet.web.router.fleet.api_mutate_decky.repo.get_state",
            new_callable=AsyncMock, return_value=None,
        ):
            resp = await client.post(
                "/api/v1/deckies/decky-01/mutate",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 404
        assert "No active deployment" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_unknown_decky_returns_404(
        self, client: httpx.AsyncClient, auth_token: str,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.delenv("DECNET_CONTRACT_TEST", raising=False)
        from decnet.config import DecnetConfig, DeckyConfig
        cfg = DecnetConfig(
            mode="unihost", interface="eth0",
            subnet="10.0.0.0/24", gateway="10.0.0.1",
            deckies=[DeckyConfig(
                name="decky-existing", ip="10.0.0.10",
                services=["ssh"], distro="debian",
                base_image="debian:bookworm-slim", hostname="d01",
            )],
        )
        with patch(
            "decnet.web.router.fleet.api_mutate_decky.repo.get_state",
            new_callable=AsyncMock,
            return_value={"config": cfg.model_dump(), "compose_path": "c.yml"},
        ):
            resp = await client.post(
                "/api/v1/deckies/decky-missing/mutate",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_invalid_decky_name_returns_422(
        self, client: httpx.AsyncClient, auth_token: str,
    ):
        resp = await client.post(
            "/api/v1/deckies/INVALID NAME!!/mutate",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_successful_mutate_returns_202_with_lifecycle_id(
        self, client: httpx.AsyncClient, auth_token: str,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.delenv("DECNET_CONTRACT_TEST", raising=False)
        from decnet.config import DecnetConfig, DeckyConfig
        cfg = DecnetConfig(
            mode="unihost", interface="eth0",
            subnet="10.0.0.0/24", gateway="10.0.0.1",
            deckies=[DeckyConfig(
                name="decky-01", ip="10.0.0.10",
                services=["ssh"], distro="debian",
                base_image="debian:bookworm-slim", hostname="d01",
            )],
        )

        spawned: list[str] = []
        real_create_task = asyncio.create_task

        def _capture(coro, **kw):
            spawned.append(kw.get("name", ""))
            coro.close()
            async def _noop(): return None
            return real_create_task(_noop())

        with patch(
            "decnet.web.router.fleet.api_mutate_decky.repo.get_state",
            new_callable=AsyncMock,
            return_value={"config": cfg.model_dump(), "compose_path": "c.yml"},
        ), patch(
            "decnet.web.router.fleet.api_mutate_decky.repo.set_state",
            new_callable=AsyncMock, return_value=None,
        ), patch(
            "decnet.web.router.fleet.api_mutate_decky.repo.create_lifecycle",
            new_callable=AsyncMock, return_value="lid-abc",
        ), patch(
            "decnet.web.router.fleet.api_mutate_decky.pick_new_services",
            return_value=["http", "ftp"],
        ), patch(
            "decnet.web.router.fleet.api_mutate_decky.asyncio.create_task",
            side_effect=_capture,
        ):
            resp = await client.post(
                "/api/v1/deckies/decky-01/mutate",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["lifecycle_ids"] == ["lid-abc"]
        assert spawned and spawned[0].startswith("mutate-")

    @pytest.mark.asyncio
    async def test_no_services_available_returns_404(
        self, client: httpx.AsyncClient, auth_token: str,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.delenv("DECNET_CONTRACT_TEST", raising=False)
        from decnet.config import DecnetConfig, DeckyConfig
        cfg = DecnetConfig(
            mode="unihost", interface="eth0",
            subnet="10.0.0.0/24", gateway="10.0.0.1",
            deckies=[DeckyConfig(
                name="decky-01", ip="10.0.0.10",
                services=["ssh"], distro="debian",
                base_image="debian:bookworm-slim", hostname="d01",
            )],
        )
        with patch(
            "decnet.web.router.fleet.api_mutate_decky.repo.get_state",
            new_callable=AsyncMock,
            return_value={"config": cfg.model_dump(), "compose_path": "c.yml"},
        ), patch(
            "decnet.web.router.fleet.api_mutate_decky.pick_new_services",
            return_value=None,
        ):
            resp = await client.post(
                "/api/v1/deckies/decky-01/mutate",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 404
        assert "No services available" in resp.json()["detail"]
