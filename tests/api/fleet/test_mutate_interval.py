"""
Tests for the mutate interval API endpoint.
"""
import pytest
import httpx
from unittest.mock import patch, AsyncMock

from decnet.config import DeckyConfig, DecnetConfig


def _decky(name: str = "decky-01") -> DeckyConfig:
    return DeckyConfig(
        name=name, ip="192.168.1.10", services=["ssh"],
        distro="debian", base_image="debian", hostname="test-host",
        build_base="debian:bookworm-slim", nmap_os="linux",
        mutate_interval=30,
    )


def _config() -> DecnetConfig:
    return DecnetConfig(
        mode="unihost", interface="eth0", subnet="192.168.1.0/24",
        gateway="192.168.1.1", deckies=[_decky()],
    )


class TestMutateInterval:
    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client: httpx.AsyncClient):
        resp = await client.put(
            "/api/v1/deckies/decky-01/mutate-interval",
            json={"mutate_interval": 60},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_no_active_deployment(self, client: httpx.AsyncClient, auth_token: str):
        with patch("decnet.web.router.fleet.api_mutate_interval.repo", new_callable=AsyncMock) as mock_repo:
            mock_repo.get_state.return_value = None
            resp = await client.put(
                "/api/v1/deckies/decky-01/mutate-interval",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"mutate_interval": 60},
            )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_decky_not_found(self, client: httpx.AsyncClient, auth_token: str):
        config = _config()
        with patch("decnet.web.router.fleet.api_mutate_interval.repo", new_callable=AsyncMock) as mock_repo:
            mock_repo.get_state.return_value = {"config": config.model_dump(), "compose_path": "c.yml"}
            resp = await client.put(
                "/api/v1/deckies/nonexistent/mutate-interval",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"mutate_interval": 60},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_successful_interval_update(self, client: httpx.AsyncClient, auth_token: str):
        config = _config()
        with patch("decnet.web.router.fleet.api_mutate_interval.repo", new_callable=AsyncMock) as mock_repo:
            mock_repo.get_state.return_value = {"config": config.model_dump(), "compose_path": "c.yml"}
            resp = await client.put(
                "/api/v1/deckies/decky-01/mutate-interval",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"mutate_interval": 120},
            )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Mutation interval updated"
        mock_repo.set_state.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_null_interval_removes_mutation(self, client: httpx.AsyncClient, auth_token: str):
        config = _config()
        with patch("decnet.web.router.fleet.api_mutate_interval.repo", new_callable=AsyncMock) as mock_repo:
            mock_repo.get_state.return_value = {"config": config.model_dump(), "compose_path": "c.yml"}
            resp = await client.put(
                "/api/v1/deckies/decky-01/mutate-interval",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"mutate_interval": None},
            )
        assert resp.status_code == 200
        mock_repo.set_state.assert_awaited_once()
