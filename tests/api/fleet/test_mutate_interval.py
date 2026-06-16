# SPDX-License-Identifier: AGPL-3.0-or-later
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
            json={"mutate_interval": "60m"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_no_active_deployment(self, client: httpx.AsyncClient, auth_token: str):
        with patch("decnet.web.router.fleet.api_mutate_interval.repo", new_callable=AsyncMock) as mock_repo:
            mock_repo.get_state.return_value = None
            resp = await client.put(
                "/api/v1/deckies/decky-01/mutate-interval",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"mutate_interval": "60m"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_decky_not_found(self, client: httpx.AsyncClient, auth_token: str):
        config = _config()
        with patch("decnet.web.router.fleet.api_mutate_interval.repo", new_callable=AsyncMock) as mock_repo:
            mock_repo.get_state.return_value = {"config": config.model_dump(), "compose_path": "c.yml"}
            resp = await client.put(
                "/api/v1/deckies/nonexistent/mutate-interval",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"mutate_interval": "60m"},
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
                json={"mutate_interval": "120m"},
            )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Mutation interval updated"
        mock_repo.set_state.assert_awaited_once()
        saved = mock_repo.set_state.call_args[0][1]
        saved_interval = saved["config"]["deckies"][0]["mutate_interval"]
        assert saved_interval == 120

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

    @pytest.mark.asyncio
    async def test_invalid_format_returns_422(self, client: httpx.AsyncClient, auth_token: str):
        """Seconds ('s') and raw integers are not accepted.
        Note: The API returns 400 for structural violations (wrong type) and 422 for semantic/pattern violations.
        """
        cases = [
            ("1s", 422),
            ("60", 422),
            (60, 400),
            (False, 400),
            ("1h", 422),
        ]
        for bad, expected_status in cases:
            resp = await client.put(
                "/api/v1/deckies/decky-01/mutate-interval",
                headers={"Authorization": f"Bearer {auth_token}"},
                json={"mutate_interval": bad},
            )
            assert resp.status_code == expected_status, f"Expected {expected_status} for {bad!r}, got {resp.status_code}"

    @pytest.mark.asyncio
    async def test_duration_units_stored_as_minutes(self, client: httpx.AsyncClient, auth_token: str):
        """Each unit suffix is parsed to the correct number of minutes."""
        cases = [
            ("2m", 2),
            ("1d", 1440),
            ("1M", 43200),
            ("1y", 525600),
            ("1Y", 525600),
        ]
        for duration, expected_minutes in cases:
            config = _config()
            with patch("decnet.web.router.fleet.api_mutate_interval.repo", new_callable=AsyncMock) as mock_repo:
                mock_repo.get_state.return_value = {"config": config.model_dump(), "compose_path": "c.yml"}
                resp = await client.put(
                    "/api/v1/deckies/decky-01/mutate-interval",
                    headers={"Authorization": f"Bearer {auth_token}"},
                    json={"mutate_interval": duration},
                )
            assert resp.status_code == 200, f"Expected 200 for {duration!r}"
            saved = mock_repo.set_state.call_args[0][1]
            saved_interval = saved["config"]["deckies"][0]["mutate_interval"]
            assert saved_interval == expected_minutes, f"{duration!r} → expected {expected_minutes} min, got {saved_interval}"
