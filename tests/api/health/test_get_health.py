# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from decnet.web.router.health.api_get_health import _reset_docker_cache, _reset_db_cache


@pytest.fixture(autouse=True)
def _clear_health_caches():
    _reset_docker_cache()
    _reset_db_cache()
    yield
    _reset_docker_cache()
    _reset_db_cache()


@pytest.mark.anyio
async def test_health_requires_auth(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_health_response_schema(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        # All workers running
        for name in ("ingestion_worker", "collector_worker", "attacker_worker", "sniffer_worker"):
            task = MagicMock(spec=asyncio.Task)
            task.done.return_value = False
            mock_tasks.return_value = {name: task for name in
                ("ingestion_worker", "collector_worker", "attacker_worker", "sniffer_worker")}
        mock_client = MagicMock()
        mock_docker.return_value = mock_client

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    data = resp.json()
    assert "status" in data
    assert data["status"] in ("healthy", "degraded", "unhealthy")
    assert "components" in data
    expected_components = {"database", "ingestion_worker", "collector_worker",
                          "attacker_worker", "sniffer_worker", "docker"}
    assert set(data["components"].keys()) == expected_components
    for comp in data["components"].values():
        assert comp["status"] in ("ok", "failing")


@pytest.mark.anyio
async def test_health_database_ok(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        _make_all_running(mock_tasks)
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    assert resp.json()["components"]["database"]["status"] == "ok"


@pytest.mark.anyio
async def test_health_all_healthy(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        _make_all_running(mock_tasks)
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


@pytest.mark.anyio
async def test_health_degraded_sniffer_only(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        tasks = _make_running_tasks()
        tasks["sniffer_worker"] = None  # sniffer not started
        mock_tasks.return_value = tasks
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"
    assert resp.json()["components"]["sniffer_worker"]["status"] == "failing"


@pytest.mark.anyio
async def test_health_unhealthy_returns_503(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        tasks = _make_running_tasks()
        tasks["ingestion_worker"] = None  # critical worker down
        mock_tasks.return_value = tasks
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    assert resp.status_code == 503
    assert resp.json()["status"] == "unhealthy"


@pytest.mark.anyio
async def test_health_degraded_when_attacker_down(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        tasks = _make_running_tasks()
        tasks["attacker_worker"] = None  # non-critical
        mock_tasks.return_value = tasks
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"
    assert resp.json()["components"]["attacker_worker"]["status"] == "failing"


@pytest.mark.anyio
async def test_health_degraded_when_collector_down(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        tasks = _make_running_tasks()
        tasks["collector_worker"] = None  # non-critical
        mock_tasks.return_value = tasks
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


@pytest.mark.anyio
async def test_health_docker_failing(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env", side_effect=Exception("connection refused")):
        _make_all_running(mock_tasks)

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    comp = resp.json()["components"]["docker"]
    assert comp["status"] == "failing"
    # Internal exception message must NOT be in the detail (V7.1.2 fix).
    assert "connection refused" not in comp["detail"]
    assert comp["detail"] == "docker daemon unavailable"


@pytest.mark.anyio
async def test_health_database_failing(client: httpx.AsyncClient, auth_token: str) -> None:
    from decnet.web.dependencies import repo as real_repo

    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker, \
         patch.object(real_repo, "get_total_logs", new=AsyncMock(side_effect=Exception("disk full"))):
        _make_all_running(mock_tasks)
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    comp = resp.json()["components"]["database"]
    assert comp["status"] == "failing"
    # Internal exception message must NOT be in the detail (V7.1.2 fix).
    assert "disk full" not in comp["detail"]
    assert comp["detail"] == "database unavailable"


@pytest.mark.anyio
async def test_health_worker_exited_with_exception(client: httpx.AsyncClient, auth_token: str) -> None:
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker:
        tasks = _make_running_tasks()
        dead_task = MagicMock(spec=asyncio.Task)
        dead_task.done.return_value = True
        dead_task.cancelled.return_value = False
        dead_task.exception.return_value = RuntimeError("segfault")
        tasks["collector_worker"] = dead_task
        mock_tasks.return_value = tasks
        mock_docker.return_value = MagicMock()

        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    comp = resp.json()["components"]["collector_worker"]
    assert comp["status"] == "failing"
    # Internal exception message must NOT be in the detail (V7.1.2 fix).
    assert "segfault" not in comp["detail"]
    assert comp["detail"] == "exited with error"


# ── V7.1.2: no internal exception detail in response body ────────────────────

@pytest.mark.anyio
async def test_health_db_failure_does_not_leak_exception_class(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """V7.1.2: DB exception class/message must not appear in the HTTP response."""
    from decnet.web.dependencies import repo as real_repo

    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env") as mock_docker, \
         patch.object(
             real_repo, "get_total_logs",
             new=AsyncMock(side_effect=OSError("[Errno 28] No space left on device")),
         ):
        _make_all_running(mock_tasks)
        mock_docker.return_value = MagicMock()
        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    detail = resp.json()["components"]["database"].get("detail", "")
    assert "Errno" not in detail
    assert "No space left" not in detail
    assert "OSError" not in detail


@pytest.mark.anyio
async def test_health_docker_failure_does_not_leak_exception_class(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """V7.1.2: Docker socket exception must not appear in the HTTP response."""
    with patch("decnet.web.api.get_background_tasks") as mock_tasks, \
         patch("docker.from_env", side_effect=OSError("[Errno 111] Connection refused")):
        _make_all_running(mock_tasks)
        resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {auth_token}"})

    detail = resp.json()["components"]["docker"].get("detail", "")
    assert "Errno" not in detail
    assert "Connection refused" not in detail
    assert "OSError" not in detail


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_running_tasks() -> dict[str, MagicMock]:
    tasks = {}
    for name in ("ingestion_worker", "collector_worker", "attacker_worker", "sniffer_worker"):
        t = MagicMock(spec=asyncio.Task)
        t.done.return_value = False
        tasks[name] = t
    return tasks


def _make_all_running(mock_tasks: MagicMock) -> None:
    mock_tasks.return_value = _make_running_tasks()
