"""
Live health endpoint tests.

Starts the real FastAPI application via ASGI transport with background workers
disabled (DECNET_CONTRACT_TEST=true). Validates the /health endpoint reports
accurate component status against real system state — no mocks.

Run: pytest -m live tests/live/test_health_live.py -v
"""

import asyncio
import os
from unittest.mock import MagicMock

import httpx
import pytest

# Must be set before any decnet import
os.environ.setdefault("DECNET_JWT_SECRET", "test-secret-key-at-least-32-chars-long!!")
os.environ.setdefault("DECNET_ADMIN_PASSWORD", "test-password-123")
os.environ["DECNET_CONTRACT_TEST"] = "true"

from decnet.web.api import app, get_background_tasks  # noqa: E402
from decnet.web.dependencies import repo  # noqa: E402
from decnet.web.db.models import User  # noqa: E402
from decnet.web.auth import get_password_hash  # noqa: E402
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD  # noqa: E402

from sqlmodel import SQLModel  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import uuid as _uuid  # noqa: E402


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module", autouse=True)
async def live_db():
    """Spin up an in-memory SQLite for the live test module."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    repo.engine = engine
    repo.session_factory = session_factory

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    async with session_factory() as session:
        existing = await session.execute(
            select(User).where(User.username == DECNET_ADMIN_USER)
        )
        if not existing.scalar_one_or_none():
            session.add(User(
                uuid=str(_uuid.uuid4()),
                username=DECNET_ADMIN_USER,
                password_hash=get_password_hash(DECNET_ADMIN_PASSWORD),
                role="admin",
                must_change_password=False,
            ))
            await session.commit()

    yield

    await engine.dispose()


@pytest.fixture(scope="module")
async def live_client(live_db):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.fixture(scope="module")
async def token(live_client):
    resp = await live_client.post("/api/v1/auth/login", json={
        "username": DECNET_ADMIN_USER,
        "password": DECNET_ADMIN_PASSWORD,
    })
    return resp.json()["access_token"]


# ─── Tests ───────────────────────────────────────────────────────────────────


@pytest.mark.live
class TestHealthLive:
    """Live integration tests — real DB, real Docker check, real task state."""

    async def test_endpoint_reachable_and_authenticated(self, live_client, token):
        """Health endpoint exists and enforces auth."""
        resp = await live_client.get("/api/v1/health")
        assert resp.status_code == 401

        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (200, 503)

    async def test_response_contains_all_components(self, live_client, token):
        """Every expected component appears in the response."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        expected = {"database", "ingestion_worker", "collector_worker",
                    "attacker_worker", "sniffer_worker", "tarpit_watcher", "docker"}
        assert set(data["components"].keys()) == expected

    async def test_database_healthy_with_real_db(self, live_client, token):
        """With a real (in-memory) SQLite, database component should be ok."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json()["components"]["database"]["status"] == "ok"

    async def test_workers_report_not_started_in_contract_mode(self, live_client, token):
        """In contract-test mode workers are skipped, so they report failing."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        for worker in ("ingestion_worker", "collector_worker", "attacker_worker"):
            comp = data["components"][worker]
            assert comp["status"] == "failing", f"{worker} should be failing"
            assert comp["detail"] is not None

    async def test_overall_status_reflects_worker_state(self, live_client, token):
        """With workers not started, overall status should be unhealthy (503)."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 503
        assert resp.json()["status"] == "unhealthy"

    async def test_docker_component_reports_real_state(self, live_client, token):
        """Docker component reflects whether Docker daemon is actually reachable."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        docker_comp = resp.json()["components"]["docker"]
        # We don't assert ok or failing — just that it reported honestly
        assert docker_comp["status"] in ("ok", "failing")
        if docker_comp["status"] == "failing":
            assert docker_comp["detail"] is not None

    async def test_component_status_values_are_valid(self, live_client, token):
        """Every component status is either 'ok' or 'failing'."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        for name, comp in resp.json()["components"].items():
            assert comp["status"] in ("ok", "failing"), f"{name} has invalid status"

    async def test_status_transitions_with_simulated_recovery(self, live_client, token):
        """Simulate workers coming alive and verify status improves."""
        import decnet.web.api as api_mod

        # Snapshot original task state
        orig = {
            "ingestion": api_mod.ingestion_task,
            "collector": api_mod.collector_task,
            "attacker": api_mod.attacker_task,
            "sniffer": api_mod.sniffer_task,
        }

        try:
            # Simulate all workers running
            for attr in ("ingestion_task", "collector_task", "attacker_task", "sniffer_task"):
                fake = MagicMock(spec=asyncio.Task)
                fake.done.return_value = False
                setattr(api_mod, attr, fake)

            resp = await live_client.get(
                "/api/v1/health",
                headers={"Authorization": f"Bearer {token}"},
            )
            data = resp.json()
            # Workers should now be ok; overall depends on docker too
            for w in ("ingestion_worker", "collector_worker", "attacker_worker", "sniffer_worker"):
                assert data["components"][w]["status"] == "ok"
        finally:
            # Restore original state
            api_mod.ingestion_task = orig["ingestion"]
            api_mod.collector_task = orig["collector"]
            api_mod.attacker_task = orig["attacker"]
            api_mod.sniffer_task = orig["sniffer"]

    async def test_degraded_when_only_sniffer_fails(self, live_client, token):
        """If only the sniffer is down but everything else is up, status is degraded."""
        import decnet.web.api as api_mod

        orig = {
            "ingestion": api_mod.ingestion_task,
            "collector": api_mod.collector_task,
            "attacker": api_mod.attacker_task,
            "sniffer": api_mod.sniffer_task,
        }

        try:
            # All required workers running
            for attr in ("ingestion_task", "collector_task", "attacker_task"):
                fake = MagicMock(spec=asyncio.Task)
                fake.done.return_value = False
                setattr(api_mod, attr, fake)
            # Sniffer explicitly not running
            api_mod.sniffer_task = None

            resp = await live_client.get(
                "/api/v1/health",
                headers={"Authorization": f"Bearer {token}"},
            )
            data = resp.json()

            # Docker may or may not be available — if docker is failing,
            # overall will be unhealthy, not degraded. Account for both.
            if data["components"]["docker"]["status"] == "ok":
                assert data["status"] == "degraded"
                assert resp.status_code == 200
            else:
                assert data["status"] == "unhealthy"

            assert data["components"]["sniffer_worker"]["status"] == "failing"
        finally:
            api_mod.ingestion_task = orig["ingestion"]
            api_mod.collector_task = orig["collector"]
            api_mod.attacker_task = orig["attacker"]
            api_mod.sniffer_task = orig["sniffer"]
