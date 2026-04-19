"""
Live service isolation tests.

Unlike tests/test_service_isolation.py (which mocks dependencies), these tests
run real workers against real (temporary) resources to verify graceful degradation
in conditions that actually occur on a host machine.

Dependency graph under test:
    Collector → (Docker SDK, state file, log file)
    Ingester  → (Collector's JSON output, DB repo)
    Attacker  → (DB repo)
    Sniffer   → (MACVLAN interface, scapy, state file)
    API       → (DB init, all workers, Docker, health endpoint)

Run: pytest -m live tests/live/test_service_isolation_live.py -v
"""

import asyncio
import json
import os
import uuid as _uuid
from pathlib import Path

import httpx
import pytest

# Must be set before any decnet import
os.environ.setdefault("DECNET_JWT_SECRET", "test-secret-key-at-least-32-chars-long!!")
os.environ.setdefault("DECNET_ADMIN_PASSWORD", "test-password-123")
os.environ["DECNET_CONTRACT_TEST"] = "true"

from decnet.collector.worker import (  # noqa: E402
    log_collector_worker,
    parse_rfc5424,
    _load_service_container_names,
    is_service_container,
)
from decnet.web.ingester import log_ingestion_worker  # noqa: E402
from decnet.profiler.worker import (  # noqa: E402
    attacker_profile_worker,
    _WorkerState,
    _incremental_update,
)
from decnet.sniffer.worker import sniffer_worker, _interface_exists  # noqa: E402
from decnet.web.api import app, lifespan  # noqa: E402
from decnet.web.dependencies import repo  # noqa: E402
from decnet.web.db.models import User, Log  # noqa: E402
from decnet.web.auth import get_password_hash  # noqa: E402
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD  # noqa: E402

from sqlmodel import SQLModel  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool  # noqa: E402


# ─── Shared fixtures ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module", autouse=True)
async def live_db():
    """Real in-memory SQLite — shared across this module."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    repo.engine = engine
    repo.session_factory = session_factory

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    async with session_factory() as session:
        existing = await session.execute(
            select(User).where(User.username == DECNET_ADMIN_USER)
        )
        if not existing.scalar_one_or_none():
            session.add(
                User(
                    uuid=str(_uuid.uuid4()),
                    username=DECNET_ADMIN_USER,
                    password_hash=get_password_hash(DECNET_ADMIN_PASSWORD),
                    role="admin",
                    must_change_password=False,
                )
            )
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
    resp = await live_client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )
    return resp.json()["access_token"]


# ─── Collector live isolation ────────────────────────────────────────────────


@pytest.mark.live
class TestCollectorLiveIsolation:
    """Real collector behaviour against the actual Docker daemon."""

    async def test_collector_finds_no_deckies_without_state(self, tmp_path):
        """With no deckies in state, collector's container scan finds nothing.

        We avoid calling the full worker because client.events() blocks
        the thread indefinitely — instead we test the scan logic directly
        against the real Docker daemon.
        """
        import docker
        import decnet.config as cfg

        original_state = cfg.STATE_FILE
        try:
            cfg.STATE_FILE = tmp_path / "empty-state.json"

            # Real Docker client, real container list — but no state means
            # is_service_container rejects everything.
            client = docker.from_env()
            matched = [c for c in client.containers.list() if is_service_container(c)]
            client.close()

            assert matched == [], (
                f"Expected no matching containers without state, got: "
                f"{[c.name for c in matched]}"
            )
        finally:
            cfg.STATE_FILE = original_state

    async def test_state_loader_returns_empty_without_state_file(self):
        """Real _load_service_container_names against no state file."""
        import decnet.config as cfg

        original = cfg.STATE_FILE
        try:
            cfg.STATE_FILE = Path("/tmp/nonexistent-decnet-state-live.json")
            result = _load_service_container_names()
            assert result == set()
        finally:
            cfg.STATE_FILE = original

    def test_rfc5424_parser_handles_real_formats(self):
        """Parser works on real log lines, not just test fixtures."""
        valid = '<134>1 2026-04-14T12:00:00Z decky-01 ssh - login_attempt [relay@55555 src_ip="10.0.0.1" username="root" password="toor"] Failed login'
        result = parse_rfc5424(valid)
        assert result is not None
        assert result["decky"] == "decky-01"
        assert result["service"] == "ssh"
        assert result["attacker_ip"] == "10.0.0.1"
        assert result["fields"]["username"] == "root"

        # Garbage must return None, not crash
        assert parse_rfc5424("random garbage") is None
        assert parse_rfc5424("") is None

    def test_container_filter_rejects_real_system_containers(self):
        """is_service_container must not match system containers."""
        import decnet.config as cfg

        original = cfg.STATE_FILE
        try:
            cfg.STATE_FILE = Path("/tmp/nonexistent-decnet-state-live.json")
            # With no state, nothing is a service container
            assert is_service_container("dockerd") is False
            assert is_service_container("portainer") is False
            assert is_service_container("kube-proxy") is False
        finally:
            cfg.STATE_FILE = original


# ─── Ingester live isolation ─────────────────────────────────────────────────


@pytest.mark.live
class TestIngesterLiveIsolation:
    """Real ingester against real DB and real filesystem."""

    async def test_ingester_waits_for_missing_log_file(self, tmp_path):
        """Ingester must poll patiently when the log file doesn't exist yet."""
        log_base = str(tmp_path / "missing.log")
        os.environ["DECNET_INGEST_LOG_FILE"] = log_base

        try:
            task = asyncio.create_task(log_ingestion_worker(repo))
            await asyncio.sleep(0.5)
            assert not task.done(), "Ingester should be waiting, not exited"
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        finally:
            os.environ.pop("DECNET_INGEST_LOG_FILE", None)

    async def test_ingester_processes_real_json_into_db(self, tmp_path):
        """Write real JSON log lines → ingester inserts them into the real DB."""
        json_file = tmp_path / "ingest.json"
        log_base = str(tmp_path / "ingest.log")

        record = {
            "timestamp": "2026-04-14 12:00:00",
            "decky": "decky-live-01",
            "service": "ssh",
            "event_type": "login_attempt",
            "attacker_ip": "10.99.99.1",
            "fields": {"username": "root", "password": "toor"},
            "msg": "Failed login",
            "raw_line": '<134>1 2026-04-14T12:00:00Z decky-live-01 ssh - login_attempt [relay@55555 src_ip="10.99.99.1"] Failed login',
        }
        json_file.write_text(json.dumps(record) + "\n")

        os.environ["DECNET_INGEST_LOG_FILE"] = log_base
        try:
            task = asyncio.create_task(log_ingestion_worker(repo))
            # Give ingester time to pick up the file and process it
            await asyncio.sleep(1.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify the record landed in the real DB
            total = await repo.get_total_logs()
            assert total >= 1

            logs = await repo.get_logs(limit=100, offset=0)
            matching = [l for l in logs if l["attacker_ip"] == "10.99.99.1"]
            assert len(matching) >= 1
            assert matching[0]["service"] == "ssh"
        finally:
            os.environ.pop("DECNET_INGEST_LOG_FILE", None)

    async def test_ingester_skips_malformed_lines_without_crashing(self, tmp_path):
        """Ingester must skip bad JSON and keep going on good lines."""
        json_file = tmp_path / "mixed.json"
        log_base = str(tmp_path / "mixed.log")

        good_record = {
            "timestamp": "2026-04-14 13:00:00",
            "decky": "decky-live-02",
            "service": "http",
            "event_type": "request",
            "attacker_ip": "10.88.88.1",
            "fields": {},
            "msg": "",
            "raw_line": "<134>1 2026-04-14T13:00:00Z decky-live-02 http - request -",
        }
        json_file.write_text(
            "not valid json\n"
            "{broken too\n"
            + json.dumps(good_record)
            + "\n"
        )

        os.environ["DECNET_INGEST_LOG_FILE"] = log_base
        try:
            task = asyncio.create_task(log_ingestion_worker(repo))
            await asyncio.sleep(1.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # The good record should have made it through
            logs = await repo.get_logs(limit=100, offset=0)
            matching = [l for l in logs if l["attacker_ip"] == "10.88.88.1"]
            assert len(matching) >= 1
        finally:
            os.environ.pop("DECNET_INGEST_LOG_FILE", None)

    async def test_ingester_exits_gracefully_without_env_var(self):
        """Ingester must return immediately when DECNET_INGEST_LOG_FILE is unset."""
        os.environ.pop("DECNET_INGEST_LOG_FILE", None)
        # Should complete instantly with no error
        await log_ingestion_worker(repo)


# ─── Attacker worker live isolation ──────────────────────────────────────────


@pytest.mark.live
class TestAttackerWorkerLiveIsolation:
    """Real attacker worker against real DB."""

    async def test_attacker_worker_cold_starts_on_empty_db(self):
        """Worker cold start must handle an empty database without error."""
        state = _WorkerState()
        await _incremental_update(repo, state)
        assert state.initialized is True

    async def test_attacker_worker_builds_profile_from_real_logs(self):
        """Worker must build attacker profiles from logs already in the DB."""
        # Seed some logs from a known attacker IP
        for i in range(3):
            await repo.add_log({
                "timestamp": f"2026-04-14 14:0{i}:00",
                "decky": "decky-live-03",
                "service": "ssh" if i < 2 else "http",
                "event_type": "login_attempt",
                "attacker_ip": "10.77.77.1",
                "fields": {"username": "admin"},
                "msg": "",
                "raw_line": f'<134>1 2026-04-14T14:0{i}:00Z decky-live-03 {"ssh" if i < 2 else "http"} - login_attempt [relay@55555 src_ip="10.77.77.1" username="admin"]',
            })

        state = _WorkerState()
        await _incremental_update(repo, state)

        # The worker should have created an attacker record
        result = await repo.get_attackers(limit=100, offset=0, search="10.77.77.1")
        matching = [a for a in result if a["ip"] == "10.77.77.1"]
        assert len(matching) >= 1
        assert matching[0]["event_count"] >= 3

    async def test_attacker_worker_survives_cycle_with_no_new_logs(self):
        """Incremental update with no new logs must not crash or corrupt state."""
        state = _WorkerState()
        await _incremental_update(repo, state)
        last_id = state.last_log_id

        # Second update with no new data
        await _incremental_update(repo, state)
        assert state.last_log_id >= last_id  # unchanged or higher


# ─── Sniffer live isolation ──────────────────────────────────────────────────


@pytest.mark.live
class TestSnifferLiveIsolation:
    """Real sniffer against the actual host network stack."""

    async def test_sniffer_exits_cleanly_no_interface(self, tmp_path):
        """Sniffer must exit gracefully when MACVLAN interface doesn't exist."""
        os.environ["DECNET_SNIFFER_IFACE"] = "decnet_fake_iface_xyz"
        try:
            await sniffer_worker(str(tmp_path / "sniffer.log"))
            # Should return without exception
        finally:
            os.environ.pop("DECNET_SNIFFER_IFACE", None)

    def test_interface_exists_check_works(self):
        """_interface_exists returns True for loopback, False for nonsense."""
        import os
        lo_exists = os.path.exists("/sys/class/net/lo")
        if lo_exists:
            assert _interface_exists("lo") is True
        else:
            pytest.skip("loopback interface not found, probably in CI. passing...")
        assert _interface_exists("definitely_not_a_real_iface") is False

    def test_sniffer_engine_isolation_from_db(self):
        """SnifferEngine has zero DB dependency — works standalone."""
        from decnet.sniffer.fingerprint import SnifferEngine

        written: list[str] = []
        engine = SnifferEngine(
            ip_to_decky={"192.168.1.10": "decky-01"},
            write_fn=written.append,
        )
        engine._log("decky-01", "tls_client_hello", src_ip="10.0.0.1", ja3="abc123")
        assert len(written) == 1
        assert "decky-01" in written[0]
        assert "10.0.0.1" in written[0]


# ─── API lifespan live isolation ─────────────────────────────────────────────


@pytest.mark.live
class TestApiLifespanLiveIsolation:
    """Real API lifespan against real DB and real host state."""

    async def test_api_serves_requests_in_contract_mode(
        self, live_client, token
    ):
        """With workers disabled, API must still serve all endpoints."""
        # Stats
        resp = await live_client.get(
            "/api/v1/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Health
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (200, 503)
        assert "components" in resp.json()

    async def test_health_reflects_real_db_state(self, live_client, token):
        """Health endpoint correctly reports DB as ok with real in-memory DB."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json()["components"]["database"]["status"] == "ok"

    async def test_health_reports_workers_not_started(self, live_client, token):
        """In contract-test mode, workers are not started — health must report that."""
        resp = await live_client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        for w in ("ingestion_worker", "collector_worker", "attacker_worker"):
            assert data["components"][w]["status"] == "failing"
            assert "not started" in data["components"][w]["detail"]


# ─── Cross-service cascade live tests ────────────────────────────────────────


@pytest.mark.live
class TestCascadeLiveIsolation:
    """Verify that real component failures do not cascade."""

    async def test_ingester_survives_collector_never_writing(self, tmp_path):
        """When the collector never writes output, ingester waits without crashing."""
        log_base = str(tmp_path / "no-collector.log")
        os.environ["DECNET_INGEST_LOG_FILE"] = log_base

        try:
            task = asyncio.create_task(log_ingestion_worker(repo))
            await asyncio.sleep(0.5)
            assert not task.done(), "Ingester crashed instead of waiting"
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        finally:
            os.environ.pop("DECNET_INGEST_LOG_FILE", None)

    async def test_api_serves_during_worker_failure(self, live_client, token):
        """API must respond to requests even when all workers are dead."""
        # Verify multiple endpoints still work
        for endpoint in ("/api/v1/stats", "/api/v1/health", "/api/v1/logs"):
            resp = await live_client.get(
                endpoint,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code != 500, f"{endpoint} returned 500"

    async def test_sniffer_failure_invisible_to_api(self, live_client, token):
        """Sniffer crash must not affect API responses."""
        # Force sniffer to fail
        os.environ["DECNET_SNIFFER_IFACE"] = "nonexistent_iface_xyz"
        try:
            await sniffer_worker(str(Path("/tmp/sniffer-cascade.log")))
        finally:
            os.environ.pop("DECNET_SNIFFER_IFACE", None)

        # API should be completely unaffected
        resp = await live_client.get(
            "/api/v1/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    async def test_attacker_worker_independent_of_ingester(self):
        """Attacker worker runs against real DB regardless of ingester state."""
        state = _WorkerState()
        # Should work fine — it queries the DB directly, not the ingester
        await _incremental_update(repo, state)
        assert state.initialized is True
