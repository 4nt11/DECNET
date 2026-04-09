import os
import json
import pytest
from typing import Generator, Any, AsyncGenerator
from pathlib import Path
import httpx
from hypothesis import HealthCheck
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Ensure required env vars are set to non-bad values for tests before anything imports decnet.env
os.environ["DECNET_JWT_SECRET"] = "test-secret-key-at-least-32-chars-long!!"
os.environ["DECNET_ADMIN_PASSWORD"] = "test-password-123"

from decnet.web.api import app
from decnet.web.dependencies import repo
from decnet.web.db.sqlite.database import get_async_engine
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
import decnet.config

TEST_STATE_FILE = Path("test-decnet-state.json")

@pytest.fixture(scope="function", autouse=True)
async def setup_db(worker_id, monkeypatch) -> AsyncGenerator[None, None]:
    import uuid
    # Use worker-specific in-memory DB with shared cache for maximum speed
    unique_id = uuid.uuid4().hex
    db_path = f"file:memdb_{worker_id}_{unique_id}?mode=memory&cache=shared"
    
    # Patch the global repo singleton
    monkeypatch.setattr(repo, "db_path", db_path)
    
    engine = get_async_engine(db_path)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    monkeypatch.setattr(repo, "engine", engine)
    monkeypatch.setattr(repo, "session_factory", session_factory)
    
    # Initialize the in-memory DB (tables + admin)
    repo.reinitialize()
    
    yield
    
    await engine.dispose()

@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def auth_token(client: httpx.AsyncClient) -> str:
    resp = await client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
    return resp.json()["access_token"]

@pytest.fixture(autouse=True)
def patch_state_file(monkeypatch):
    monkeypatch.setattr(decnet.config, "STATE_FILE", TEST_STATE_FILE)

@pytest.fixture
def mock_state_file():
    _test_state = {
        "config": {
            "mode": "unihost",
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
            "gateway": "192.168.1.1",
            "deckies": [
                {
                    "name": "test-decky-1",
                    "ip": "192.168.1.10",
                    "services": ["ssh"],
                    "distro": "debian",
                    "base_image": "debian",
                    "hostname": "test-host-1",
                    "service_config": {"ssh": {"banner": "SSH-2.0-OpenSSH_8.9"}},
                    "archetype": "deaddeck",
                    "nmap_os": "linux",
                    "build_base": "debian:bookworm-slim",
                    "mutate_interval": 30,
                    "last_mutated": 0.0
                },
                {
                    "name": "test-decky-2",
                    "ip": "192.168.1.11",
                    "services": ["http"],
                    "distro": "ubuntu",
                    "base_image": "ubuntu",
                    "hostname": "test-host-2",
                    "service_config": {},
                    "archetype": None,
                    "nmap_os": "linux",
                    "build_base": "debian:bookworm-slim",
                    "mutate_interval": 30,
                    "last_mutated": 0.0
                }
            ],
            "log_target": None,
            "log_file": "test.log",
            "ipvlan": False,
            "mutate_interval": 30
        },
        "compose_path": "test-compose.yml"
    }
    TEST_STATE_FILE.write_text(json.dumps(_test_state))
    yield _test_state
    if TEST_STATE_FILE.exists():
        TEST_STATE_FILE.unlink()

# Share fuzz settings across API tests
_FUZZ_SETTINGS: dict[str, Any] = {
    "max_examples": 50,
    "deadline": None,
    "suppress_health_check": [HealthCheck.function_scoped_fixture]
}
