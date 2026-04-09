import os
import json
import uuid as _uuid
import pytest
from typing import Any, AsyncGenerator
from pathlib import Path
from sqlmodel import SQLModel
import httpx
from hypothesis import HealthCheck
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

# Must be set before any decnet import touches decnet.env
os.environ["DECNET_JWT_SECRET"] = "test-secret-key-at-least-32-chars-long!!"
os.environ["DECNET_ADMIN_PASSWORD"] = "test-password-123"

from decnet.web.api import app
from decnet.web.dependencies import repo
from decnet.web.db.models import User
from decnet.web.auth import get_password_hash
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
import decnet.config


@pytest.fixture(scope="function", autouse=True)
async def setup_db(monkeypatch) -> AsyncGenerator[None, None]:
    # Unique in-memory DB per test — no file I/O, no WAL/SHM side-cars
    db_url = f"sqlite+aiosqlite:///file:testdb_{_uuid.uuid4().hex}?mode=memory&cache=shared"
    engine = create_async_engine(db_url, connect_args={"uri": True}, poolclass=StaticPool)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Patch BOTH — session_factory is what all queries actually use
    monkeypatch.setattr(repo, "engine", engine)
    monkeypatch.setattr(repo, "session_factory", session_factory)

    # Create schema
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    # Seed admin user
    async with session_factory() as session:
        if not (await session.execute(select(User).where(User.username == DECNET_ADMIN_USER))).scalar_one_or_none():
            session.add(User(
                uuid=str(_uuid.uuid4()),
                username=DECNET_ADMIN_USER,
                password_hash=get_password_hash(DECNET_ADMIN_PASSWORD),
                role="admin",
                must_change_password=True,
            ))
            await session.commit()

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
def patch_state_file(monkeypatch, tmp_path) -> Path:
    state_file = tmp_path / "decnet-state.json"
    monkeypatch.setattr(decnet.config, "STATE_FILE", state_file)
    return state_file

@pytest.fixture
def mock_state_file(patch_state_file: Path):
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
    patch_state_file.write_text(json.dumps(_test_state))
    yield _test_state

# Share fuzz settings across API tests
# FUZZ_EXAMPLES: keep low for dev speed; bump via HYPOTHESIS_MAX_EXAMPLES env var in CI
import os as _os
_FUZZ_EXAMPLES = int(_os.environ.get("HYPOTHESIS_MAX_EXAMPLES", "10"))
_FUZZ_SETTINGS: dict[str, Any] = {
    "max_examples": _FUZZ_EXAMPLES,
    "deadline": None,
    "suppress_health_check": [HealthCheck.function_scoped_fixture],
}
