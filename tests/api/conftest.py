import os
import json
import pytest
from typing import Generator, Any
from pathlib import Path
from fastapi.testclient import TestClient
from hypothesis import HealthCheck

from decnet.web.api import app
from decnet.web.dependencies import repo
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
import decnet.config

TEST_STATE_FILE = Path("test-decnet-state.json")

@pytest.fixture(scope="function", autouse=True)
def setup_db() -> Generator[None, None, None]:
    # Use a unique DB for each test process/thread if possible, but for now just one
    repo.db_path = "test_api_decnet.db"
    if os.path.exists(repo.db_path):
        try:
            os.remove(repo.db_path)
        except OSError:
            pass
    
    repo.reinitialize()
    yield
    if os.path.exists(repo.db_path):
        try:
            os.remove(repo.db_path)
        except OSError:
            pass

@pytest.fixture
def auth_token() -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
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
