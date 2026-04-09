import json
import pytest
from fastapi.testclient import TestClient
from decnet.web.api import app
import decnet.config
from pathlib import Path
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.api import repo

@pytest.fixture(autouse=True)
def setup_db():
    repo.db_path = "test_fleet_decnet.db"
    import os
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)
    repo.reinitialize()
    yield
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)

TEST_STATE_FILE = Path("test-decnet-state.json")

@pytest.fixture(autouse=True)
def patch_state_file(monkeypatch):
    # Patch the global STATE_FILE variable in the config module
    monkeypatch.setattr(decnet.config, "STATE_FILE", TEST_STATE_FILE)

@pytest.fixture
def mock_state_file():
    # Create a dummy state file for testing
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
                    "build_base": "debian:bookworm-slim"
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
                    "build_base": "debian:bookworm-slim"
                }
            ],
            "log_target": None,
            "log_file": "test.log",
            "ipvlan": False
        },
        "compose_path": "test-compose.yml"
    }
    TEST_STATE_FILE.write_text(json.dumps(_test_state))
    
    yield _test_state
    
    # Cleanup
    if TEST_STATE_FILE.exists():
        TEST_STATE_FILE.unlink()

def test_get_deckies_endpoint(mock_state_file):
    with TestClient(app) as _client:
        # Login to get token
        _login_resp = _client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
        _token = _login_resp.json()["access_token"]
        
        _response = _client.get("/api/v1/deckies", headers={"Authorization": f"Bearer {_token}"})
        assert _response.status_code == 200
        _data = _response.json()
        assert len(_data) == 2
        assert _data[0]["name"] == "test-decky-1"
        assert _data[0]["service_config"]["ssh"]["banner"] == "SSH-2.0-OpenSSH_8.9"

def test_stats_includes_deployed_count(mock_state_file):
    with TestClient(app) as _client:
        _login_resp = _client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
        _token = _login_resp.json()["access_token"]
        
        _response = _client.get("/api/v1/stats", headers={"Authorization": f"Bearer {_token}"})
        assert _response.status_code == 200
        _data = _response.json()
        assert "deployed_deckies" in _data
        assert _data["deployed_deckies"] == 2
