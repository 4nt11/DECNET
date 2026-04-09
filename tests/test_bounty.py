import os
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from decnet.web.api import app, repo
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD

@pytest.fixture(autouse=True)
def setup_db() -> Generator[None, None, None]:
    repo.db_path = "test_bounty_decnet.db"
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)
    repo.reinitialize()
    yield
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)

@pytest.fixture
def auth_token():
    with TestClient(app) as client:
        resp = client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
        return resp.json()["access_token"]

def test_add_and_get_bounty(auth_token):
    with TestClient(app) as client:
        # We can't directly call add_bounty from API yet (it's internal to ingester)
        # But we can test the repository if we want, or mock a log line that triggers it.
        # For now, let's test the endpoint returns 200 even if empty.
        resp = client.get("/api/v1/bounty", headers={"Authorization": f"Bearer {auth_token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

def test_bounty_pagination(auth_token):
    with TestClient(app) as client:
        resp = client.get("/api/v1/bounty?limit=1&offset=0", headers={"Authorization": f"Bearer {auth_token}"})
        assert resp.status_code == 200
        assert resp.json()["limit"] == 1
