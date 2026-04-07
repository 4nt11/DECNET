import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient

from decnet.web.api import app, repo


@pytest.fixture(autouse=True)
def setup_db() -> Generator[None, None, None]:
    repo.db_path = "test_decnet.db"
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)
    
    # Yield control to the test function
    yield
    
    # Teardown
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)


def test_login_success() -> None:
    with TestClient(app) as client:
        # The TestClient context manager triggers startup/shutdown events
        response = client.post(
            "/api/v1/auth/login", 
            json={"username": "admin", "password": "admin"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "must_change_password" in data
        assert data["must_change_password"] is True


def test_login_failure() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login", 
            json={"username": "admin", "password": "wrongpassword"}
        )
        assert response.status_code == 401
        
        response = client.post(
            "/api/v1/auth/login", 
            json={"username": "nonexistent", "password": "wrongpassword"}
        )
        assert response.status_code == 401


def test_change_password() -> None:
    with TestClient(app) as client:
        # First login to get token
        login_resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        token = login_resp.json()["access_token"]

        # Try changing password with wrong old password
        resp1 = client.post(
            "/api/v1/auth/change-password",
            json={"old_password": "wrong", "new_password": "new_secure_password"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp1.status_code == 401

        # Change password successfully
        resp2 = client.post(
            "/api/v1/auth/change-password",
            json={"old_password": "admin", "new_password": "new_secure_password"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp2.status_code == 200

        # Verify old password no longer works
        resp3 = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        assert resp3.status_code == 401

        # Verify new password works and must_change_password is False
        resp4 = client.post("/api/v1/auth/login", json={"username": "admin", "password": "new_secure_password"})
        assert resp4.status_code == 200
        assert resp4.json()["must_change_password"] is False


def test_get_logs_unauthorized() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/logs")
        assert response.status_code == 401


def test_get_logs_success() -> None:
    with TestClient(app) as client:
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        token = login_response.json()["access_token"]
        
        response = client.get(
            "/api/v1/logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["total"] >= 0
        assert isinstance(data["data"], list)

def test_get_stats_unauthorized() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/stats")
        assert response.status_code == 401

def test_get_stats_success() -> None:
    with TestClient(app) as client:
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        token = login_response.json()["access_token"]
        
        response = client.get(
            "/api/v1/stats",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_logs" in data
        assert "unique_attackers" in data
        assert "active_deckies" in data
