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
