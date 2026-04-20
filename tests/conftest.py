"""
Shared pytest configuration.

Env vars required by decnet.env must be set here, at module level, before
any test file imports decnet.* — pytest loads conftest.py first.
"""
import os

os.environ["DECNET_JWT_SECRET"] = "stable-test-secret-key-at-least-32-chars-long"
os.environ["DECNET_ADMIN_PASSWORD"] = "test-password-123"
os.environ["DECNET_DEVELOPER"] = "true"
os.environ["DECNET_DEVELOPER_TRACING"] = "false"
os.environ["DECNET_DB_TYPE"] = "sqlite"

import pytest
from typing import Any

@pytest.fixture(autouse=True)
def standardize_auth_secret(monkeypatch: Any) -> None:
    import decnet.web.auth
    monkeypatch.setattr(decnet.web.auth, "SECRET_KEY", os.environ["DECNET_JWT_SECRET"])
