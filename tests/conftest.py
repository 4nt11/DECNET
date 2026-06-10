# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Shared pytest configuration.

Env vars required by decnet.env must be set here, at module level, before
any test file imports decnet.* — pytest loads conftest.py first.
"""
import os
import tempfile

# Redirect log paths to a user-writable tempdir so unprivileged test runs
# (CI, local sans-sudo) don't try to mkdir /var/log/decnet.
_TEST_LOG_DIR = os.path.join(tempfile.gettempdir(), "decnet-tests-logs")
os.makedirs(_TEST_LOG_DIR, exist_ok=True)
os.environ.setdefault("DECNET_LOG_FILE", os.path.join(_TEST_LOG_DIR, "decnet.log"))
os.environ.setdefault("DECNET_INGEST_LOG_FILE", os.path.join(_TEST_LOG_DIR, "decnet.log"))
os.environ.setdefault("DECNET_AGENT_LOG_FILE", os.path.join(_TEST_LOG_DIR, "agent.log"))

# Explicit test-harness flag: tells env._require_env to skip secret-strength
# validation so the suite can run with weak/short secrets. This is the ONLY
# bypass — it replaced the old "any PYTEST* var present" fail-open check (V2.1.7).
os.environ["DECNET_TESTING"] = "1"

os.environ["DECNET_JWT_SECRET"] = "stable-test-secret-key-at-least-32-chars-long"
os.environ["DECNET_ADMIN_PASSWORD"] = "test-password-123"
os.environ["DECNET_DEVELOPER"] = "true"
os.environ["DECNET_DEVELOPER_TRACING"] = "false"
os.environ["DECNET_DB_TYPE"] = "sqlite"

# GeoIP enrichment is offline-by-design (RIR delegated-stats) but the
# first access triggers a background file fetch. Unit tests must never
# hit the network and don't care about country codes — disable
# enrichment globally. The geoip-specific tests re-enable it via
# monkeypatch + a temp DECNET_GEOIP_ROOT.
os.environ["DECNET_GEOIP_ENABLED"] = "false"
# Same posture for PTR resolution — tests that cover the resolver
# re-enable it explicitly via monkeypatch; everyone else gets the
# short-circuit (returns None without touching socket.gethostbyaddr).
os.environ["DECNET_PTR_ENABLED"] = "false"

import pytest
from typing import Any

@pytest.fixture(autouse=True)
def standardize_auth_secret(monkeypatch: Any) -> None:
    import decnet.web.auth
    monkeypatch.setattr(decnet.web.auth, "SECRET_KEY", os.environ["DECNET_JWT_SECRET"])
