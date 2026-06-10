# SPDX-License-Identifier: AGPL-3.0-or-later
"""Master API startup guards: mode gating + eager JWT load.

The lifespan is what enforces these. We invoke it directly with a fresh
FastAPI app instance rather than spinning up a TestClient — TestClient
fixtures elsewhere set DECNET_JWT_SECRET globally and would mask the
"missing secret fails at boot" assertion.
"""
from __future__ import annotations

import asyncio
import importlib
import sys

import pytest
from fastapi import FastAPI


def _reload_api(monkeypatch: pytest.MonkeyPatch):
    for mod in list(sys.modules):
        if mod == "decnet.env" or mod == "decnet.web.api" or mod.startswith("decnet.env."):
            sys.modules.pop(mod)
    return importlib.import_module("decnet.web.api")


async def _run_lifespan_startup(api_mod) -> None:
    """Run the lifespan up to (but not past) yield, then unwind cleanly.

    DECNET_CONTRACT_TEST suppresses all background workers (ingestion,
    collector, TTP, tarpit) so no tasks escape test teardown.
    """
    import os
    os.environ["DECNET_CONTRACT_TEST"] = "true"
    try:
        app = FastAPI()
        cm = api_mod.lifespan(app)
        await cm.__aenter__()
        try:
            return
        finally:
            try:
                await cm.__aexit__(None, None, None)
            except Exception:
                pass
    finally:
        os.environ.pop("DECNET_CONTRACT_TEST", None)


def test_master_api_refuses_to_start_in_agent_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DECNET_MODE", "agent")
    monkeypatch.setenv("DECNET_DISALLOW_MASTER", "true")
    monkeypatch.setenv("DECNET_JWT_SECRET", "x" * 32)
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "http://localhost:8080")
    api = _reload_api(monkeypatch)
    with pytest.raises(RuntimeError, match="master-only"):
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            _run_lifespan_startup(api)
        )


def test_master_api_starts_when_dual_role_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DECNET_DISALLOW_MASTER=false is the documented escape hatch for
    dev hosts that play both sides — must not trip the gate."""
    monkeypatch.setenv("DECNET_MODE", "agent")
    monkeypatch.setenv("DECNET_DISALLOW_MASTER", "false")
    monkeypatch.setenv("DECNET_JWT_SECRET", "x" * 32)
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "http://localhost:8080")
    api = _reload_api(monkeypatch)
    # Reaching the DB init phase means the gate passed; we don't need to
    # actually finish startup. Cancel via a synthetic exception that the
    # lifespan doesn't catch.
    # Reaching repo.initialize means the gate passed. We don't actually
    # need DB to come up — short-circuit and assert no master-only raise.
    seen: list[str] = []

    async def _spy(*_a, **_kw):
        seen.append("init_called")

    monkeypatch.setattr(api.repo, "initialize", _spy)
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        _run_lifespan_startup(api)
    )
    assert seen == ["init_called"], "DB init should have been reached, gate must be inert"


def test_master_api_eager_loads_jwt_secret_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lifespan must touch DECNET_JWT_SECRET so a missing/insecure
    value fails at boot rather than on the first auth-gated request.

    We can't realistically exercise the raise-on-missing path in this
    repo: dev hosts have a populated .env.local that dotenv auto-loads,
    and conftest seeds a JWT secret globally. The actual raise behaviour
    is covered by tests/web/test_env_lazy_jwt.py — here we just assert
    the lifespan calls into the env module's lazy resolver.
    """
    monkeypatch.setenv("DECNET_MODE", "master")
    monkeypatch.setenv("DECNET_JWT_SECRET", "y" * 32)
    monkeypatch.setenv("DECNET_API_HOST", "127.0.0.1")
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "http://localhost:8080")
    api = _reload_api(monkeypatch)
    import decnet.env as env_mod

    seen: list[str] = []
    real_getattr = env_mod.__getattr__

    def _spy(name: str) -> str:
        seen.append(name)
        return real_getattr(name)

    monkeypatch.setattr(env_mod, "__getattr__", _spy, raising=False)

    async def _noop_init(*_a, **_kw) -> None:
        return None

    monkeypatch.setattr(api.repo, "initialize", _noop_init)
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        _run_lifespan_startup(api)
    )
    assert "DECNET_JWT_SECRET" in seen, (
        "lifespan must access env.DECNET_JWT_SECRET at startup"
    )


# ---------------------------------------------------------------------------
# V13.1.4 — CORS wildcard guard
# ---------------------------------------------------------------------------

def test_cors_wildcard_guard_function_raises() -> None:
    """_check_cors_origins raises ValueError when '*' is in the list."""
    from decnet.web.api import _check_cors_origins
    with pytest.raises(ValueError, match="wildcard"):
        _check_cors_origins(["*"])


def test_cors_wildcard_among_explicit_origins_raises() -> None:
    """Wildcard in a mixed list is still rejected."""
    from decnet.web.api import _check_cors_origins
    with pytest.raises(ValueError, match="wildcard"):
        _check_cors_origins(["https://example.com", "*"])


def test_cors_explicit_origins_pass() -> None:
    """Explicit origin URLs pass the guard without raising."""
    from decnet.web.api import _check_cors_origins
    _check_cors_origins(["https://example.com", "https://app.internal"])


def test_cors_wildcard_raises_in_lifespan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lifespan raises ValueError when DECNET_CORS_ORIGINS contains '*'.

    Uses _reload_api to pick up the patched env; tests the full guard
    path including the lifespan call to _check_cors_origins.
    """
    monkeypatch.setenv("DECNET_MODE", "master")
    monkeypatch.setenv("DECNET_JWT_SECRET", "z" * 32)
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "*")
    api = _reload_api(monkeypatch)
    with pytest.raises(ValueError, match="wildcard"):
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            _run_lifespan_startup(api)
        )
