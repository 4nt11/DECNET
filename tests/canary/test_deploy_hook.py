# SPDX-License-Identifier: AGPL-3.0-or-later
"""Smoke coverage for the deploy-time canary baseline seed.

The deployer hook calls ``decnet.canary.planter.seed_baseline`` for
every running decky.  Two properties matter:

* a baseline seed runs, producing one token row per configured
  generator; and
* failures in seed_baseline must never abort the surrounding
  deploy flow (resilience principle).

We don't drive the full ``deploy()`` here — that pulls in docker,
network helpers, etc.  Instead we exercise ``seed_baseline``
directly with the planter's docker-exec patched, then assert the
hook's wiring via static inspection.
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator
from unittest.mock import patch

import pytest
import pytest_asyncio

from decnet.canary import planter
from decnet.web.db.sqlite.repository import SQLiteRepository
import decnet.web.db.models  # noqa: F401


class _FakeProc:
    def __init__(self, rc: int = 0, stderr: bytes = b"") -> None:
        self.returncode = rc
        self._stderr = stderr

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return b"", self._stderr


def _patch(rc: int = 0, stderr: bytes = b""):
    async def _fake(*argv, **kw):  # noqa: ANN001
        return _FakeProc(rc, stderr)
    return patch.object(asyncio, "create_subprocess_exec", _fake)


@pytest_asyncio.fixture
async def repo(tmp_path) -> AsyncIterator[SQLiteRepository]:
    r = SQLiteRepository(str(tmp_path / "h.db"))
    await r.initialize()
    yield r


@pytest.mark.asyncio
async def test_baseline_creates_tokens_per_decky(
    repo: SQLiteRepository, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BASELINE", "git_config,env_file,aws_creds")
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    with _patch(rc=0):
        await planter.seed_baseline("web1", repo)
        await planter.seed_baseline("web2", repo)
    web1 = await repo.list_canary_tokens(decky_name="web1")
    web2 = await repo.list_canary_tokens(decky_name="web2")
    assert len(web1) == 3 and len(web2) == 3
    assert {t["generator"] for t in web1} == {"git_config", "env_file", "aws_creds"}


def test_deploy_hook_is_wired_into_deployer() -> None:
    """Static check: deployer's _mirror_fleet_to_db calls seed_baseline.

    We grep the source rather than driving the full deploy() because
    that pulls in docker + networking helpers and we don't want a
    second test environment for this one assertion.
    """
    import inspect
    from decnet.engine import deployer
    source = inspect.getsource(deployer)
    assert "seed_baseline" in source, "deployer must call canary.planter.seed_baseline"
    # And the call must be wrapped in try/except so a failure doesn't
    # abort the deploy.
    assert "canary baseline seed failed (best-effort)" in source
