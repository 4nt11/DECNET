# SPDX-License-Identifier: AGPL-3.0-or-later
"""Credential-reuse correlator tests.

Covers:
- ``CorrelationEngine.correlate_credential_reuse`` — group detection,
  threshold gating, idempotency on a second call.
- ``run_reuse_loop`` — bus-driven wake, reuse.detected publish on
  insert/grow, clean shutdown via the *shutdown* signal.
- Repo helper ``find_credential_reuse_candidates`` — used by the engine.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
from pathlib import Path

import pytest

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.correlation.engine import CorrelationEngine
from decnet.correlation.reuse_worker import run_reuse_loop
from decnet.web.db.factory import get_repository


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "reuse_corr.db"))
    await r.initialize()
    return r


async def _seed_credential(repo, **overrides):
    base = {
        "attacker_ip": "10.0.0.5",
        "decky_name": "decky-01",
        "service": "ssh",
        "principal": "root",
        "secret_kind": "plaintext",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {},
    }
    base.update(overrides)
    return await repo.upsert_credential(base)


# ─── find_credential_reuse_candidates ────────────────────────────────────────


class TestFindCandidates:
    @pytest.mark.anyio
    async def test_below_threshold_excluded(self, repo) -> None:
        sha = _sha256("solo")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")

        groups = await repo.find_credential_reuse_candidates(min_targets=2)
        assert groups == []

    @pytest.mark.anyio
    async def test_threshold_exact_match_included(self, repo) -> None:
        sha = _sha256("p4ss")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

        groups = await repo.find_credential_reuse_candidates(min_targets=2)
        assert len(groups) == 1
        g = groups[0]
        assert g["secret_sha256"] == sha
        assert g["secret_kind"] == "plaintext"
        assert g["target_count"] == 2
        assert len(g["credentials"]) == 2

    @pytest.mark.anyio
    async def test_distinct_principals_form_distinct_groups(self, repo) -> None:
        """Same secret + different principals → two separate groups."""
        sha = _sha256("hunter2")
        await _seed_credential(
            repo, secret_sha256=sha, principal="root",
            decky_name="d1", service="ssh",
        )
        await _seed_credential(
            repo, secret_sha256=sha, principal="root",
            decky_name="d2", service="ftp",
        )
        await _seed_credential(
            repo, secret_sha256=sha, principal="admin",
            decky_name="d1", service="ssh",
        )
        await _seed_credential(
            repo, secret_sha256=sha, principal="admin",
            decky_name="d2", service="ftp",
        )

        groups = await repo.find_credential_reuse_candidates(min_targets=2)
        principals = sorted(g["principal"] for g in groups)
        assert principals == ["admin", "root"]

    @pytest.mark.anyio
    async def test_repeated_decky_service_does_not_count_twice(self, repo) -> None:
        """A repeat attempt on the same (decky, service) doesn't pad target_count."""
        sha = _sha256("h2")
        # Two attempts on the same decky/service → upsert dedups.
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")

        groups = await repo.find_credential_reuse_candidates(min_targets=2)
        assert groups == []


# ─── CorrelationEngine.correlate_credential_reuse ────────────────────────────


class TestEngineCorrelate:
    @pytest.mark.anyio
    async def test_emits_reuse_for_qualifying_group(self, repo) -> None:
        sha = _sha256("hunter2")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

        engine = CorrelationEngine()
        results = await engine.correlate_credential_reuse(repo, min_targets=2)

        assert len(results) >= 1
        assert any(r.get("inserted") for r in results)

        total, rows = await repo.list_credential_reuses(min_target_count=2)
        assert total == 1
        assert rows[0]["target_count"] == 2

    @pytest.mark.anyio
    async def test_below_threshold_persists_nothing(self, repo) -> None:
        sha = _sha256("loner")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")

        engine = CorrelationEngine()
        results = await engine.correlate_credential_reuse(repo, min_targets=2)

        assert results == []
        total, _ = await repo.list_credential_reuses(min_target_count=2)
        assert total == 0

    @pytest.mark.anyio
    async def test_idempotent_on_second_run(self, repo) -> None:
        """A second call with no new credentials returns no
        insert/grow rows and leaves the table at the same row count.
        """
        sha = _sha256("idempotent")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

        engine = CorrelationEngine()
        await engine.correlate_credential_reuse(repo, min_targets=2)
        before_total, _ = await repo.list_credential_reuses(min_target_count=2)

        results2 = await engine.correlate_credential_reuse(repo, min_targets=2)
        after_total, _ = await repo.list_credential_reuses(min_target_count=2)

        assert before_total == after_total == 1
        assert results2 == []

    @pytest.mark.anyio
    async def test_list_and_get_enrich_with_secret(self, repo) -> None:
        """``list_credential_reuses`` and ``get_credential_reuse_by_id``
        must surface ``secret_printable`` + ``secret_b64`` from the
        underlying ``Credential`` rows so the dashboard drawer can show
        the actual secret instead of just its sha256.
        """
        sha = _sha256("hunter2")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

        engine = CorrelationEngine()
        await engine.correlate_credential_reuse(repo, min_targets=2)

        _, rows = await repo.list_credential_reuses(min_target_count=2)
        assert rows[0]["secret_printable"] == "hunter2"
        assert rows[0]["secret_b64"] == "aHVudGVyMg=="

        single = await repo.get_credential_reuse_by_id(rows[0]["id"])
        assert single is not None
        assert single["secret_printable"] == "hunter2"
        assert single["secret_b64"] == "aHVudGVyMg=="

    @pytest.mark.anyio
    async def test_growth_emits_changed(self, repo) -> None:
        """Adding a third target after an initial reuse run yields a
        ``changed`` row on the next correlation pass.
        """
        sha = _sha256("grower")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

        engine = CorrelationEngine()
        await engine.correlate_credential_reuse(repo, min_targets=2)

        await _seed_credential(repo, secret_sha256=sha, decky_name="d3", service="rdp")
        results = await engine.correlate_credential_reuse(repo, min_targets=2)

        assert any(r.get("changed") for r in results)
        _, rows = await repo.list_credential_reuses(min_target_count=2)
        assert rows[0]["target_count"] == 3


# ─── run_reuse_loop ──────────────────────────────────────────────────────────


class TestRunReuseLoop:
    @pytest.mark.anyio
    async def test_publishes_reuse_detected_on_insert(self, repo, monkeypatch) -> None:
        """One ``credential.reuse.detected`` per new CredentialReuse row."""
        bus = FakeBus()
        await bus.connect()

        # Force the worker to pick up our FakeBus.
        from decnet.correlation import reuse_worker as _rw
        monkeypatch.setattr(_rw, "get_bus", lambda client_name=None: bus)

        sha = _sha256("loop-insert")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

        sub = bus.subscribe(_topics.credential(_topics.CREDENTIAL_REUSE_DETECTED))
        shutdown = asyncio.Event()
        task = asyncio.create_task(run_reuse_loop(
            repo, poll_interval_secs=60.0, min_targets=2, shutdown=shutdown,
        ))

        # Wait for the first tick to publish.
        async with sub:
            event = await asyncio.wait_for(sub.__anext__(), timeout=5.0)

        assert event.topic == _topics.credential(_topics.CREDENTIAL_REUSE_DETECTED)
        assert event.payload["target_count"] == 2
        assert event.payload["secret_kind"] == "plaintext"

        shutdown.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await bus.close()

    @pytest.mark.anyio
    async def test_no_reuse_no_publish(self, repo, monkeypatch) -> None:
        """A loop with no qualifying groups publishes nothing on its tick."""
        bus = FakeBus()
        await bus.connect()
        from decnet.correlation import reuse_worker as _rw
        monkeypatch.setattr(_rw, "get_bus", lambda client_name=None: bus)

        sha = _sha256("loner-loop")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")

        sub = bus.subscribe(_topics.credential(_topics.CREDENTIAL_REUSE_DETECTED))
        shutdown = asyncio.Event()
        task = asyncio.create_task(run_reuse_loop(
            repo, poll_interval_secs=0.05, min_targets=2, shutdown=shutdown,
        ))

        # Let the loop run a few ticks.
        await asyncio.sleep(0.3)

        async with sub:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sub.__anext__(), timeout=0.1)

        shutdown.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await bus.close()

    @pytest.mark.anyio
    async def test_no_duplicate_publish_on_second_tick(
        self, repo, monkeypatch,
    ) -> None:
        """A subsequent tick with no new credentials must not republish."""
        bus = FakeBus()
        await bus.connect()
        from decnet.correlation import reuse_worker as _rw
        monkeypatch.setattr(_rw, "get_bus", lambda client_name=None: bus)

        sha = _sha256("once")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
        await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

        sub = bus.subscribe(_topics.credential(_topics.CREDENTIAL_REUSE_DETECTED))
        shutdown = asyncio.Event()
        task = asyncio.create_task(run_reuse_loop(
            repo, poll_interval_secs=0.05, min_targets=2, shutdown=shutdown,
        ))

        # Drain the first publish (the insert).
        async with sub:
            await asyncio.wait_for(sub.__anext__(), timeout=5.0)

            # Subsequent ticks must produce no further publishes.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sub.__anext__(), timeout=0.3)

        shutdown.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await bus.close()
