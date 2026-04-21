"""
Tests for decnet.mutator — mutation engine, retry logic, due-time scheduling.
All subprocess and state I/O is mocked; no Docker or filesystem access.
"""
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from decnet.config import DeckyConfig, DecnetConfig
from decnet.engine import _compose_with_retry
from decnet.mutator import mutate_all, mutate_decky


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_decky(name="decky-01", services=None, archetype=None,
                mutate_interval=30, last_mutated=0.0):
    return DeckyConfig(
        name=name,
        ip="192.168.1.10",
        services=services or ["ssh"],
        distro="debian",
        base_image="debian",
        hostname="host-01",
        archetype=archetype,
        mutate_interval=mutate_interval,
        last_mutated=last_mutated,
    )


def _make_config(deckies=None, mutate_interval=30):
    return DecnetConfig(
        mode="unihost", interface="eth0",
        subnet="192.168.1.0/24", gateway="192.168.1.1",
        deckies=deckies or [_make_decky()],
        mutate_interval=mutate_interval,
    )

@pytest.fixture
def mock_repo():
    repo = AsyncMock()
    repo.get_state.return_value = None
    return repo


# ---------------------------------------------------------------------------
# mutate_decky
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMutateDecky:
    def _patch_io(self):
        """Return a context manager that mocks all other I/O in mutate_decky."""
        return (
            patch("decnet.mutator.engine.write_compose"),
            patch("decnet.mutator.engine._compose_with_retry", new_callable=AsyncMock),
        )

    async def test_returns_false_when_no_state(self, mock_repo):
        mock_repo.get_state.return_value = None
        assert await mutate_decky("decky-01", repo=mock_repo) is False

    async def test_returns_false_when_decky_not_found(self, mock_repo):
        cfg = _make_config()
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        assert await mutate_decky("nonexistent", repo=mock_repo) is False

    async def test_returns_true_on_success(self, mock_repo):
        cfg = _make_config()
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.write_compose"), \
             patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
            assert await mutate_decky("decky-01", repo=mock_repo) is True

    async def test_saves_state_after_mutation(self, mock_repo):
        cfg = _make_config()
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.write_compose"), \
             patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
            await mutate_decky("decky-01", repo=mock_repo)
        mock_repo.set_state.assert_awaited_once()

    async def test_regenerates_compose_after_mutation(self, mock_repo):
        cfg = _make_config()
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.write_compose") as mock_compose, \
             patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
            await mutate_decky("decky-01", repo=mock_repo)
        mock_compose.assert_called_once()

    async def test_returns_false_on_compose_failure(self, mock_repo):
        cfg = _make_config()
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.write_compose"), \
             patch("anyio.to_thread.run_sync", side_effect=Exception("docker fail")):
            assert await mutate_decky("decky-01", repo=mock_repo) is False

    async def test_mutation_changes_services(self, mock_repo):
        cfg = _make_config(deckies=[_make_decky(services=["ssh"])])
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.write_compose"), \
             patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
            await mutate_decky("decky-01", repo=mock_repo)
        
        # Check that set_state was called with a config where services might have changed
        call_args = mock_repo.set_state.await_args[0]
        new_config_dict = call_args[1]["config"]
        new_services = new_config_dict["deckies"][0]["services"]
        assert isinstance(new_services, list)
        assert len(new_services) >= 1

    async def test_updates_last_mutated_timestamp(self, mock_repo):
        cfg = _make_config(deckies=[_make_decky(last_mutated=0.0)])
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        before = time.time()
        with patch("decnet.mutator.engine.write_compose"), \
             patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
            await mutate_decky("decky-01", repo=mock_repo)
        
        call_args = mock_repo.set_state.await_args[0]
        new_last_mutated = call_args[1]["config"]["deckies"][0]["last_mutated"]
        assert new_last_mutated >= before

# ---------------------------------------------------------------------------
# mutate_all
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMutateAll:
    async def test_no_state_returns_early(self, mock_repo):
        mock_repo.get_state.return_value = None
        with patch("decnet.mutator.engine.mutate_decky") as mock_mutate:
            await mutate_all(repo=mock_repo)
        mock_mutate.assert_not_called()

    async def test_force_mutates_all_deckies(self, mock_repo):
        cfg = _make_config(deckies=[_make_decky("d1"), _make_decky("d2")])
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.mutate_decky", new_callable=AsyncMock, return_value=True) as mock_mutate:
            await mutate_all(repo=mock_repo, force=True)
        assert mock_mutate.call_count == 2

    async def test_skips_decky_not_yet_due(self, mock_repo):
        # last_mutated = now, interval = 30 min → not due
        now = time.time()
        cfg = _make_config(deckies=[_make_decky(mutate_interval=30, last_mutated=now)])
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.mutate_decky") as mock_mutate:
            await mutate_all(repo=mock_repo, force=False)
        mock_mutate.assert_not_called()

    async def test_mutates_decky_that_is_due(self, mock_repo):
        # last_mutated = 2 hours ago, interval = 30 min → due
        old_ts = time.time() - 7200
        cfg = _make_config(deckies=[_make_decky(mutate_interval=30, last_mutated=old_ts)])
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.mutate_decky", new_callable=AsyncMock, return_value=True) as mock_mutate:
            await mutate_all(repo=mock_repo, force=False)
        mock_mutate.assert_called_once()

    async def test_no_state_returns_none_not_error(self, mock_repo):
        """Missing deployment is idle, not an error — must return None."""
        mock_repo.get_state.return_value = None
        assert await mutate_all(repo=mock_repo) is None

    async def test_returns_seconds_until_next_due(self, mock_repo):
        # Two deckies: one 10 min to go, one 25 min to go → min is ~600s
        now = time.time()
        cfg = _make_config(deckies=[
            _make_decky("d1", mutate_interval=30, last_mutated=now - 20 * 60),
            _make_decky("d2", mutate_interval=30, last_mutated=now - 5 * 60),
        ])
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.mutate_decky", new_callable=AsyncMock):
            next_due = await mutate_all(repo=mock_repo, force=False)
        assert next_due is not None
        assert 590 < next_due < 610  # ~10 min

    async def test_only_filter_forces_named_decky(self, mock_repo):
        """only={'d1'} mutates d1 regardless of schedule, skips others."""
        now = time.time()
        cfg = _make_config(deckies=[
            _make_decky("d1", mutate_interval=30, last_mutated=now),  # not due
            _make_decky("d2", mutate_interval=30, last_mutated=now),  # not due
        ])
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        with patch("decnet.mutator.engine.mutate_decky", new_callable=AsyncMock, return_value=True) as mock_mutate:
            await mutate_all(repo=mock_repo, force=False, only={"d1"})
        assert mock_mutate.call_count == 1
        assert mock_mutate.call_args.args[0] == "d1"


class TestMutateDeckyBusPublish:
    @pytest.mark.asyncio
    async def test_publishes_decky_state_on_success(self, mock_repo):
        cfg = _make_config()
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        bus = AsyncMock()
        with patch("decnet.mutator.engine.write_compose"), \
             patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
            ok = await mutate_decky("decky-01", repo=mock_repo, bus=bus)
        assert ok is True
        bus.publish.assert_awaited_once()
        topic = bus.publish.await_args.args[0]
        payload = bus.publish.await_args.args[1]
        assert topic == "decky.decky-01.state"
        assert payload["name"] == "decky-01"
        assert isinstance(payload["services"], list)

    @pytest.mark.asyncio
    async def test_no_publish_on_compose_failure(self, mock_repo):
        cfg = _make_config()
        mock_repo.get_state.return_value = {"config": cfg.model_dump(), "compose_path": "c.yml"}
        bus = AsyncMock()
        with patch("decnet.mutator.engine.write_compose"), \
             patch("anyio.to_thread.run_sync",
                   new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            ok = await mutate_decky("decky-01", repo=mock_repo, bus=bus)
        assert ok is False
        bus.publish.assert_not_awaited()


# ---------------------------------------------------------------------------
# _compose_with_retry (Sync tests, keep as is or minimal update)
# ---------------------------------------------------------------------------

class TestComposeWithRetry:
    def test_succeeds_on_first_attempt(self):
        result = MagicMock(returncode=0, stdout="done\n")
        with patch("decnet.engine.deployer.subprocess.run", return_value=result) as mock_run:
            _compose_with_retry("up", "-d", compose_file=Path("compose.yml"))
        mock_run.assert_called_once()

    def test_retries_on_failure_then_succeeds(self):
        fail = MagicMock(returncode=1, stdout="", stderr="transient error")
        ok   = MagicMock(returncode=0, stdout="", stderr="")
        with patch("decnet.engine.deployer.subprocess.run", side_effect=[fail, ok]) as mock_run, \
             patch("decnet.engine.deployer.time.sleep"):
            _compose_with_retry("up", "-d", compose_file=Path("compose.yml"), retries=3)
        assert mock_run.call_count == 2
