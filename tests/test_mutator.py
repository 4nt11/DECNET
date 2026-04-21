"""
Tests for decnet.mutator — mutation engine, retry logic, due-time scheduling.
All subprocess and state I/O is mocked; no Docker or filesystem access.
"""
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from decnet.bus.fake import FakeBus
from decnet.config import DeckyConfig, DecnetConfig
from decnet.correlation.parser import parse_line
from decnet.engine import _compose_with_retry
from decnet.mutator import mutate_all, mutate_decky
from decnet.mutator.events import emit_decky_mutated


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
# emit_decky_mutated — syslog + bus round-trip
# ---------------------------------------------------------------------------

class TestEmitDeckyMutated:
    @pytest.mark.asyncio
    async def test_writes_syslog_line_and_publishes_bus_event(self, tmp_path):
        bus = FakeBus()
        await bus.connect()
        log_path = tmp_path / "subdir" / "decnet.log"
        sub = bus.subscribe("decky.*.mutation")
        try:
            async with sub:
                await emit_decky_mutated(
                    bus,
                    decky="decky-01",
                    old_services=["ssh", "http"],
                    new_services=["rdp"],
                    trigger="operator",
                    actor="anti",
                    log_path=log_path,
                )
                event = await sub.__aiter__().__anext__()
        finally:
            await bus.close()

        assert event.topic == "decky.decky-01.mutation"
        assert event.payload["trigger"] == "operator"
        assert event.payload["old_services"] == ["ssh", "http"]
        assert event.payload["new_services"] == ["rdp"]
        assert event.payload["actor"] == "anti"

        assert log_path.exists()
        lines = log_path.read_text().splitlines()
        assert len(lines) == 1
        parsed = parse_line(lines[0])
        assert parsed is not None
        assert parsed.service == "mutator"
        assert parsed.decky == "decky-01"
        assert parsed.event_type == "decky_mutated"
        assert parsed.fields["trigger"] == "operator"
        assert parsed.fields["old_services"] == "ssh,http"
        assert parsed.fields["new_services"] == "rdp"
        assert parsed.attacker_ip is None

    @pytest.mark.asyncio
    async def test_empty_set_symmetry_creation_and_retirement(self, tmp_path):
        """Creation has old_services=[]; retirement has new_services=[]."""
        bus = FakeBus()
        await bus.connect()
        log_path = tmp_path / "decnet.log"
        try:
            await emit_decky_mutated(
                bus, decky="new-decky",
                old_services=[], new_services=["ssh"],
                trigger="creation", log_path=log_path,
            )
            await emit_decky_mutated(
                bus, decky="old-decky",
                old_services=["ftp"], new_services=[],
                trigger="retirement", log_path=log_path,
            )
        finally:
            await bus.close()

        lines = log_path.read_text().splitlines()
        assert len(lines) == 2
        create = parse_line(lines[0])
        retire = parse_line(lines[1])
        assert create.fields["old_services"] == ""
        assert create.fields["trigger"] == "creation"
        assert retire.fields["new_services"] == ""
        assert retire.fields["trigger"] == "retirement"

    @pytest.mark.asyncio
    async def test_bus_none_still_writes_syslog(self, tmp_path):
        """Bus is optional; syslog is the durable record and must land alone."""
        log_path = tmp_path / "decnet.log"
        await emit_decky_mutated(
            None, decky="d1",
            old_services=["ssh"], new_services=["rdp"],
            trigger="scheduled", log_path=log_path,
        )
        assert log_path.exists()
        parsed = parse_line(log_path.read_text().strip())
        assert parsed is not None
        assert parsed.fields["trigger"] == "scheduled"

    @pytest.mark.asyncio
    async def test_syslog_failure_does_not_block_bus_publish(self):
        """If the log path is unwritable, the bus event still fires."""
        bus = AsyncMock()
        bad = Path("/dev/null/nope/decnet.log")
        await emit_decky_mutated(
            bus, decky="d1",
            old_services=[], new_services=["ssh"],
            trigger="creation", log_path=bad,
        )
        bus.publish.assert_awaited_once()


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
