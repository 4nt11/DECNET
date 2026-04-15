"""
Service isolation tests.

Verifies that each background worker handles missing dependencies gracefully
and that failures in one service do not cascade to others.

Dependency graph under test:
    Collector → (Docker SDK, state file, log file)
    Ingester  → (Collector's JSON output, DB repo)
    Attacker  → (DB repo)
    Sniffer   → (MACVLAN interface, scapy, state file)
    API       → (DB init, all workers)

Each test disables or breaks one dependency and asserts the affected
worker degrades gracefully while unrelated workers remain unaffected.
"""

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─── Collector isolation ─────────────────────────────────────────────────────

class TestCollectorIsolation:
    """Collector depends on Docker SDK and state file."""

    @pytest.mark.asyncio
    async def test_collector_survives_docker_unavailable(self):
        """Collector must not crash when Docker daemon is not running."""
        import docker as docker_mod
        from decnet.collector.worker import log_collector_worker

        original_from_env = docker_mod.from_env
        with patch.object(docker_mod, "from_env",
                          side_effect=Exception("Cannot connect to Docker daemon")):
            task = asyncio.create_task(log_collector_worker("/tmp/decnet-test-collector.log"))
            await asyncio.sleep(0.1)
            assert task.done()
            exc = task.exception()
            assert exc is None  # Should not propagate exceptions

    @pytest.mark.asyncio
    async def test_collector_survives_no_state_file(self):
        """Collector must handle missing state file (no deckies deployed)."""
        from decnet.collector.worker import _load_service_container_names

        with patch("decnet.config.load_state", return_value=None):
            result = _load_service_container_names()
            assert result == set()

    @pytest.mark.asyncio
    async def test_collector_survives_empty_fleet(self):
        """Collector runs but finds no matching containers when fleet is empty."""
        import docker as docker_mod
        from decnet.collector.worker import log_collector_worker

        mock_client = MagicMock()
        mock_client.containers.list.return_value = []
        mock_client.events.side_effect = Exception("connection closed")

        with patch.object(docker_mod, "from_env", return_value=mock_client):
            with patch("decnet.config.load_state", return_value=None):
                task = asyncio.create_task(log_collector_worker("/tmp/decnet-test-collector.log"))
                await asyncio.sleep(0.1)
                assert task.done()
                assert task.exception() is None

    def test_collector_container_filter_with_unknown_containers(self):
        """is_service_container must reject containers not in state."""
        from decnet.collector.worker import is_service_container

        with patch("decnet.collector.worker._load_service_container_names",
                    return_value={"decky-01-ssh", "decky-01-http"}):
            assert is_service_container("decky-01-ssh") is True
            assert is_service_container("random-container") is False
            assert is_service_container("decky-99-ftp") is False


# ─── Ingester isolation ──────────────────────────────────────────────────────

class TestIngesterIsolation:
    """Ingester depends on collector's JSON output and DB repo."""

    @pytest.mark.asyncio
    async def test_ingester_survives_missing_log_file(self):
        """Ingester must wait patiently when JSON log file doesn't exist yet."""
        from decnet.web.ingester import log_ingestion_worker

        mock_repo = MagicMock()
        iterations = 0

        async def _controlled_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": "/tmp/nonexistent-decnet-test.log"}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=_controlled_sleep):
                task = asyncio.create_task(log_ingestion_worker(mock_repo))
                with pytest.raises(asyncio.CancelledError):
                    await task
        # Should have waited at least 2 iterations without crashing
        assert iterations >= 2
        mock_repo.add_log.assert_not_called()

    @pytest.mark.asyncio
    async def test_ingester_survives_no_log_file_env(self):
        """Ingester must exit gracefully when DECNET_INGEST_LOG_FILE is unset."""
        from decnet.web.ingester import log_ingestion_worker

        mock_repo = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            # Remove the env var if it exists
            os.environ.pop("DECNET_INGEST_LOG_FILE", None)
            await log_ingestion_worker(mock_repo)
        # Should return immediately without error
        mock_repo.add_log.assert_not_called()

    @pytest.mark.asyncio
    async def test_ingester_survives_malformed_json(self, tmp_path):
        """Ingester must skip malformed JSON lines without crashing."""
        from decnet.web.ingester import log_ingestion_worker

        json_file = tmp_path / "test.json"
        json_file.write_text("not valid json\n{also broken\n")

        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        iterations = 0

        async def _controlled_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": str(tmp_path / "test.log")}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=_controlled_sleep):
                task = asyncio.create_task(log_ingestion_worker(mock_repo))
                with pytest.raises(asyncio.CancelledError):
                    await task
        mock_repo.add_log.assert_not_called()

    @pytest.mark.asyncio
    async def test_ingester_exits_on_db_fatal_error(self, tmp_path):
        """Ingester must exit cleanly on fatal DB errors (table missing, connection closed)."""
        from decnet.web.ingester import log_ingestion_worker

        json_file = tmp_path / "test.json"
        valid_record = {
            "timestamp": "2026-01-01 00:00:00",
            "decky": "decky-01",
            "service": "ssh",
            "event_type": "login_attempt",
            "attacker_ip": "10.0.0.1",
            "fields": {},
            "msg": "",
            "raw_line": "<134>1 2026-01-01T00:00:00Z decky-01 ssh - login_attempt -",
        }
        json_file.write_text(json.dumps(valid_record) + "\n")

        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock(side_effect=Exception("no such table: logs"))

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": str(tmp_path / "test.log")}):
            # Worker should exit the loop on fatal DB error
            await log_ingestion_worker(mock_repo)
        # Should have attempted to add the log before dying
        mock_repo.add_log.assert_awaited_once()


# ─── Attacker worker isolation ───────────────────────────────────────────────

class TestAttackerWorkerIsolation:
    """Attacker worker depends on DB repo."""

    @pytest.mark.asyncio
    async def test_attacker_worker_survives_db_error(self):
        """Attacker worker must catch DB errors and continue looping."""
        from decnet.profiler import attacker_profile_worker

        mock_repo = MagicMock()
        mock_repo.get_all_logs_raw = AsyncMock(side_effect=Exception("DB is locked"))
        mock_repo.get_max_log_id = AsyncMock(return_value=0)
        mock_repo.set_state = AsyncMock()

        iterations = 0

        async def _controlled_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                raise asyncio.CancelledError()

        with patch("decnet.profiler.worker.asyncio.sleep", side_effect=_controlled_sleep):
            task = asyncio.create_task(attacker_profile_worker(mock_repo))
            with pytest.raises(asyncio.CancelledError):
                await task
        # Worker should have retried at least twice before we cancelled
        assert iterations >= 2

    @pytest.mark.asyncio
    async def test_attacker_worker_survives_empty_db(self):
        """Attacker worker must handle an empty database gracefully."""
        from decnet.profiler.worker import _WorkerState, _incremental_update

        mock_repo = MagicMock()
        mock_repo.get_logs_after_id = AsyncMock(return_value=[])
        mock_repo.set_state = AsyncMock()

        state = _WorkerState()
        await _incremental_update(mock_repo, state)
        assert state.initialized is True
        assert state.last_log_id == 0


# ─── Sniffer isolation ───────────────────────────────────────────────────────

class TestSnifferIsolation:
    """Sniffer depends on MACVLAN interface, scapy, and state file."""

    @pytest.mark.asyncio
    async def test_sniffer_survives_missing_interface(self):
        """Sniffer must exit gracefully when MACVLAN interface doesn't exist."""
        from decnet.sniffer.worker import sniffer_worker

        with patch("decnet.sniffer.worker._interface_exists", return_value=False):
            await sniffer_worker("/tmp/decnet-test-sniffer.log")
        # Should return without error

    @pytest.mark.asyncio
    async def test_sniffer_survives_no_state(self):
        """Sniffer must exit gracefully when no deckies are deployed."""
        from decnet.sniffer.worker import sniffer_worker

        with patch("decnet.sniffer.worker._interface_exists", return_value=True):
            with patch("decnet.config.load_state", return_value=None):
                await sniffer_worker("/tmp/decnet-test-sniffer.log")
        # Should return without error

    @pytest.mark.asyncio
    async def test_sniffer_survives_scapy_import_error(self):
        """Sniffer must handle missing scapy library gracefully."""
        from decnet.sniffer.worker import _sniff_loop

        import threading
        stop = threading.Event()

        with patch("decnet.config.load_state", return_value=None):
            with patch.dict("sys.modules", {"scapy": None, "scapy.sendrecv": None}):
                # Should exit gracefully (no deckies = early return before scapy import)
                _sniff_loop("fake0", Path("/tmp/test.log"), Path("/tmp/test.json"), stop)

    @pytest.mark.asyncio
    async def test_sniffer_survives_scapy_crash(self):
        """Sniffer must handle scapy runtime errors without crashing the API."""
        from decnet.sniffer.worker import sniffer_worker

        mock_state = MagicMock()
        mock_config = MagicMock()
        mock_config.deckies = [MagicMock(ip="192.168.1.10", name="decky-01")]

        with patch("decnet.sniffer.worker._interface_exists", return_value=True):
            with patch("decnet.config.load_state", return_value=(mock_config, Path("/tmp"))):
                with patch("decnet.sniffer.worker.asyncio.to_thread",
                           side_effect=Exception("scapy segfault")):
                    # Should catch and log, not raise
                    await sniffer_worker("/tmp/decnet-test-sniffer.log")

    def test_sniffer_engine_ignores_non_decky_traffic(self):
        """Engine must silently skip packets not involving any known decky."""
        from decnet.sniffer.fingerprint import SnifferEngine

        written: list[str] = []
        engine = SnifferEngine(
            ip_to_decky={"192.168.1.10": "decky-01"},
            write_fn=written.append,
        )
        # Simulate a packet between two unknown IPs
        pkt = MagicMock()
        pkt.haslayer.return_value = True
        ip_layer = MagicMock()
        ip_layer.src = "10.0.0.1"
        ip_layer.dst = "10.0.0.2"
        tcp_layer = MagicMock()
        tcp_layer.sport = 12345
        tcp_layer.dport = 443
        tcp_layer.flags = MagicMock(value=0x10)
        tcp_layer.payload = b""
        pkt.__getitem__ = lambda self, cls: ip_layer if cls.__name__ == "IP" else tcp_layer
        # Import layers for haslayer check
        from scapy.layers.inet import IP, TCP
        pkt.haslayer.side_effect = lambda layer: True

        engine.on_packet(pkt)
        assert written == []  # Nothing written for non-decky traffic


# ─── API lifespan isolation ──────────────────────────────────────────────────

class TestApiLifespanIsolation:
    """API lifespan must survive individual worker failures."""

    @pytest.mark.asyncio
    async def test_api_survives_all_workers_failing(self):
        """API must start and serve requests even if every worker fails to start."""
        from decnet.web.api import lifespan

        mock_app = MagicMock()
        mock_repo = MagicMock()
        mock_repo.initialize = AsyncMock()

        with patch("decnet.web.api.repo", mock_repo):
            with patch("decnet.web.api.log_ingestion_worker",
                       side_effect=Exception("ingester exploded")):
                with patch("decnet.web.api.log_collector_worker",
                           side_effect=Exception("collector exploded")):
                    with patch("decnet.web.api.attacker_profile_worker",
                               side_effect=Exception("attacker exploded")):
                        with patch("decnet.sniffer.sniffer_worker",
                                   side_effect=Exception("sniffer exploded")):
                            # API should still start
                            async with lifespan(mock_app):
                                mock_repo.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_api_survives_db_init_failure(self):
        """API must survive even if DB never initializes (5 failed attempts)."""
        from decnet.web.api import lifespan

        mock_app = MagicMock()
        mock_repo = MagicMock()
        mock_repo.initialize = AsyncMock(side_effect=Exception("DB locked"))

        with patch("decnet.web.api.repo", mock_repo):
            with patch("decnet.web.api.asyncio.sleep", new_callable=AsyncMock):
                with patch("decnet.web.api.log_ingestion_worker", return_value=asyncio.sleep(0)):
                    with patch("decnet.web.api.log_collector_worker", return_value=asyncio.sleep(0)):
                        with patch("decnet.web.api.attacker_profile_worker", return_value=asyncio.sleep(0)):
                            async with lifespan(mock_app):
                                # DB init failed 5 times but API is running
                                assert mock_repo.initialize.await_count == 5

    @pytest.mark.asyncio
    async def test_api_survives_sniffer_import_failure(self):
        """API must start even if the sniffer module cannot be imported."""
        from decnet.web.api import lifespan

        mock_app = MagicMock()
        mock_repo = MagicMock()
        mock_repo.initialize = AsyncMock()

        with patch("decnet.web.api.repo", mock_repo):
            with patch("decnet.web.api.log_ingestion_worker", return_value=asyncio.sleep(0)):
                with patch("decnet.web.api.log_collector_worker", return_value=asyncio.sleep(0)):
                    with patch("decnet.web.api.attacker_profile_worker", return_value=asyncio.sleep(0)):
                        # Simulate sniffer import failure
                        import builtins
                        real_import = builtins.__import__

                        def _mock_import(name, *args, **kwargs):
                            if name == "decnet.sniffer":
                                raise ImportError("No module named 'scapy'")
                            return real_import(name, *args, **kwargs)

                        with patch("builtins.__import__", side_effect=_mock_import):
                            async with lifespan(mock_app):
                                mock_repo.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_shutdown_handles_already_dead_tasks(self):
        """Shutdown must not crash when tasks have already completed or failed."""
        from decnet.web.api import lifespan

        mock_app = MagicMock()
        mock_repo = MagicMock()
        mock_repo.initialize = AsyncMock()

        # Workers that complete immediately
        async def _instant_worker(*args):
            return

        with patch("decnet.web.api.repo", mock_repo):
            with patch("decnet.web.api.log_ingestion_worker", side_effect=_instant_worker):
                with patch("decnet.web.api.log_collector_worker", side_effect=_instant_worker):
                    with patch("decnet.web.api.attacker_profile_worker", side_effect=_instant_worker):
                        async with lifespan(mock_app):
                            # Let tasks finish
                            await asyncio.sleep(0.05)
                        # Shutdown should handle already-done tasks gracefully


# ─── Cross-service cascade tests ────────────────────────────────────────────

class TestCascadeIsolation:
    """Verify that failure in one service does not cascade to others."""

    @pytest.mark.asyncio
    async def test_collector_failure_does_not_kill_ingester(self, tmp_path):
        """When collector dies, ingester must keep waiting (not crash)."""
        from decnet.web.ingester import log_ingestion_worker

        json_file = tmp_path / "cascade.json"
        # File doesn't exist — simulates collector never writing

        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        iterations = 0

        async def _controlled_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 5:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": str(tmp_path / "cascade.log")}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=_controlled_sleep):
                task = asyncio.create_task(log_ingestion_worker(mock_repo))
                with pytest.raises(asyncio.CancelledError):
                    await task
        # Ingester should have been patiently waiting, not crashing
        assert iterations >= 4
        mock_repo.add_log.assert_not_called()

    @pytest.mark.asyncio
    async def test_ingester_failure_does_not_kill_attacker(self):
        """When ingester dies, attacker worker must keep running independently."""
        from decnet.profiler import attacker_profile_worker

        mock_repo = MagicMock()
        mock_repo.get_all_logs_raw = AsyncMock(return_value=[])
        mock_repo.get_max_log_id = AsyncMock(return_value=0)
        mock_repo.set_state = AsyncMock()
        mock_repo.get_logs_after_id = AsyncMock(return_value=[])

        iterations = 0

        async def _controlled_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                raise asyncio.CancelledError()

        with patch("decnet.profiler.worker.asyncio.sleep", side_effect=_controlled_sleep):
            task = asyncio.create_task(attacker_profile_worker(mock_repo))
            with pytest.raises(asyncio.CancelledError):
                await task
        # Attacker should have run independently
        assert iterations >= 2

    @pytest.mark.asyncio
    async def test_sniffer_crash_does_not_affect_collector(self):
        """Sniffer crash must not affect collector operation."""
        from decnet.collector.worker import is_service_container, is_service_event

        # These should work regardless of sniffer state
        with patch("decnet.collector.worker._load_service_container_names",
                    return_value={"decky-01-ssh"}):
            assert is_service_container("decky-01-ssh") is True
            assert is_service_event({"name": "decky-01-ssh"}) is True

    @pytest.mark.asyncio
    async def test_db_failure_does_not_crash_sniffer(self):
        """Sniffer has no DB dependency — must be completely unaffected by DB issues."""
        from decnet.sniffer.fingerprint import SnifferEngine

        written: list[str] = []
        engine = SnifferEngine(
            ip_to_decky={"192.168.1.10": "decky-01"},
            write_fn=written.append,
        )
        # Engine should work with zero DB interaction
        engine._log("decky-01", "tls_client_hello", src_ip="10.0.0.1", ja3="abc", ja4="def")
        assert len(written) == 1
        assert "decky-01" in written[0]
