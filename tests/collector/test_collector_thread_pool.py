"""Verify that the collector and sniffer use dedicated thread pools
instead of the default asyncio executor — preventing starvation of
short-lived ``asyncio.to_thread`` calls in the web API layer."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from decnet.collector.worker import log_collector_worker
from decnet.sniffer.worker import sniffer_worker


class TestCollectorDedicatedPool:
    """Collector log streams must NOT use the default asyncio executor."""

    @pytest.mark.asyncio
    async def test_stream_containers_use_dedicated_pool(self, tmp_path):
        """Spawning container log threads should go through a dedicated
        ThreadPoolExecutor, not the default loop executor."""
        log_file = str(tmp_path / "decnet.log")

        captured_executors: list[ThreadPoolExecutor | None] = []
        original_run_in_executor = asyncio.get_event_loop().run_in_executor

        async def _spy_run_in_executor(executor, func, *args):
            captured_executors.append(executor)
            # Don't actually run the blocking function — raise to exit.
            raise asyncio.CancelledError

        fake_container = MagicMock()
        fake_container.id = "abc123"
        fake_container.name = "/omega-decky-http"

        fake_client = MagicMock()
        fake_client.containers.list.return_value = [fake_container]

        mock_docker = MagicMock()
        mock_docker.from_env.return_value = fake_client

        with (
            patch.dict("sys.modules", {"docker": mock_docker}),
            patch(
                "decnet.collector.worker.is_service_container",
                return_value=True,
            ),
        ):
            loop = asyncio.get_running_loop()

            with patch.object(loop, "run_in_executor", side_effect=_spy_run_in_executor):
                with pytest.raises(asyncio.CancelledError):
                    await log_collector_worker(log_file)

        # The executor passed should be a dedicated pool, not None (default).
        assert len(captured_executors) >= 1
        for executor in captured_executors:
            assert executor is not None, (
                "Collector used default executor (None) — must use a dedicated pool"
            )
            assert isinstance(executor, ThreadPoolExecutor)


class TestSnifferDedicatedPool:
    """Sniffer sniff loop must NOT use the default asyncio executor."""

    @pytest.mark.asyncio
    async def test_sniff_loop_uses_dedicated_pool(self, tmp_path):
        log_file = str(tmp_path / "decnet.log")

        captured_executors: list[ThreadPoolExecutor | None] = []

        async def _spy_run_in_executor(executor, func, *args):
            captured_executors.append(executor)
            raise asyncio.CancelledError

        with (
            patch(
                "decnet.sniffer.worker._interface_exists",
                return_value=True,
            ),
            patch.dict("os.environ", {"DECNET_SNIFFER_IFACE": "eth0"}),
        ):
            loop = asyncio.get_running_loop()
            with patch.object(loop, "run_in_executor", side_effect=_spy_run_in_executor):
                with pytest.raises(asyncio.CancelledError):
                    await sniffer_worker(log_file)

        assert len(captured_executors) >= 1
        for executor in captured_executors:
            assert executor is not None, (
                "Sniffer used default executor (None) — must use a dedicated pool"
            )
            assert isinstance(executor, ThreadPoolExecutor)
