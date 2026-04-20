"""
Tests for decnet/engine/deployer.py

Covers _compose, _compose_with_retry, _sync_logging_helper,
deploy (dry-run and mocked), teardown, status, and _print_status.
All Docker and subprocess calls are mocked.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from decnet.config import DeckyConfig, DecnetConfig


# ── Helpers ───────────────────────────────────────────────────────────────────

def _decky(name: str = "decky-01", ip: str = "192.168.1.10",
           services: list[str] | None = None) -> DeckyConfig:
    return DeckyConfig(
        name=name, ip=ip, services=services or ["ssh"],
        distro="debian", base_image="debian", hostname="test-host",
        build_base="debian:bookworm-slim", nmap_os="linux",
    )


def _config(deckies: list[DeckyConfig] | None = None, ipvlan: bool = False) -> DecnetConfig:
    return DecnetConfig(
        mode="unihost", interface="eth0", subnet="192.168.1.0/24",
        gateway="192.168.1.1", deckies=deckies or [_decky()],
        ipvlan=ipvlan,
    )


# ── _compose ──────────────────────────────────────────────────────────────────

class TestCompose:
    @patch("decnet.engine.deployer.subprocess.run")
    def test_compose_constructs_correct_command(self, mock_run):
        from decnet.engine.deployer import _compose
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _compose("up", "-d", compose_file=Path("test.yml"))
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[:6] == ["docker", "compose", "-p", "decnet", "-f", "test.yml"]
        assert "up" in cmd
        assert "-d" in cmd

    @patch("decnet.engine.deployer.subprocess.run")
    def test_compose_passes_env(self, mock_run):
        from decnet.engine.deployer import _compose
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _compose("build", env={"DOCKER_BUILDKIT": "1"})
        _, kwargs = mock_run.call_args
        assert "DOCKER_BUILDKIT" in kwargs["env"]


# ── _compose_with_retry ───────────────────────────────────────────────────────

class TestComposeWithRetry:
    @patch("decnet.engine.deployer.subprocess.run")
    def test_success_first_try(self, mock_run):
        from decnet.engine.deployer import _compose_with_retry
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _compose_with_retry("up", "-d")  # should not raise

    @patch("decnet.engine.deployer.time.sleep")
    @patch("decnet.engine.deployer.subprocess.run")
    def test_transient_failure_retries(self, mock_run, mock_sleep):
        from decnet.engine.deployer import _compose_with_retry
        fail_result = MagicMock(returncode=1, stdout="", stderr="temporary error")
        ok_result = MagicMock(returncode=0, stdout="ok", stderr="")
        mock_run.side_effect = [fail_result, ok_result]
        _compose_with_retry("up", retries=3)
        assert mock_run.call_count == 2
        mock_sleep.assert_called_once()

    @patch("decnet.engine.deployer.time.sleep")
    @patch("decnet.engine.deployer.subprocess.run")
    def test_permanent_error_no_retry(self, mock_run, mock_sleep):
        from decnet.engine.deployer import _compose_with_retry
        fail_result = MagicMock(returncode=1, stdout="", stderr="manifest unknown error")
        mock_run.return_value = fail_result
        with pytest.raises(subprocess.CalledProcessError):
            _compose_with_retry("pull", retries=3)
        assert mock_run.call_count == 1
        mock_sleep.assert_not_called()

    @patch("decnet.engine.deployer.time.sleep")
    @patch("decnet.engine.deployer.subprocess.run")
    def test_max_retries_exhausted(self, mock_run, mock_sleep):
        from decnet.engine.deployer import _compose_with_retry
        fail_result = MagicMock(returncode=1, stdout="", stderr="connection refused")
        mock_run.return_value = fail_result
        with pytest.raises(subprocess.CalledProcessError):
            _compose_with_retry("up", retries=2)
        assert mock_run.call_count == 2

    @patch("decnet.engine.deployer.subprocess.run")
    def test_stdout_printed_on_success(self, mock_run, capsys):
        from decnet.engine.deployer import _compose_with_retry
        mock_run.return_value = MagicMock(returncode=0, stdout="done\n", stderr="")
        _compose_with_retry("build")
        captured = capsys.readouterr()
        assert "done" in captured.out


# ── _sync_logging_helper ─────────────────────────────────────────────────────

class TestSyncLoggingHelper:
    @patch("decnet.engine.deployer.shutil.copy2")
    @patch("decnet.engine.deployer._CANONICAL_LOGGING")
    def test_copies_when_file_differs(self, mock_canonical, mock_copy):
        from decnet.engine.deployer import _sync_logging_helper
        mock_svc = MagicMock()
        mock_svc.dockerfile_context.return_value = Path("/tmp/test_ctx")
        mock_canonical.__truediv__ = Path.__truediv__

        with patch("decnet.services.registry.get_service", return_value=mock_svc):
            with patch("pathlib.Path.exists", return_value=False):
                config = _config()
                _sync_logging_helper(config)


# ── deploy ────────────────────────────────────────────────────────────────────

class TestDeploy:
    @patch("decnet.engine.deployer._print_status")
    @patch("decnet.engine.deployer._compose_with_retry")
    @patch("decnet.engine.deployer.save_state")
    @patch("decnet.engine.deployer.write_compose", return_value=Path("test.yml"))
    @patch("decnet.engine.deployer._sync_logging_helper")
    @patch("decnet.engine.deployer.setup_host_macvlan")
    @patch("decnet.engine.deployer.create_macvlan_network")
    @patch("decnet.engine.deployer.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.engine.deployer.ips_to_range", return_value="192.168.1.10/32")
    @patch("decnet.engine.deployer.docker.from_env")
    def test_dry_run_no_containers(self, mock_docker, mock_range, mock_hip,
                                    mock_create, mock_setup, mock_sync,
                                    mock_compose, mock_save, mock_retry, mock_print):
        from decnet.engine.deployer import deploy
        config = _config()
        deploy(config, dry_run=True)
        mock_create.assert_not_called()
        mock_retry.assert_not_called()
        mock_save.assert_not_called()

    @patch("decnet.engine.deployer._print_status")
    @patch("decnet.engine.deployer._compose_with_retry")
    @patch("decnet.engine.deployer.save_state")
    @patch("decnet.engine.deployer.write_compose", return_value=Path("test.yml"))
    @patch("decnet.engine.deployer._sync_logging_helper")
    @patch("decnet.engine.deployer.setup_host_macvlan")
    @patch("decnet.engine.deployer.create_macvlan_network")
    @patch("decnet.engine.deployer.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.engine.deployer.ips_to_range", return_value="192.168.1.10/32")
    @patch("decnet.engine.deployer.docker.from_env")
    def test_macvlan_deploy(self, mock_docker, mock_range, mock_hip,
                             mock_create, mock_setup, mock_sync,
                             mock_compose, mock_save, mock_retry, mock_print):
        from decnet.engine.deployer import deploy
        config = _config(ipvlan=False)
        deploy(config)
        mock_create.assert_called_once()
        mock_setup.assert_called_once()
        mock_save.assert_called_once()
        mock_retry.assert_called()

    @patch("decnet.engine.deployer._print_status")
    @patch("decnet.engine.deployer._compose_with_retry")
    @patch("decnet.engine.deployer.save_state")
    @patch("decnet.engine.deployer.write_compose", return_value=Path("test.yml"))
    @patch("decnet.engine.deployer._sync_logging_helper")
    @patch("decnet.engine.deployer.setup_host_ipvlan")
    @patch("decnet.engine.deployer.create_ipvlan_network")
    @patch("decnet.engine.deployer.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.engine.deployer.ips_to_range", return_value="192.168.1.10/32")
    @patch("decnet.engine.deployer.docker.from_env")
    def test_ipvlan_deploy(self, mock_docker, mock_range, mock_hip,
                            mock_create, mock_setup, mock_sync,
                            mock_compose, mock_save, mock_retry, mock_print):
        from decnet.engine.deployer import deploy
        config = _config(ipvlan=True)
        deploy(config)
        mock_create.assert_called_once()
        mock_setup.assert_called_once()

    @patch("decnet.engine.deployer._print_status")
    @patch("decnet.engine.deployer._compose_with_retry")
    @patch("decnet.engine.deployer.save_state")
    @patch("decnet.engine.deployer.write_compose", return_value=Path("test.yml"))
    @patch("decnet.engine.deployer._sync_logging_helper")
    @patch("decnet.engine.deployer.setup_host_macvlan")
    @patch("decnet.engine.deployer.create_macvlan_network")
    @patch("decnet.engine.deployer.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.engine.deployer.ips_to_range", return_value="192.168.1.10/32")
    @patch("decnet.engine.deployer.docker.from_env")
    def test_parallel_build(self, mock_docker, mock_range, mock_hip,
                             mock_create, mock_setup, mock_sync,
                             mock_compose, mock_save, mock_retry, mock_print):
        from decnet.engine.deployer import deploy
        config = _config()
        deploy(config, parallel=True)
        # Parallel mode calls _compose_with_retry for "build" and "up" separately
        calls = mock_retry.call_args_list
        assert any("build" in str(c) for c in calls)

    @patch("decnet.engine.deployer._print_status")
    @patch("decnet.engine.deployer._compose_with_retry")
    @patch("decnet.engine.deployer.save_state")
    @patch("decnet.engine.deployer.write_compose", return_value=Path("test.yml"))
    @patch("decnet.engine.deployer._sync_logging_helper")
    @patch("decnet.engine.deployer.setup_host_macvlan")
    @patch("decnet.engine.deployer.create_macvlan_network")
    @patch("decnet.engine.deployer.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.engine.deployer.ips_to_range", return_value="192.168.1.10/32")
    @patch("decnet.engine.deployer.docker.from_env")
    def test_no_cache_build(self, mock_docker, mock_range, mock_hip,
                             mock_create, mock_setup, mock_sync,
                             mock_compose, mock_save, mock_retry, mock_print):
        from decnet.engine.deployer import deploy
        config = _config()
        deploy(config, no_cache=True)
        calls = mock_retry.call_args_list
        assert any("--no-cache" in str(c) for c in calls)


# ── teardown ──────────────────────────────────────────────────────────────────

class TestTeardown:
    @patch("decnet.engine.deployer.load_state", return_value=None)
    def test_no_state(self, mock_load):
        from decnet.engine.deployer import teardown
        teardown()  # should not raise

    @patch("decnet.engine.deployer.clear_state")
    @patch("decnet.engine.deployer.remove_macvlan_network")
    @patch("decnet.engine.deployer.teardown_host_macvlan")
    @patch("decnet.engine.deployer._compose")
    @patch("decnet.engine.deployer.ips_to_range", return_value="192.168.1.10/32")
    @patch("decnet.engine.deployer.docker.from_env")
    @patch("decnet.engine.deployer.load_state")
    def test_full_teardown_macvlan(self, mock_load, mock_docker, mock_range,
                                    mock_compose, mock_td_macvlan, mock_rm_net,
                                    mock_clear):
        config = _config()
        mock_load.return_value = (config, Path("test.yml"))
        from decnet.engine.deployer import teardown
        teardown()
        mock_compose.assert_called_once()
        mock_td_macvlan.assert_called_once()
        mock_rm_net.assert_called_once()
        mock_clear.assert_called_once()

    @patch("decnet.engine.deployer.clear_state")
    @patch("decnet.engine.deployer.remove_macvlan_network")
    @patch("decnet.engine.deployer.teardown_host_ipvlan")
    @patch("decnet.engine.deployer._compose")
    @patch("decnet.engine.deployer.ips_to_range", return_value="192.168.1.10/32")
    @patch("decnet.engine.deployer.docker.from_env")
    @patch("decnet.engine.deployer.load_state")
    def test_full_teardown_ipvlan(self, mock_load, mock_docker, mock_range,
                                   mock_compose, mock_td_ipvlan, mock_rm_net,
                                   mock_clear):
        config = _config(ipvlan=True)
        mock_load.return_value = (config, Path("test.yml"))
        from decnet.engine.deployer import teardown
        teardown()
        mock_td_ipvlan.assert_called_once()

    @patch("decnet.engine.deployer._compose")
    @patch("decnet.engine.deployer.docker.from_env")
    @patch("decnet.engine.deployer.load_state")
    def test_single_decky_emits_flat_service_names(
        self, mock_load, mock_docker, mock_compose,
    ):
        """Regression: teardown(decky_id=...) must iterate the matched decky's
        services, not stringify the services list itself. The old nested
        comprehension produced `decky3-['sip']` and docker compose choked."""
        config = _config(deckies=[
            _decky(name="decky3", ip="192.168.1.13", services=["sip", "ssh"]),
            _decky(name="decky4", ip="192.168.1.14", services=["http"]),
        ])
        mock_load.return_value = (config, Path("test.yml"))
        from decnet.engine.deployer import teardown
        teardown(decky_id="decky3")

        # stop + rm, each called with the flat per-service names
        assert mock_compose.call_count == 2
        for call in mock_compose.call_args_list:
            args = call.args
            svc_names = [a for a in args if a.startswith("decky3-")]
            assert svc_names == ["decky3-sip", "decky3-ssh"], svc_names
            for name in svc_names:
                assert "[" not in name and "'" not in name

    @patch("decnet.engine.deployer._compose")
    @patch("decnet.engine.deployer.docker.from_env")
    @patch("decnet.engine.deployer.load_state")
    def test_unknown_decky_id_is_noop(
        self, mock_load, mock_docker, mock_compose,
    ):
        mock_load.return_value = (_config(), Path("test.yml"))
        from decnet.engine.deployer import teardown
        teardown(decky_id="does-not-exist")
        mock_compose.assert_not_called()


# ── status ────────────────────────────────────────────────────────────────────

class TestStatus:
    @patch("decnet.engine.deployer.load_state", return_value=None)
    def test_no_state(self, mock_load):
        from decnet.engine.deployer import status
        status()  # should not raise

    @patch("decnet.engine.deployer.docker.from_env")
    @patch("decnet.engine.deployer.load_state")
    def test_with_running_containers(self, mock_load, mock_docker):
        config = _config()
        mock_load.return_value = (config, Path("test.yml"))
        mock_container = MagicMock()
        mock_container.name = "decky-01-ssh"
        mock_container.status = "running"
        mock_docker.return_value.containers.list.return_value = [mock_container]
        from decnet.engine.deployer import status
        status()  # should not raise

    @patch("decnet.engine.deployer.docker.from_env")
    @patch("decnet.engine.deployer.load_state")
    def test_with_absent_containers(self, mock_load, mock_docker):
        config = _config()
        mock_load.return_value = (config, Path("test.yml"))
        mock_docker.return_value.containers.list.return_value = []
        from decnet.engine.deployer import status
        status()  # should not raise


# ── _print_status ─────────────────────────────────────────────────────────────

class TestPrintStatus:
    def test_renders_table(self):
        from decnet.engine.deployer import _print_status
        config = _config(deckies=[_decky(), _decky("decky-02", "192.168.1.11")])
        _print_status(config)  # should not raise
