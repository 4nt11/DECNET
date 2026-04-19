"""
Tests for decnet/cli.py — CLI commands via Typer's CliRunner.
"""

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from decnet.cli import app
from decnet.config import DeckyConfig, DecnetConfig

runner = CliRunner()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _decky(name: str = "decky-01", ip: str = "192.168.1.10") -> DeckyConfig:
    return DeckyConfig(
        name=name, ip=ip, services=["ssh"],
        distro="debian", base_image="debian", hostname="test-host",
        build_base="debian:bookworm-slim", nmap_os="linux",
    )


def _config() -> DecnetConfig:
    return DecnetConfig(
        mode="unihost", interface="eth0", subnet="192.168.1.0/24",
        gateway="192.168.1.1", deckies=[_decky()],
    )


# ── services command ──────────────────────────────────────────────────────────

class TestServicesCommand:
    def test_lists_services(self):
        result = runner.invoke(app, ["services"])
        assert result.exit_code == 0
        assert "ssh" in result.stdout


# ── distros command ───────────────────────────────────────────────────────────

class TestDistrosCommand:
    def test_lists_distros(self):
        result = runner.invoke(app, ["distros"])
        assert result.exit_code == 0
        assert "debian" in result.stdout.lower()


# ── archetypes command ────────────────────────────────────────────────────────

class TestArchetypesCommand:
    def test_lists_archetypes(self):
        result = runner.invoke(app, ["archetypes"])
        assert result.exit_code == 0
        assert "deaddeck" in result.stdout.lower()


# ── deploy command ────────────────────────────────────────────────────────────

class TestDeployCommand:
    @patch("decnet.engine.deploy")
    @patch("decnet.cli.allocate_ips", return_value=["192.168.1.10"])
    @patch("decnet.cli.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.cli.detect_subnet", return_value=("192.168.1.0/24", "192.168.1.1"))
    @patch("decnet.cli.detect_interface", return_value="eth0")
    def test_deploy_dry_run(self, mock_iface, mock_subnet, mock_hip,
                             mock_ips, mock_deploy):
        result = runner.invoke(app, [
            "deploy", "--deckies", "1", "--services", "ssh", "--dry-run",
        ])
        assert result.exit_code == 0
        mock_deploy.assert_called_once()

    def test_deploy_no_interface_found(self):
        with patch("decnet.cli.detect_interface", side_effect=ValueError("No interface")):
            result = runner.invoke(app, ["deploy", "--deckies", "1"])
            assert result.exit_code == 1

    def test_deploy_no_subnet_found(self):
        with patch("decnet.cli.detect_interface", return_value="eth0"), \
             patch("decnet.cli.detect_subnet", side_effect=ValueError("No subnet")):
            result = runner.invoke(app, ["deploy", "--deckies", "1", "--services", "ssh"])
            assert result.exit_code == 1

    def test_deploy_invalid_mode(self):
        result = runner.invoke(app, ["deploy", "--mode", "invalid", "--deckies", "1"])
        assert result.exit_code == 1

    @patch("decnet.cli.detect_interface", return_value="eth0")
    def test_deploy_no_deckies_no_config(self, mock_iface):
        result = runner.invoke(app, ["deploy", "--services", "ssh"])
        assert result.exit_code == 1

    @patch("decnet.cli.detect_interface", return_value="eth0")
    def test_deploy_no_services_no_randomize(self, mock_iface):
        result = runner.invoke(app, ["deploy", "--deckies", "1"])
        assert result.exit_code == 1

    @patch("decnet.engine.deploy")
    @patch("decnet.cli.allocate_ips", return_value=["192.168.1.10"])
    @patch("decnet.cli.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.cli.detect_subnet", return_value=("192.168.1.0/24", "192.168.1.1"))
    @patch("decnet.cli.detect_interface", return_value="eth0")
    def test_deploy_with_archetype(self, mock_iface, mock_subnet, mock_hip,
                                    mock_ips, mock_deploy):
        result = runner.invoke(app, [
            "deploy", "--deckies", "1", "--archetype", "deaddeck", "--dry-run",
        ])
        assert result.exit_code == 0

    def test_deploy_invalid_archetype(self):
        result = runner.invoke(app, [
            "deploy", "--deckies", "1", "--archetype", "nonexistent_arch",
        ])
        assert result.exit_code == 1

    @patch("decnet.engine.deploy")
    @patch("subprocess.Popen")
    @patch("decnet.cli.allocate_ips", return_value=["192.168.1.10"])
    @patch("decnet.cli.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.cli.detect_subnet", return_value=("192.168.1.0/24", "192.168.1.1"))
    @patch("decnet.cli.detect_interface", return_value="eth0")
    def test_deploy_full_with_api(self, mock_iface, mock_subnet, mock_hip,
                                  mock_ips, mock_popen, mock_deploy):
        # Test non-dry-run with API and collector starts
        result = runner.invoke(app, [
            "deploy", "--deckies", "1", "--services", "ssh", "--api",
        ])
        assert result.exit_code == 0
        assert mock_popen.call_count >= 1 # API

    @patch("decnet.engine.deploy")
    @patch("decnet.cli.allocate_ips", return_value=["192.168.1.10"])
    @patch("decnet.cli.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.cli.detect_subnet", return_value=("192.168.1.0/24", "192.168.1.1"))
    @patch("decnet.cli.detect_interface", return_value="eth0")
    def test_deploy_with_distro(self, mock_iface, mock_subnet, mock_hip,
                                 mock_ips, mock_deploy):
        result = runner.invoke(app, [
            "deploy", "--deckies", "1", "--services", "ssh", "--distro", "debian", "--dry-run",
        ])
        assert result.exit_code == 0

    def test_deploy_invalid_distro(self):
        result = runner.invoke(app, [
            "deploy", "--deckies", "1", "--services", "ssh", "--distro", "nonexistent_distro",
        ])
        assert result.exit_code == 1

    @patch("decnet.engine.deploy")
    @patch("decnet.cli.load_ini")
    @patch("decnet.cli.get_host_ip", return_value="192.168.1.2")
    @patch("decnet.cli.detect_subnet", return_value=("192.168.1.0/24", "192.168.1.1"))
    @patch("decnet.cli.detect_interface", return_value="eth0")
    def test_deploy_with_config_file(self, mock_iface, mock_subnet, mock_hip,
                                      mock_load_ini, mock_deploy, tmp_path):
        from decnet.ini_loader import IniConfig, DeckySpec
        ini_file = tmp_path / "test.ini"
        ini_file.touch()
        mock_load_ini.return_value = IniConfig(
            deckies=[DeckySpec(name="test-1", services=["ssh"], ip="192.168.1.50")],
            interface="eth0", subnet="192.168.1.0/24", gateway="192.168.1.1",
        )
        result = runner.invoke(app, [
            "deploy", "--config", str(ini_file), "--dry-run",
        ])
        assert result.exit_code == 0

    def test_deploy_config_file_not_found(self):
        result = runner.invoke(app, [
            "deploy", "--config", "/nonexistent/config.ini",
        ])
        assert result.exit_code == 1


# ── teardown command ──────────────────────────────────────────────────────────

class TestTeardownCommand:
    def test_teardown_no_args(self):
        result = runner.invoke(app, ["teardown"])
        assert result.exit_code == 1

    @patch("decnet.cli._kill_all_services")
    @patch("decnet.engine.teardown")
    def test_teardown_all(self, mock_teardown, mock_kill):
        result = runner.invoke(app, ["teardown", "--all"])
        assert result.exit_code == 0

    @patch("decnet.engine.teardown")
    def test_teardown_by_id(self, mock_teardown):
        result = runner.invoke(app, ["teardown", "--id", "decky-01"])
        assert result.exit_code == 0
        mock_teardown.assert_called_once_with(decky_id="decky-01")

    @patch("decnet.engine.teardown", side_effect=Exception("Teardown failed"))
    def test_teardown_error(self, mock_teardown):
        result = runner.invoke(app, ["teardown", "--all"])
        assert result.exit_code == 1

    @patch("decnet.engine.teardown", side_effect=Exception("Specific ID failed"))
    def test_teardown_id_error(self, mock_teardown):
        result = runner.invoke(app, ["teardown", "--id", "decky-01"])
        assert result.exit_code == 1


# ── status command ────────────────────────────────────────────────────────────

class TestStatusCommand:
    @patch("decnet.engine.status", return_value=[])
    def test_status_empty(self, mock_status):
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0

    @patch("decnet.engine.status", return_value=[{"ID": "1", "Status": "running"}])
    def test_status_active(self, mock_status):
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0

    def test_status_available_in_agent_mode(self, monkeypatch):
        # Agents run deckies locally and must be able to inspect them;
        # `status` is intentionally NOT in MASTER_ONLY_COMMANDS.
        import importlib

        import decnet.cli as cli_mod

        monkeypatch.setenv("DECNET_MODE", "agent")
        monkeypatch.setenv("DECNET_DISALLOW_MASTER", "true")
        reloaded = importlib.reload(cli_mod)
        try:
            names = {
                (c.name or c.callback.__name__)
                for c in reloaded.app.registered_commands
            }
            assert "status" in names
            assert "deploy" not in names  # sanity: master-only still gated
        finally:
            monkeypatch.delenv("DECNET_MODE", raising=False)
            monkeypatch.delenv("DECNET_DISALLOW_MASTER", raising=False)
            importlib.reload(cli_mod)


# ── mutate command ────────────────────────────────────────────────────────────

class TestMutateCommand:
    @patch("decnet.mutator.mutate_all")
    def test_mutate_default(self, mock_mutate_all):
        result = runner.invoke(app, ["mutate"])
        assert result.exit_code == 0

    @patch("decnet.mutator.mutate_all")
    def test_mutate_force_all(self, mock_mutate_all):
        result = runner.invoke(app, ["mutate", "--all"])
        assert result.exit_code == 0

    @patch("decnet.mutator.mutate_decky")
    def test_mutate_specific_decky(self, mock_mutate):
        result = runner.invoke(app, ["mutate", "--decky", "decky-01"])
        assert result.exit_code == 0

    @patch("decnet.mutator.run_watch_loop")
    def test_mutate_watch(self, mock_watch):
        result = runner.invoke(app, ["mutate", "--watch"])
        assert result.exit_code == 0

    @patch("decnet.mutator.mutate_all", side_effect=Exception("Mutate error"))
    def test_mutate_error(self, mock_mutate):
        result = runner.invoke(app, ["mutate"])
        assert result.exit_code == 1


# ── collect command ───────────────────────────────────────────────────────────

class TestCollectCommand:
    @patch("asyncio.run")
    def test_collect(self, mock_run):
        result = runner.invoke(app, ["collect"])
        assert result.exit_code == 0

    @patch("asyncio.run", side_effect=KeyboardInterrupt)
    def test_collect_interrupt(self, mock_run):
        result = runner.invoke(app, ["collect"])
        assert result.exit_code in (0, 130)

    @patch("asyncio.run", side_effect=Exception("Collect error"))
    def test_collect_error(self, mock_run):
        result = runner.invoke(app, ["collect"])
        assert result.exit_code == 1


# ── web command ───────────────────────────────────────────────────────────────

class TestWebCommand:
    @patch("pathlib.Path.exists", return_value=False)
    def test_web_no_dist(self, mock_exists):
        result = runner.invoke(app, ["web"])
        assert result.exit_code == 1
        assert "Frontend build not found" in result.stdout

    def test_web_success(self):
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("os.chdir"),
            patch(
                "socketserver.TCPServer.__init__",
                lambda self, *a, **kw: None,
            ),
            patch(
                "socketserver.TCPServer.__enter__",
                lambda self: self,
            ),
            patch(
                "socketserver.TCPServer.__exit__",
                lambda self, *a: None,
            ),
            patch(
                "socketserver.TCPServer.serve_forever",
                side_effect=KeyboardInterrupt,
            ),
        ):
            result = runner.invoke(app, ["web"])

        assert result.exit_code == 0
        assert "Serving DECNET Web Dashboard" in result.stdout


# ── correlate command ─────────────────────────────────────────────────────────

class TestCorrelateCommand:
    def test_correlate_no_input(self):
        with patch("sys.stdin.isatty", return_value=True):
            result = runner.invoke(app, ["correlate"])
            if result.exit_code != 0:
                assert result.exit_code == 1
                assert "Provide --log-file" in result.stdout

    def test_correlate_with_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "<134>1 2024-01-15T12:00:00+00:00 decky-01 ssh - auth "
            '[relay@55555 src_ip="10.0.0.5" username="admin"] login\n'
        )
        result = runner.invoke(app, ["correlate", "--log-file", str(log_file)])
        assert result.exit_code == 0


# ── api command ───────────────────────────────────────────────────────────────

class TestApiCommand:
    @patch("os.killpg")
    @patch("subprocess.Popen")
    def test_api_keyboard_interrupt(self, mock_popen, mock_killpg):
        proc = MagicMock()
        proc.wait.side_effect = [KeyboardInterrupt, 0]
        proc.pid = 4321
        mock_popen.return_value = proc
        result = runner.invoke(app, ["api"])
        assert result.exit_code == 0
        mock_killpg.assert_called()

    @patch("subprocess.Popen", side_effect=FileNotFoundError)
    def test_api_not_found(self, mock_popen):
        result = runner.invoke(app, ["api"])
        assert result.exit_code == 0


# ── _kill_all_services ────────────────────────────────────────────────────────

class TestKillAllServices:
    @patch("os.kill")
    @patch("psutil.process_iter")
    def test_kills_matching_processes(self, mock_iter, mock_kill):
        from decnet.cli import _kill_all_services
        mock_uvicorn = MagicMock()
        mock_uvicorn.info = {
            "pid": 111, "name": "python",
            "cmdline": ["python", "-m", "uvicorn", "decnet.web.api:app"],
        }
        mock_mutate = MagicMock()
        mock_mutate.info = {
            "pid": 222, "name": "python",
            "cmdline": ["python", "decnet.cli", "mutate", "--watch"],
        }
        mock_collector = MagicMock()
        mock_collector.info = {
            "pid": 333, "name": "python",
            "cmdline": ["python", "-m", "decnet.cli", "collect", "--log-file", "/tmp/decnet.log"],
        }
        mock_iter.return_value = [mock_uvicorn, mock_mutate, mock_collector]
        _kill_all_services()
        assert mock_kill.call_count == 3

    @patch("psutil.process_iter")
    def test_no_matching_processes(self, mock_iter):
        from decnet.cli import _kill_all_services
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1, "name": "bash", "cmdline": ["bash"]}
        mock_iter.return_value = [mock_proc]
        _kill_all_services()

    @patch("psutil.process_iter")
    def test_handles_empty_cmdline(self, mock_iter):
        from decnet.cli import _kill_all_services
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1, "name": "bash", "cmdline": None}
        mock_iter.return_value = [mock_proc]
        _kill_all_services()
