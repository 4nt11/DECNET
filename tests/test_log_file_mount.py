"""Tests for log_file volume mount in compose generation."""

from pathlib import Path


from decnet.composer import _CONTAINER_LOG_DIR, _resolve_log_file, generate_compose
from decnet.config import DeckyConfig, DecnetConfig
from decnet.distros import DISTROS


def _make_config(log_file: str | None = None) -> DecnetConfig:
    profile = DISTROS["debian"]
    decky = DeckyConfig(
        name="decky-01",
        ip="10.0.0.10",
        services=["http"],
        distro="debian",
        base_image=profile.image,
        build_base=profile.build_base,
        hostname="test-host",
    )
    return DecnetConfig(
        mode="unihost",
        interface="eth0",
        subnet="10.0.0.0/24",
        gateway="10.0.0.1",
        deckies=[decky],
        log_file=log_file,
    )


class TestResolveLogFile:
    def test_absolute_path(self, tmp_path):
        log_path = str(tmp_path / "decnet.log")
        host_dir, container_path = _resolve_log_file(log_path)
        assert host_dir == str(tmp_path)
        assert container_path == f"{_CONTAINER_LOG_DIR}/decnet.log"

    def test_relative_path_resolves_to_absolute(self):
        host_dir, container_path = _resolve_log_file("decnet.log")
        assert Path(host_dir).is_absolute()
        assert container_path == f"{_CONTAINER_LOG_DIR}/decnet.log"

    def test_nested_filename_preserved(self, tmp_path):
        log_path = str(tmp_path / "logs" / "honeypot.log")
        _, container_path = _resolve_log_file(log_path)
        assert container_path.endswith("honeypot.log")


class TestComposeLogFileMount:
    def test_no_log_file_no_volume(self):
        config = _make_config(log_file=None)
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        assert "DECNET_LOG_FILE" not in fragment.get("environment", {})
        volumes = fragment.get("volumes", [])
        assert not any(_CONTAINER_LOG_DIR in v for v in volumes)

    def test_log_file_sets_env_var(self, tmp_path):
        config = _make_config(log_file=str(tmp_path / "decnet.log"))
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        env = fragment["environment"]
        assert "DECNET_LOG_FILE" in env
        assert env["DECNET_LOG_FILE"].startswith(_CONTAINER_LOG_DIR)
        assert env["DECNET_LOG_FILE"].endswith("decnet.log")

    def test_log_file_adds_volume_mount(self, tmp_path):
        config = _make_config(log_file=str(tmp_path / "decnet.log"))
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        volumes = fragment.get("volumes", [])
        assert any(_CONTAINER_LOG_DIR in v for v in volumes)

    def test_volume_mount_format(self, tmp_path):
        config = _make_config(log_file=str(tmp_path / "decnet.log"))
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        mount = next(v for v in fragment["volumes"] if _CONTAINER_LOG_DIR in v)
        host_part, container_part = mount.split(":")
        assert Path(host_part).is_absolute()
        assert container_part == _CONTAINER_LOG_DIR

    def test_host_log_dir_created(self, tmp_path):
        log_dir = tmp_path / "newdir"
        config = _make_config(log_file=str(log_dir / "decnet.log"))
        generate_compose(config)
        assert log_dir.exists()

    def test_volume_not_duplicated(self, tmp_path):
        """Same mount must not appear twice even if fragment already has volumes."""
        config = _make_config(log_file=str(tmp_path / "decnet.log"))
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        log_mounts = [v for v in fragment["volumes"] if _CONTAINER_LOG_DIR in v]
        assert len(log_mounts) == 1
