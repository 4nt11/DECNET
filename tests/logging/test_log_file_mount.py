# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for compose generation — logging block and absence of volume mounts."""

from decnet.composer import generate_compose, _DOCKER_LOGGING
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


class TestComposeLogging:
    def test_service_container_has_logging_block(self):
        config = _make_config()
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        assert "logging" in fragment
        assert fragment["logging"] == _DOCKER_LOGGING

    def test_logging_driver_is_json_file(self):
        config = _make_config()
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        assert fragment["logging"]["driver"] == "json-file"

    def test_logging_has_rotation_options(self):
        config = _make_config()
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        opts = fragment["logging"]["options"]
        assert "max-size" in opts
        assert "max-file" in opts

    def test_base_container_has_no_logging_block(self):
        """Base containers run sleep infinity and produce no app logs."""
        config = _make_config()
        compose = generate_compose(config)
        base = compose["services"]["decky-01"]
        assert "logging" not in base

    def test_no_volume_mounts_on_service_container(self):
        config = _make_config(log_file="/tmp/decnet.log")
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        assert not fragment.get("volumes")

    def test_no_decnet_log_file_env_var(self):
        config = _make_config(log_file="/tmp/decnet.log")
        compose = generate_compose(config)
        fragment = compose["services"]["decky-01-http"]
        assert "DECNET_LOG_FILE" not in fragment.get("environment", {})

    def test_no_log_network_in_networks(self):
        config = _make_config()
        compose = generate_compose(config)
        assert "decnet_logs" not in compose["networks"]
