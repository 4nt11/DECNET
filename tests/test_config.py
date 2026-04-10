"""
Tests for decnet.config — Pydantic models, save/load/clear state.
Covers the uncovered lines: validators, save_state, load_state, clear_state.
"""
import pytest

import decnet.config as config_module
from decnet.config import (
    DeckyConfig,
    DecnetConfig,
    save_state,
    load_state,
    clear_state,
)


# ---------------------------------------------------------------------------
# DeckyConfig validator
# ---------------------------------------------------------------------------

class TestDeckyConfig:
    def _base(self, **kwargs):
        defaults = dict(
            name="decky-01", ip="192.168.1.10", services=["ssh"],
            distro="debian", base_image="debian", hostname="host-01",
        )
        defaults.update(kwargs)
        return defaults

    def test_valid_decky(self):
        d = DeckyConfig(**self._base())
        assert d.name == "decky-01"

    def test_empty_services_raises(self):
        with pytest.raises(Exception, match="at least one service"):
            DeckyConfig(**self._base(services=[]))

    def test_multiple_services_ok(self):
        d = DeckyConfig(**self._base(services=["ssh", "smb", "rdp"]))
        assert len(d.services) == 3


# ---------------------------------------------------------------------------
# DecnetConfig validator
# ---------------------------------------------------------------------------

class TestDecnetConfig:
    def _base_decky(self):
        return DeckyConfig(
            name="d", ip="10.0.0.2", services=["ssh"],
            distro="debian", base_image="debian", hostname="h",
        )

    def test_valid_config(self):
        cfg = DecnetConfig(
            mode="unihost", interface="eth0",
            subnet="10.0.0.0/24", gateway="10.0.0.1",
            deckies=[self._base_decky()],
        )
        assert cfg.mode == "unihost"

    def test_log_file_field(self):
        cfg = DecnetConfig(
            mode="unihost", interface="eth0",
            subnet="10.0.0.0/24", gateway="10.0.0.1",
            deckies=[self._base_decky()],
            log_file="/var/log/decnet/decnet.log",
        )
        assert cfg.log_file == "/var/log/decnet/decnet.log"

    def test_log_file_defaults_to_none(self):
        cfg = DecnetConfig(
            mode="unihost", interface="eth0",
            subnet="10.0.0.0/24", gateway="10.0.0.1",
            deckies=[self._base_decky()],
        )
        assert cfg.log_file is None


# ---------------------------------------------------------------------------
# save_state / load_state / clear_state
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_state_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "STATE_FILE", tmp_path / "decnet-state.json")


def _sample_config():
    return DecnetConfig(
        mode="unihost", interface="eth0",
        subnet="192.168.1.0/24", gateway="192.168.1.1",
        deckies=[
            DeckyConfig(
                name="decky-01", ip="192.168.1.10", services=["ssh"],
                distro="debian", base_image="debian", hostname="host-01",
            )
        ],
    )


def test_save_and_load_state(tmp_path):
    cfg = _sample_config()
    compose = tmp_path / "docker-compose.yml"
    save_state(cfg, compose)

    result = load_state()
    assert result is not None
    loaded_cfg, loaded_compose = result
    assert loaded_cfg.mode == "unihost"
    assert loaded_cfg.deckies[0].name == "decky-01"
    assert loaded_compose == compose


def test_load_state_returns_none_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "STATE_FILE", tmp_path / "nonexistent.json")
    assert load_state() is None


def test_clear_state(tmp_path):
    cfg = _sample_config()
    save_state(cfg, tmp_path / "compose.yml")
    assert config_module.STATE_FILE.exists()

    clear_state()
    assert not config_module.STATE_FILE.exists()


def test_clear_state_noop_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "STATE_FILE", tmp_path / "nonexistent.json")
    clear_state()  # should not raise


def test_state_roundtrip_preserves_all_fields(tmp_path):
    cfg = _sample_config()
    cfg.deckies[0].archetype = "workstation"
    cfg.deckies[0].mutate_interval = 45
    compose = tmp_path / "compose.yml"
    save_state(cfg, compose)

    loaded_cfg, _ = load_state()
    assert loaded_cfg.deckies[0].archetype == "workstation"
    assert loaded_cfg.deckies[0].mutate_interval == 45
