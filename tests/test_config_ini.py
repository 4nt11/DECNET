"""decnet.config_ini — INI file loader, precedence, section routing."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from decnet.config_ini import load_ini_config


def _write_ini(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "decnet.ini"
    p.write_text(body)
    return p


def _scrub(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for n in names:
        monkeypatch.delenv(n, raising=False)


def test_missing_file_is_noop(monkeypatch, tmp_path):
    _scrub(monkeypatch, "DECNET_MODE", "DECNET_AGENT_PORT")
    result = load_ini_config(tmp_path / "does-not-exist.ini")
    assert result is None
    assert "DECNET_AGENT_PORT" not in os.environ


def test_agent_section_only_loaded_when_mode_agent(monkeypatch, tmp_path):
    _scrub(
        monkeypatch,
        "DECNET_MODE", "DECNET_DISALLOW_MASTER",
        "DECNET_AGENT_PORT", "DECNET_MASTER_HOST",
        "DECNET_API_PORT", "DECNET_SWARMCTL_PORT",
    )
    ini = _write_ini(tmp_path, """
[decnet]
mode = agent

[agent]
agent-port = 8765
master-host = 192.168.1.50

[master]
api-port = 9999
swarmctl-port = 8770
""")
    load_ini_config(ini)
    assert os.environ["DECNET_MODE"] == "agent"
    assert os.environ["DECNET_AGENT_PORT"] == "8765"
    assert os.environ["DECNET_MASTER_HOST"] == "192.168.1.50"
    # [master] section values must NOT leak into an agent host's env
    assert "DECNET_API_PORT" not in os.environ
    assert "DECNET_SWARMCTL_PORT" not in os.environ


def test_master_section_loaded_when_mode_master(monkeypatch, tmp_path):
    _scrub(
        monkeypatch,
        "DECNET_MODE", "DECNET_API_PORT",
        "DECNET_SWARMCTL_PORT", "DECNET_AGENT_PORT",
    )
    ini = _write_ini(tmp_path, """
[decnet]
mode = master

[agent]
agent-port = 8765

[master]
api-port = 8000
swarmctl-port = 8770
""")
    load_ini_config(ini)
    assert os.environ["DECNET_MODE"] == "master"
    assert os.environ["DECNET_API_PORT"] == "8000"
    assert os.environ["DECNET_SWARMCTL_PORT"] == "8770"
    assert "DECNET_AGENT_PORT" not in os.environ


def test_env_wins_over_ini(monkeypatch, tmp_path):
    _scrub(monkeypatch, "DECNET_MODE")
    monkeypatch.setenv("DECNET_AGENT_PORT", "7777")
    ini = _write_ini(tmp_path, """
[decnet]
mode = agent

[agent]
agent-port = 8765
""")
    load_ini_config(ini)
    # Real env var must beat INI value
    assert os.environ["DECNET_AGENT_PORT"] == "7777"


def test_common_keys_always_exported(monkeypatch, tmp_path):
    _scrub(monkeypatch, "DECNET_MODE", "DECNET_DISALLOW_MASTER", "DECNET_LOG_DIRECTORY")
    ini = _write_ini(tmp_path, """
[decnet]
mode = agent
disallow-master = true
log-directory = /var/log/decnet
""")
    load_ini_config(ini)
    assert os.environ["DECNET_MODE"] == "agent"
    assert os.environ["DECNET_DISALLOW_MASTER"] == "true"
    assert os.environ["DECNET_LOG_DIRECTORY"] == "/var/log/decnet"


def test_invalid_mode_raises(monkeypatch, tmp_path):
    _scrub(monkeypatch, "DECNET_MODE")
    ini = _write_ini(tmp_path, """
[decnet]
mode = supervisor
""")
    with pytest.raises(ValueError, match="mode must be"):
        load_ini_config(ini)


def test_decnet_config_env_var_overrides_default_path(monkeypatch, tmp_path):
    _scrub(monkeypatch, "DECNET_MODE", "DECNET_API_PORT")
    ini = _write_ini(tmp_path, """
[decnet]
mode = master

[master]
api-port = 9001
""")
    monkeypatch.setenv("DECNET_CONFIG", str(ini))
    # Call with no explicit path — loader reads $DECNET_CONFIG
    loaded = load_ini_config()
    assert loaded == ini
    assert os.environ["DECNET_API_PORT"] == "9001"
