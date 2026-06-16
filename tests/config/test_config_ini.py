# SPDX-License-Identifier: AGPL-3.0-or-later
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


def test_inline_comments_stripped_from_values(monkeypatch, tmp_path):
    """The module docstring teaches inline ``#`` comments — the parser
    must accept them. Hit live on the first VPS deploy 2026-04-28: a
    ``mode = master    # or "agent"`` line caused the value to be parsed
    as ``master                  # or "agent"`` and downstream
    validators rejected it."""
    _scrub(monkeypatch, "DECNET_MODE", "DECNET_API_PORT")
    ini = _write_ini(tmp_path, """
[decnet]
mode = master   # inline hash comment
[master]
api-port = 8000   ; inline semi comment
""")
    load_ini_config(ini)
    assert os.environ["DECNET_MODE"] == "master"
    assert os.environ["DECNET_API_PORT"] == "8000"


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


# ─── Domain sections ────────────────────────────────────────────────────────


def test_domain_sections_load_regardless_of_mode(monkeypatch, tmp_path):
    """[api], [web], [database], etc. load on both master and agent —
    setdefault makes unused keys harmless on the other role."""
    _scrub(
        monkeypatch,
        "DECNET_MODE", "DECNET_API_HOST", "DECNET_API_PORT",
        "DECNET_WEB_PORT", "DECNET_ADMIN_USER", "DECNET_CORS_ORIGINS",
        "DECNET_DB_TYPE", "DECNET_DB_URL",
        "DECNET_BUS_ENABLED", "DECNET_BUS_GROUP",
        "DECNET_SWARM_SYSLOG_PORT",
        "DECNET_SYSTEM_LOGS", "DECNET_INGEST_LOG_FILE",
        "DECNET_BATCH_SIZE", "DECNET_BATCH_MAX_WAIT_MS",
        "DECNET_DEVELOPER_TRACING", "DECNET_OTEL_ENDPOINT",
    )
    ini = _write_ini(tmp_path, """
[decnet]
mode = agent

[api]
host = 0.0.0.0
port = 8001

[web]
port = 9090
admin-user = superman
cors-origins = https://dash.example.com

[database]
type = mysql
url = mysql+asyncmy://decnet@db/decnet

[bus]
enabled = false
group = custom

[swarm]
syslog-port = 7514

[logging]
system-log = /tmp/decnet.log
ingest-log = /tmp/decnet.ingest.log

[ingester]
batch-size = 500
batch-max-wait-ms = 1000

[tracing]
enabled = true
otel-endpoint = http://otel.internal:4317
""")
    load_ini_config(ini)
    assert os.environ["DECNET_API_HOST"] == "0.0.0.0"
    assert os.environ["DECNET_API_PORT"] == "8001"
    assert os.environ["DECNET_WEB_PORT"] == "9090"
    assert os.environ["DECNET_ADMIN_USER"] == "superman"
    assert os.environ["DECNET_CORS_ORIGINS"] == "https://dash.example.com"
    assert os.environ["DECNET_DB_TYPE"] == "mysql"
    assert os.environ["DECNET_DB_URL"] == "mysql+asyncmy://decnet@db/decnet"
    assert os.environ["DECNET_BUS_ENABLED"] == "false"
    assert os.environ["DECNET_BUS_GROUP"] == "custom"
    assert os.environ["DECNET_SWARM_SYSLOG_PORT"] == "7514"
    assert os.environ["DECNET_SYSTEM_LOGS"] == "/tmp/decnet.log"
    assert os.environ["DECNET_INGEST_LOG_FILE"] == "/tmp/decnet.ingest.log"
    assert os.environ["DECNET_BATCH_SIZE"] == "500"
    assert os.environ["DECNET_BATCH_MAX_WAIT_MS"] == "1000"
    assert os.environ["DECNET_DEVELOPER_TRACING"] == "true"
    assert os.environ["DECNET_OTEL_ENDPOINT"] == "http://otel.internal:4317"


def test_domain_section_env_wins_over_ini(monkeypatch, tmp_path):
    """Real env var beats the INI for a domain-section key, same as
    the role-specific section contract."""
    _scrub(monkeypatch, "DECNET_MODE")
    monkeypatch.setenv("DECNET_API_PORT", "5555")
    ini = _write_ini(tmp_path, """
[decnet]
mode = master

[api]
port = 8000
""")
    load_ini_config(ini)
    assert os.environ["DECNET_API_PORT"] == "5555"


def test_domain_unknown_key_logs_warning(monkeypatch, tmp_path, caplog):
    """Typos in a domain section should be visible to the operator —
    a silent drop is how you spend an afternoon debugging 'why isn't
    my setting taking effect'."""
    _scrub(monkeypatch, "DECNET_MODE")
    ini = _write_ini(tmp_path, """
[decnet]
mode = master

[api]
host = 127.0.0.1
# typo: hostt instead of host
hostt = 0.0.0.0
""")
    import logging as _logging
    with caplog.at_level(_logging.WARNING, logger="decnet.config_ini"):
        load_ini_config(ini)
    assert any(
        "unknown key [api] hostt" in rec.getMessage()
        for rec in caplog.records
    ), f"expected warning about unknown key, got: {[r.getMessage() for r in caplog.records]}"


def test_domain_absent_section_is_noop(monkeypatch, tmp_path):
    """INI with only [decnet] present doesn't touch any domain env var."""
    _scrub(
        monkeypatch,
        "DECNET_MODE", "DECNET_API_PORT", "DECNET_WEB_PORT",
        "DECNET_DB_TYPE", "DECNET_BUS_ENABLED",
    )
    ini = _write_ini(tmp_path, """
[decnet]
mode = master
""")
    load_ini_config(ini)
    assert os.environ["DECNET_MODE"] == "master"
    assert "DECNET_API_PORT" not in os.environ
    assert "DECNET_WEB_PORT" not in os.environ
    assert "DECNET_DB_TYPE" not in os.environ
    assert "DECNET_BUS_ENABLED" not in os.environ


def test_domain_section_does_not_override_role_section(monkeypatch, tmp_path):
    """If both [master] (role) and [swarm] (domain) define swarmctl-port,
    whichever the loader applies first wins via setdefault — and the role
    section runs first, so the [swarm] value is dropped silently.

    This locks in the precedence order as part of the contract."""
    _scrub(monkeypatch, "DECNET_MODE", "DECNET_SWARMCTL_PORT")
    ini = _write_ini(tmp_path, """
[decnet]
mode = master

[master]
swarmctl-port = 9001

[swarm]
swarmctl-port = 9999
""")
    load_ini_config(ini)
    # [master] loaded first, [swarm] lost via setdefault
    assert os.environ["DECNET_SWARMCTL_PORT"] == "9001"


def test_swarm_section_seeds_swarmctl_host(monkeypatch, tmp_path):
    """[swarm] swarmctl-host → DECNET_SWARMCTL_HOST so the systemd unit and
    `decnet swarmctl` CLI both pick up the operator's bind choice from the
    INI without anyone passing --host on ExecStart."""
    _scrub(monkeypatch, "DECNET_MODE", "DECNET_SWARMCTL_HOST", "DECNET_SWARMCTL_PORT")
    ini = _write_ini(tmp_path, """
[swarm]
swarmctl-host = 0.0.0.0
swarmctl-port = 9000
""")
    load_ini_config(ini)
    assert os.environ["DECNET_SWARMCTL_HOST"] == "0.0.0.0"
    assert os.environ["DECNET_SWARMCTL_PORT"] == "9000"
