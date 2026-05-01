"""Parse /etc/decnet/decnet.ini and seed os.environ defaults.

The INI file is a convenience layer on top of the existing DECNET_* env
vars. It never overrides an explicit environment variable (uses
os.environ.setdefault). Call load_ini_config() once, very early, before
any decnet.env import, so env.py picks up the seeded values as if they
had been exported by the shell.

Shape::

    [decnet]
    mode = master                 # or "agent"

    [api]
    host = 127.0.0.1
    port = 8000

    [web]
    host = 127.0.0.1
    port = 8080
    admin-user = admin
    cors-origins = http://localhost:8080

    [database]
    type = sqlite                 # or "mysql"
    url = mysql+asyncmy://user@host:3306/decnet  # wins over host/port/name/user
    host = localhost
    port = 3306
    name = decnet
    user = decnet

    [bus]
    enabled = true
    type = unix                   # or "fake"
    socket = /run/decnet/bus.sock
    group = decnet

    [swarm]
    master-host = 10.0.0.1        # required on agents
    syslog-port = 6514
    swarmctl-port = 8770
    swarmctl-host = 127.0.0.1     # bind address for `decnet swarmctl`

    [logging]
    system-log = /var/log/decnet/decnet.system.log
    ingest-log = /var/log/decnet/decnet.log
    agent-log  = /var/log/decnet/agent.log

    [ingester]
    batch-size = 100
    batch-max-wait-ms = 250

    [tracing]
    enabled = false
    otel-endpoint = http://localhost:4317

    [agent]
    # Written by the enroll bundle on agent hosts — don't hand-edit.
    host-uuid = ...
    master-host = ...

The ``[decnet]`` and role-specific ``[agent]`` / ``[master]`` sections
use auto kebab-to-snake translation (``master-host`` → ``DECNET_MASTER_HOST``).
The domain sections (``[api]``, ``[web]``, etc.) use an explicit key map
so ``[web] admin-user`` resolves to ``DECNET_ADMIN_USER`` without silently
renaming the env-var contract consumers already import from ``decnet.env``.

Secrets (``DECNET_JWT_SECRET``, ``DECNET_ADMIN_PASSWORD``,
``DECNET_DB_PASSWORD``) are deliberately NOT in the domain map. They
belong in ``.env.local`` / systemd ``EnvironmentFile=`` so they never
hit the dashboard, never end up in `config.ini`-style diffs, and never
get group-readable alongside tunables.
"""
from __future__ import annotations

import configparser
import logging
import os
from pathlib import Path
from typing import Optional


DEFAULT_CONFIG_PATH = Path("/etc/decnet/decnet.ini")

log = logging.getLogger(__name__)

# The [decnet] section keys are role-agnostic and always exported.
_COMMON_KEYS = frozenset({"mode", "disallow-master", "log-directory"})


# Explicit INI-key → env-var mapping for the domain sections. Kept
# separate from the role-specific [agent] / [master] loader so the
# admin-facing section layout ([web] admin-user) can diverge from the
# env-var name (DECNET_ADMIN_USER) without breaking any consumer.
_DOMAIN_MAP: dict[str, dict[str, str]] = {
    "api": {
        "host": "DECNET_API_HOST",
        "port": "DECNET_API_PORT",
    },
    "web": {
        "host": "DECNET_WEB_HOST",
        "port": "DECNET_WEB_PORT",
        "admin-user": "DECNET_ADMIN_USER",
        "cors-origins": "DECNET_CORS_ORIGINS",
    },
    "database": {
        "type": "DECNET_DB_TYPE",
        "url": "DECNET_DB_URL",
        "host": "DECNET_DB_HOST",
        "port": "DECNET_DB_PORT",
        "name": "DECNET_DB_NAME",
        "user": "DECNET_DB_USER",
    },
    "bus": {
        "enabled": "DECNET_BUS_ENABLED",
        "type": "DECNET_BUS_TYPE",
        "socket": "DECNET_BUS_SOCKET",
        "group": "DECNET_BUS_GROUP",
    },
    "swarm": {
        "master-host": "DECNET_SWARM_MASTER_HOST",
        "syslog-port": "DECNET_SWARM_SYSLOG_PORT",
        "swarmctl-port": "DECNET_SWARMCTL_PORT",
        "swarmctl-host": "DECNET_SWARMCTL_HOST",
    },
    "logging": {
        "system-log": "DECNET_SYSTEM_LOGS",
        "ingest-log": "DECNET_INGEST_LOG_FILE",
        "agent-log": "DECNET_AGENT_LOG_FILE",
    },
    "ingester": {
        "batch-size": "DECNET_BATCH_SIZE",
        "batch-max-wait-ms": "DECNET_BATCH_MAX_WAIT_MS",
    },
    "tracing": {
        "enabled": "DECNET_DEVELOPER_TRACING",
        "otel-endpoint": "DECNET_OTEL_ENDPOINT",
    },
}


def _key_to_env(key: str) -> str:
    return "DECNET_" + key.replace("-", "_").upper()


def load_ini_config(path: Optional[Path] = None) -> Optional[Path]:
    """Seed os.environ defaults from the DECNET INI file.

    Returns the path that was actually loaded (so callers can log it), or
    None if no file was read. Missing file is a no-op — callers fall back
    to env vars / CLI flags / hardcoded defaults.

    Precedence: real os.environ > INI > defaults. Real env vars are never
    overwritten because we use setdefault().
    """
    if path is None:
        override = os.environ.get("DECNET_CONFIG")
        path = Path(override) if override else DEFAULT_CONFIG_PATH

    if not path.is_file():
        return None

    # The docstring at the top of this module advertises inline ``#`` and
    # ``;`` comments (e.g. ``mode = master    # or "agent"``). Python's
    # ``configparser`` only recognises those when ``inline_comment_prefixes``
    # is set explicitly — without it, the comment becomes part of the value
    # and downstream validators reject it ("mode must be 'agent' or 'master',
    # got 'master                  # or \"agent\"'"). Match what the docs
    # promise.
    parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    parser.read(path)

    # [decnet] first — mode/disallow-master/log-directory. These seed the
    # mode decision for the section selection below.
    if parser.has_section("decnet"):
        for key, value in parser.items("decnet"):
            os.environ.setdefault(_key_to_env(key), value)

    mode = os.environ.get("DECNET_MODE", "master").lower()
    if mode not in ("agent", "master"):
        raise ValueError(
            f"decnet.ini: [decnet] mode must be 'agent' or 'master', got '{mode}'"
        )

    # Role-specific section — kebab→SCREAMING_SNAKE auto-translation.
    # Kept for backwards compatibility with the enroll-bundle [agent]
    # writer (decnet/web/router/swarm_mgmt/api_enroll_bundle.py).
    section = mode
    if parser.has_section(section):
        for key, value in parser.items(section):
            os.environ.setdefault(_key_to_env(key), value)

    # Domain sections — explicit key map; loaded regardless of mode.
    # Unknown keys inside a known section log a WARNING so operator
    # typos are visible; unknown sections are silently ignored (so the
    # file format can grow without breaking older loaders).
    for section_name, key_map in _DOMAIN_MAP.items():
        if not parser.has_section(section_name):
            continue
        for key, value in parser.items(section_name):
            env_name = key_map.get(key)
            if env_name is None:
                log.warning(
                    "decnet.ini: unknown key [%s] %s — ignored",
                    section_name, key,
                )
                continue
            os.environ.setdefault(env_name, value)

    return path
