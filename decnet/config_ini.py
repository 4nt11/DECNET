"""Parse /etc/decnet/decnet.ini and seed os.environ defaults.

The INI file is a convenience layer on top of the existing DECNET_* env
vars. It never overrides an explicit environment variable (uses
os.environ.setdefault). Call load_ini_config() once, very early, before
any decnet.env import, so env.py picks up the seeded values as if they
had been exported by the shell.

Shape::

    [decnet]
    mode = agent              # or "master"
    log-file-path = /var/log/decnet/decnet.log
    disallow-master = true

    [agent]
    master-host = 192.168.1.50
    master-port = 8770
    agent-port = 8765
    agent-dir = /home/anti/.decnet/agent
    ...

    [master]
    api-host = 0.0.0.0
    swarmctl-port = 8770
    listener-port = 6514
    ...

Only the section matching `mode` is loaded. The other section is
ignored silently so an agent host never reads master secrets (and
vice versa). Keys are converted to SCREAMING_SNAKE_CASE and prefixed
with ``DECNET_`` — e.g. ``master-host`` → ``DECNET_MASTER_HOST``.
"""
from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Optional


DEFAULT_CONFIG_PATH = Path("/etc/decnet/decnet.ini")

# The [decnet] section keys are role-agnostic and always exported.
_COMMON_KEYS = frozenset({"mode", "disallow-master", "log-file-path"})


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

    parser = configparser.ConfigParser()
    parser.read(path)

    # [decnet] first — mode/disallow-master/log-file-path. These seed the
    # mode decision for the section selection below.
    if parser.has_section("decnet"):
        for key, value in parser.items("decnet"):
            os.environ.setdefault(_key_to_env(key), value)

    mode = os.environ.get("DECNET_MODE", "master").lower()
    if mode not in ("agent", "master"):
        raise ValueError(
            f"decnet.ini: [decnet] mode must be 'agent' or 'master', got '{mode}'"
        )

    # Role-specific section.
    section = mode
    if parser.has_section(section):
        for key, value in parser.items(section):
            os.environ.setdefault(_key_to_env(key), value)

    return path
