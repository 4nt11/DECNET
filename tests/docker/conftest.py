"""
Shared fixtures for tests under `tests/docker/`.

All tests here are marked `docker` and excluded from the default run
(see pyproject.toml addopts). Enable with: `pytest -m docker`.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    return True


@pytest.fixture(scope="session", autouse=True)
def _require_docker():
    if not _docker_available():
        pytest.skip("docker daemon not reachable", allow_module_level=True)
