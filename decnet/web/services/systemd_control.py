"""Thin async wrapper over ``systemctl`` for DECNET worker units.

The API process runs as the unprivileged ``decnet`` user and delegates
the actual start/stop to systemd via a scoped polkit rule (see
``deploy/polkit/50-decnet-workers.rules``).  This module keeps the shell
surface area minimal:

* Unit names are always ``decnet-<name>.service`` — callers pass the
  bare worker name and the ``.service`` suffix is bolted on here.
* ``asyncio.create_subprocess_exec`` — never ``shell=True``.  Worker
  names are also validated at the router boundary against
  :data:`decnet.web.worker_registry.KNOWN_WORKERS`; the extra regex
  check here is defence in depth.
* ``list_installed()`` results are cached for 30 seconds to keep the
  status endpoint cheap under repeated REFRESH clicks.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Set

from decnet.logging import get_logger

log = get_logger("web.systemd_control")

_UNIT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_LIST_CACHE_TTL = 30.0

_cache: Set[str] | None = None
_cache_ts: float = 0.0


class SystemctlError(RuntimeError):
    """Non-zero exit from ``systemctl``.  Carries returncode + stderr."""

    def __init__(self, unit: str, returncode: int, stderr: str) -> None:
        self.unit = unit
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(
            f"systemctl failed on {unit}: rc={returncode} stderr={stderr!r}"
        )


def _unit(name: str) -> str:
    if not _UNIT_NAME_RE.match(name):
        raise ValueError(f"invalid worker name: {name!r}")
    return f"decnet-{name}.service"


async def _run(*argv: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout_b.decode("utf-8", "replace"),
        stderr_b.decode("utf-8", "replace"),
    )


async def _systemctl(verb: str, name: str) -> None:
    unit = _unit(name)
    rc, _, stderr = await _run("systemctl", verb, unit)
    if rc != 0:
        log.warning("systemctl %s %s failed: rc=%s stderr=%s", verb, unit, rc, stderr.strip())
        raise SystemctlError(unit=unit, returncode=rc, stderr=stderr.strip())


async def start(name: str) -> None:
    """Start ``decnet-<name>.service``.  Raises :class:`SystemctlError`."""
    await _systemctl("start", name)


async def stop(name: str) -> None:
    """Stop ``decnet-<name>.service``.  Raises :class:`SystemctlError`.

    Unused in v1 (bus-based STOP is authoritative) but kept for parity
    so the supervisor contract is symmetric.
    """
    await _systemctl("stop", name)


async def is_active(name: str) -> bool:
    """Return True iff ``systemctl is-active`` reports ``active``.

    ``is-active`` exits non-zero for inactive / failed / unknown units;
    that is **not** an error here — it's a signal.
    """
    unit = _unit(name)
    _, stdout, _ = await _run("systemctl", "is-active", unit)
    return stdout.strip() == "active"


async def list_installed(*, force: bool = False) -> Set[str]:
    """Return the set of worker names with unit files installed.

    Parses ``systemctl list-unit-files 'decnet-*.service' --no-legend``
    and strips the ``decnet-`` prefix + ``.service`` suffix off each
    line.  Cached for :data:`_LIST_CACHE_TTL` seconds; pass
    ``force=True`` to bypass.
    """
    global _cache, _cache_ts
    now = time.time()
    if not force and _cache is not None and (now - _cache_ts) < _LIST_CACHE_TTL:
        return set(_cache)
    rc, stdout, stderr = await _run(
        "systemctl", "list-unit-files", "decnet-*.service", "--no-legend",
    )
    if rc != 0:
        # systemd missing / non-systemd host — treat as "nothing installed"
        # and keep the UI rendering.  Cache the empty result so we don't
        # hammer the failing binary on every refresh.
        log.info("list-unit-files failed (treating as empty): rc=%s stderr=%s", rc, stderr.strip())
        _cache = set()
        _cache_ts = now
        return set()
    names: Set[str] = set()
    for line in stdout.splitlines():
        token = line.split(None, 1)[0] if line.strip() else ""
        if token.startswith("decnet-") and token.endswith(".service"):
            names.add(token[len("decnet-"):-len(".service")])
    _cache = names
    _cache_ts = now
    return set(names)


def reset_cache_for_tests() -> None:
    global _cache, _cache_ts
    _cache = None
    _cache_ts = 0.0
