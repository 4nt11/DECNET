"""Plant / revoke canary artifacts inside running decky containers.

Single entry point per operation:

* :func:`plant` writes a :class:`CanaryArtifact` into one decky's
  filesystem via ``docker exec`` (mirroring the SSH driver's
  ``_run_file`` pattern), backdates the mtime, sets the requested
  mode, and publishes ``canary.{token_id}.placed`` on the bus.
* :func:`revoke` unlinks the file (best-effort) and publishes
  ``canary.{token_id}.revoked``.
* :func:`seed_baseline` is the deploy-hook helper: synthesises the
  configured baseline set for one decky, persists rows, plants each.
  Failures are logged but do **not** abort the deploy (the deployer
  hook calls this best-effort).

We don't reuse :class:`SSHDriver` directly because the orchestrator
driver is tied to its action types (``FileAction`` carries str
content; canary content is bytes).  The planter takes the same
shape but speaks bytes-via-base64 over the wire.
"""
from __future__ import annotations

import asyncio
import base64
import os
import shlex
import time
from secrets import token_urlsafe
from typing import Any, Iterable, Optional

from decnet.bus import topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.canary.base import CanaryArtifact, CanaryContext
from decnet.canary.factory import get_generator
from decnet.canary.paths import default_path_for
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("canary.planter")

_DOCKER = "docker"
_TIMEOUT = 8.0
# Container suffix — matches the orchestrator SSH driver's convention
# (``<decky_name>-ssh``).  Canary placement always happens through the
# ssh container because every decky has one and it carries the most
# realistic filesystem layout.
_SSH_CONTAINER_SUFFIX = "-ssh"


def _container_for(decky_name: str) -> str:
    return f"{decky_name}{_SSH_CONTAINER_SUFFIX}"


def _dirname(path: str) -> str:
    idx = path.rfind("/")
    if idx <= 0:
        return "/"
    return path[:idx]


async def _run(argv: list[str]) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return 127, "", f"argv[0] not found: {exc}"
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_TIMEOUT)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return 124, "", "timeout"
    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )


def _build_plant_command(artifact: CanaryArtifact) -> str:
    """Compose the ``sh -c`` script that writes one artifact.

    Binary safety: we base64-encode on the host side and ``base64 -d``
    inside the container, so the bytes never touch a shell argv
    interpolation point.  Both ``base64`` (coreutils) and ``touch -d
    @<unix_ts>`` are present on every Linux base image we ship, so
    there's no per-distro branching.
    """
    encoded = base64.b64encode(artifact.content).decode("ascii")
    mtime = int(time.time() + artifact.mtime_offset)
    mode_str = oct(artifact.mode)[2:]
    parts = [
        f"mkdir -p {shlex.quote(_dirname(artifact.path))}",
        f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(artifact.path)}",
        f"chmod {mode_str} {shlex.quote(artifact.path)}",
        f"touch -d @{mtime} {shlex.quote(artifact.path)}",
    ]
    return " && ".join(parts)


async def _publish(
    bus: Optional[BaseBus], topic: str, payload: dict[str, Any],
) -> None:
    """Best-effort publish — never raises.

    When ``bus`` is None we resolve via :func:`get_bus`; either way
    bus-side failures are logged and swallowed (delivery is at-most-once
    by contract; the DB row is source of truth).
    """
    try:
        owns_bus = bus is None
        target = bus if bus is not None else get_bus()
        if owns_bus:
            await target.connect()
        await target.publish(topic, payload)
        if owns_bus:
            await target.close()
    except Exception as e:  # noqa: BLE001
        log.warning("canary bus publish failed topic=%s err=%s", topic, e)


async def plant(
    decky_name: str,
    artifact: CanaryArtifact,
    *,
    token_uuid: str,
    repo: Optional[BaseRepository] = None,
    publish: bool = True,
    bus: Optional[BaseBus] = None,
) -> tuple[bool, Optional[str]]:
    """Write *artifact* into the decky's ssh container.

    Returns ``(success, error_or_none)``.  When ``repo`` is provided
    the token row's state is updated to ``planted`` / ``failed``
    accordingly.  When ``publish`` is True a ``canary.<id>.placed``
    event is published on the bus on success.

    The function never raises on docker errors — callers (the API,
    the deploy hook) treat the result as data.
    """
    if not artifact.path:
        err = "planter requires a non-empty artifact.path"
        log.warning("canary.plant skipped: %s decky=%s token=%s", err, decky_name, token_uuid)
        if repo is not None:
            await repo.update_canary_token_state(token_uuid, "failed", err)
        return False, err

    sh_cmd = _build_plant_command(artifact)
    argv = [_DOCKER, "exec", _container_for(decky_name), "sh", "-c", sh_cmd]
    rc, _stdout, stderr = await _run(argv)
    success = rc == 0
    error = None if success else (stderr.strip()[:256] or f"rc={rc}")

    if repo is not None:
        if success:
            await repo.update_canary_token_state(token_uuid, "planted", None)
        else:
            await repo.update_canary_token_state(token_uuid, "failed", error)

    if success and publish:
        await _publish(bus, topics.canary(token_uuid, topics.CANARY_PLACED), {
            "token_id": token_uuid,
            "decky_name": decky_name,
            "placement_path": artifact.path,
            "instrumenter": artifact.instrumenter,
            "generator": artifact.generator,
        })

    if not success:
        log.warning(
            "canary.plant failed decky=%s token=%s rc=%d stderr=%r",
            decky_name, token_uuid, rc, stderr[:120],
        )
    return success, error


async def revoke(
    decky_name: str,
    placement_path: str,
    *,
    token_uuid: str,
    repo: Optional[BaseRepository] = None,
    publish: bool = True,
    bus: Optional[BaseBus] = None,
) -> tuple[bool, Optional[str]]:
    """Best-effort unlink + state transition + bus publish.

    Returns ``(success, error_or_none)``.  ``success`` is True when
    the file is gone after the call (whether we deleted it or it was
    already missing); only docker / container-down errors return False.
    """
    sh_cmd = f"rm -f {shlex.quote(placement_path)}"
    argv = [_DOCKER, "exec", _container_for(decky_name), "sh", "-c", sh_cmd]
    rc, _stdout, stderr = await _run(argv)
    success = rc == 0
    error = None if success else (stderr.strip()[:256] or f"rc={rc}")

    if repo is not None:
        await repo.update_canary_token_state(token_uuid, "revoked", error if not success else None)

    if publish:
        await _publish(bus, topics.canary(token_uuid, topics.CANARY_REVOKED), {
            "token_id": token_uuid,
            "decky_name": decky_name,
            "placement_path": placement_path,
        })

    return success, error


def _baseline_set() -> Iterable[str]:
    """Return the configured baseline generator names.

    Honors ``DECNET_CANARY_BASELINE`` (comma-separated).  Default is
    a sensible mix that exercises every callback-bearing generator
    plus a passive aws_creds drop for realism.
    """
    raw = os.environ.get(
        "DECNET_CANARY_BASELINE",
        "git_config,env_file,honeydoc,aws_creds",
    )
    return [n.strip() for n in raw.split(",") if n.strip()]


def _ctx_for(slug: str) -> CanaryContext:
    """Build a :class:`CanaryContext` from the canary worker config."""
    base = os.environ.get("DECNET_CANARY_HTTP_BASE", "http://localhost:8088")
    zone = os.environ.get("DECNET_CANARY_DNS_ZONE", "")
    return CanaryContext(callback_token=slug, http_base=base, dns_zone=zone)


async def seed_baseline(
    decky_name: str,
    repo: BaseRepository,
    *,
    persona: str = "linux",
    created_by: str = "system",
    bus: Optional[BaseBus] = None,
) -> list[dict[str, Any]]:
    """Plant the configured baseline canary set on one decky.

    Best-effort: any individual placement that fails is logged and
    the row is left in ``state=failed``; the deployer hook treats the
    return value as informational, not authoritative.

    Returns the list of token rows created (whether their planting
    ultimately succeeded or not), so the caller can surface them in
    the deploy report.
    """
    out: list[dict[str, Any]] = []
    for gen_name in _baseline_set():
        try:
            generator = get_generator(gen_name)
        except ValueError:
            log.warning("canary.seed_baseline: unknown generator %r — skipping", gen_name)
            continue
        slug = token_urlsafe(16)
        ctx = _ctx_for(slug)
        artifact = generator.generate(ctx)
        artifact.path = default_path_for(gen_name, persona)
        kind = "aws_passive" if gen_name == "aws_creds" else "http"
        # Persist first so the planter has a row to update; that way a
        # crash mid-plant leaves a recoverable failed-state row.
        from uuid import uuid4
        token_uuid = str(uuid4())
        await repo.create_canary_token({
            "uuid": token_uuid,
            "kind": kind,
            "decky_name": decky_name,
            "blob_uuid": None,
            "instrumenter": None,
            "generator": gen_name,
            "placement_path": artifact.path,
            "callback_token": slug,
            "secret_seed": slug,
            "created_by": created_by,
            "state": "planted",  # optimistic — plant() flips to failed on error
        })
        await plant(
            decky_name, artifact,
            token_uuid=token_uuid, repo=repo, publish=True, bus=bus,
        )
        out.append({
            "token_uuid": token_uuid, "generator": gen_name, "kind": kind,
            "callback_token": slug, "placement_path": artifact.path,
        })
    return out
