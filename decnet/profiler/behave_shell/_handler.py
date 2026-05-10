"""``attacker.session.ended`` handler — Phase 4 wiring.

Pure handler module: takes a payload (from bus or poll fallback),
disk-reaches the asciinema shard, runs ``extract_session()``,
upserts observations, and publishes them on the bus best-effort.
Lives outside ``worker.py`` so unit tests can exercise it without
spinning up the asyncio worker loop.

Trigger isolation: every public entry point is wrapped in a single
try/except in the worker; this module is allowed to raise. The worker
logs and continues with the next event.
"""
from __future__ import annotations

import collections
import json
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from behave_core.spec.envelope import Observation
from behave_shell.spec.event_adapter import event_topic_for, to_event_payload

from decnet.logging import get_logger
from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent, parse_shard_line
from decnet.web.db.repository import BaseRepository

log = get_logger("profiler.behave_handler")

PublishFn = Callable[[str, dict[str, Any], str], None]
"""Bus-publish callable (sync). The thread-safe publisher returned by
``decnet.bus.publish.make_thread_safe_publisher`` matches this shape;
``None`` is also accepted (no-op publish path)."""

_REQUIRED_FIELDS: tuple[str, ...] = (
    "session_id", "decky_id", "service", "attacker_ip",
)


def _build_evidence_ref(decky: str, service: str, shard_path: str, sid: str) -> str:
    """Canonical ``shard:{decky}/{service}/{shard_basename}#{sid}`` pointer.

    Stays a *pointer*, never the evidence itself. Worker uses it as
    the idempotency key against the ``observations`` table.
    """
    basename = Path(shard_path).name
    return f"shard:{decky}/{service}/{basename}#{sid}"


def _events_for_sid(shard: Path, sid: str) -> list[AsciinemaEvent]:
    """Read ``shard``, return parsed events whose ``sid`` matches.

    Mirrors the loader pattern in
    ``tests/profiler/behave_shell/test_calibration_grid.py``: skip
    headers / non-matching sids / unparseable lines silently.

    ``errors="surrogateescape"`` because sessrec.c's json_escape only
    escapes bytes < 0x20 + DEL — bytes >= 0x80 pass through raw, so
    a real shard with Latin-1 / GB18030 / arbitrary 8-bit attacker
    paste content is NOT valid UTF-8. surrogateescape preserves byte
    fidelity through the JSON read; downstream isalpha() / isascii()
    correctly filter the surrogate-half chars out of the typed-letter
    histograms. Filed for v0.2: tighten sessrec.c to escape >= 0x80.
    """
    events: list[AsciinemaEvent] = []
    with shard.open(encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("sid") != sid or "hdr" in rec:
                continue
            ev = parse_shard_line(line)
            if ev is not None:
                events.append(ev)
    return events


def _flatten_observation(obs: Observation, attacker_uuid: str) -> dict[str, Any]:
    """Project a BEHAVE Observation onto the ObservationRow column shape.

    Mirrors the storage schema in
    ``decnet/web/db/models/observations.py`` — flattens
    ``window.{start,end}_ts`` and stamps the DECNET-side
    ``attacker_uuid`` denorm. ``id`` / ``ts`` / ``v`` / ``identity_ref``
    / ``evidence_ref`` ride through unchanged.
    """
    return {
        "id": obs.id,
        "identity_ref": obs.identity_ref,
        "primitive": obs.primitive,
        "value": obs.value,
        "confidence": obs.confidence,
        "window_start_ts": obs.window.start_ts,
        "window_end_ts": obs.window.end_ts,
        "source": obs.source,
        "evidence_ref": obs.evidence_ref,
        "envelope_v": obs.v,
        "ts": obs.ts,
        "attacker_uuid": attacker_uuid,
    }


def _publish_observation(
    publish: Optional[PublishFn],
    obs: Observation,
    attacker_uuid: str,
) -> None:
    """Best-effort publish; never raise. Re-merges id/ts/v plus
    DECNET-side ``attacker_uuid`` denorm into payload per
    BEHAVE-INTEGRATION.md §339-366 deviation note. The ``attacker_uuid``
    stamp gives the per-attacker SSE route an O(1) filter without a
    repo round-trip per event (Phase 5)."""
    if publish is None:
        return
    payload = to_event_payload(obs) | {
        "id": obs.id,
        "ts": obs.ts,
        "v": obs.v,
        "attacker_uuid": attacker_uuid,
    }
    try:
        publish(event_topic_for(obs.primitive), payload, obs.primitive)
    except Exception as exc:  # noqa: BLE001
        log.debug(
            "behave_handler: publish failed for primitive=%s: %s",
            obs.primitive, exc,
        )


async def handle_session_ended(
    repo: BaseRepository,
    payload: dict[str, Any],
    publish: Optional[PublishFn] = None,
) -> int:
    """Process one ``attacker.session.ended`` event end-to-end.

    Returns the number of observations persisted (zero on any skip
    path: missing fields, missing shard, idempotency hit, attacker
    not yet resolved, sid not in shard, extractor produced nothing).

    Order: persist first, publish best-effort. DB is the source of
    truth (see BEHAVE-INTEGRATION.md §"Persistence").
    """
    # 1. Required-field guard.
    missing = [k for k in _REQUIRED_FIELDS if not payload.get(k)]
    if missing:
        log.debug(
            "behave_handler: skipping session.ended (missing fields=%s)",
            missing,
        )
        return 0
    shard_path = payload.get("shard_path")
    if not shard_path:
        log.debug("behave_handler: skipping session.ended (no shard_path)")
        return 0

    sid = str(payload["session_id"])
    decky = str(payload["decky_id"])
    service = str(payload["service"])
    attacker_ip = str(payload["attacker_ip"])

    # 2. evidence_ref + idempotency.
    evidence_ref = _build_evidence_ref(decky, service, str(shard_path), sid)
    if await repo.has_observations_for_evidence(evidence_ref):
        log.debug(
            "behave_handler: already profiled evidence_ref=%s", evidence_ref,
        )
        return 0

    # 3. Resolve attacker_uuid. Skip until profiler tick has materialised
    # the Attacker row — same posture as TTP's _resolve_attacker_uuid.
    attacker_uuid = await repo.get_attacker_uuid_by_ip(attacker_ip)
    if not attacker_uuid:
        log.info(
            "behave_handler: no Attacker row for ip=%s yet; deferring",
            attacker_ip,
        )
        return 0

    # 4. Load shard, slice events.
    shard = Path(shard_path)
    if not shard.is_file():
        log.info(
            "behave_handler: shard not on disk yet path=%s sid=%s; deferring",
            shard_path, sid,
        )
        return 0
    events = _events_for_sid(shard, sid)
    if not events:
        log.info(
            "behave_handler: sid=%s not present in shard=%s; skipping",
            sid, shard_path,
        )
        return 0

    # 5. Extract.
    observations: list[Observation] = []
    for obs in extract_session(events, sid=sid, evidence_ref=evidence_ref):
        observations.append(obs)
    if not observations:
        log.info(
            "behave_handler: extractor produced zero observations sid=%s",
            sid,
        )
        return 0

    # 6. Persist. Per-row upsert via the existing repo method; the
    # idempotency unique index makes accidental duplicates impossible.
    # Any per-row failure aborts publishing — DB is source of truth.
    persisted = 0
    for obs in observations:
        await repo.upsert_observation(_flatten_observation(obs, attacker_uuid))
        persisted += 1

    # 7. Publish — fire-and-forget, never raises out.
    for obs in observations:
        _publish_observation(publish, obs, attacker_uuid)

    log.info(
        "behave_handler: persisted=%d primitives sid=%s attacker_ip=%s",
        persisted, sid, attacker_ip,
    )
    return persisted


def primitive_counts(observations: Iterable[Observation]) -> dict[str, int]:
    """Small debug helper: count emissions by primitive name."""
    counter: collections.Counter[str] = collections.Counter()
    for obs in observations:
        counter[obs.primitive] += 1
    return dict(counter)
