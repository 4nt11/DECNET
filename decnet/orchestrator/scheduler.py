"""Action picker for the orchestrator.

Stage-3 realism: file actions are sourced from
:func:`decnet.realism.planner.pick`, not the old hardcoded
``_FILE_TEMPLATES``/``_USERS`` constants.  Persona resolution per
decky still belongs here (the realism planner is pure of
:class:`~decnet.web.db.repository.BaseRepository` knowledge) — we
walk each decky to either ``Topology.email_personas`` or the
``decnet.realism.personas_pool`` global pool, depending on
``decky["source"]``, then hand the resolved set to the planner.

TrafficAction stays untouched: still a flat random pair-pick of
SSH-capable deckies.  Email actions land in stage 5 of the realism
migration when the emailgen worker collapses into the orchestrator.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from decnet.realism import personas_pool
from decnet.realism.personas import EmailPersona, parse_personas
from decnet.realism.planner import pick as _realism_pick
from decnet.realism.taxonomy import ContentClass, Plan


@dataclass(frozen=True)
class TrafficAction:
    src_uuid: str
    src_name: str
    dst_uuid: str
    dst_name: str
    dst_ip: str
    protocol: str = "ssh"
    description: str = "tcp_connect:22"


@dataclass(frozen=True)
class FileAction:
    """One file plant request the SSH driver materialises.

    Stage-3 realism: ``persona`` / ``content_class`` / ``mtime`` are
    populated when the action came through :func:`pick_file`.  Older
    direct constructions (tests, manual operator drives) leave them
    at the defaults — back-compat for the pre-realism call sites
    that haven't migrated yet.
    """
    dst_uuid: str
    dst_name: str
    path: str
    content: str
    persona: str = ""
    content_class: str = ContentClass.NOTE.value
    mtime: Optional[datetime] = None
    description: str = "file:create"


Action = TrafficAction | FileAction


def _has_ssh(decky: dict[str, Any]) -> bool:
    services = decky.get("services") or []
    if isinstance(services, str):
        return False  # not deserialised — treat as "we don't know"
    return "ssh" in services


def pick(
    deckies: Sequence[dict[str, Any]],
    *,
    rand: Optional[secrets.SystemRandom] = None,
) -> Optional[Action]:
    """Pick one *traffic* action against the given decky set.

    Returns ``None`` when no SSH-capable pair is available.  File
    actions are produced by :func:`pick_file` (async — needs the repo
    for persona resolution).  The orchestrator worker calls one or the
    other per tick, weighted 50/50.
    """
    rng = rand or secrets.SystemRandom()
    ssh_deckies = [d for d in deckies if _has_ssh(d) and d.get("ip")]
    if len(ssh_deckies) < 2:
        return None
    src, dst = rng.sample(ssh_deckies, 2)
    return TrafficAction(
        src_uuid=src["uuid"],
        src_name=src["name"],
        dst_uuid=dst["uuid"],
        dst_name=dst["name"],
        dst_ip=dst["ip"],
    )


async def pick_file(
    deckies: Sequence[dict[str, Any]],
    repo: Any,
    *,
    now: Optional[datetime] = None,
    rand: Optional[secrets.SystemRandom] = None,
) -> Optional[FileAction]:
    """Realism-driven file action.

    Resolves personas per decky (topology pool when the decky has a
    parent topology; global pool otherwise), filters to deckies in any
    persona's work hours, asks :func:`decnet.realism.planner.pick` to
    pick the (decky, persona, content_class, path, body, mtime), and
    maps the resulting :class:`Plan` to a :class:`FileAction` the
    SSH driver can dispatch.

    Returns ``None`` when no decky has a non-empty persona pool with a
    persona currently in its active-hours window.
    """
    rng = rand or secrets.SystemRandom()
    when = now or datetime.now(timezone.utc)

    enriched = await _resolve_personas(deckies, repo)
    plan = _realism_pick(enriched, when, rand=rng)
    if plan is None:
        return None
    return FileAction(
        dst_uuid=plan.decky_uuid,
        dst_name=plan.decky_name,
        path=plan.target_path,
        content=plan.body_hint or "",
        persona=plan.persona,
        content_class=plan.content_class.value,
        mtime=plan.mtime,
    )


async def _resolve_personas(
    deckies: Sequence[dict[str, Any]],
    repo: Any,
) -> list[dict[str, Any]]:
    """Attach a resolved persona list to each decky dict.

    The realism planner expects each decky to carry
    ``_realism_personas`` (list of :class:`EmailPersona`).  We do the
    repo lookups here so the planner stays pure-of-DB.

    Topology-source deckies pull from ``Topology.email_personas``.
    Fleet/shard deckies pull from the global pool
    (:func:`decnet.realism.personas_pool.load`).  Decky source unknown
    → fall back to global pool too; better noisy than silent.
    """
    enriched: list[dict[str, Any]] = []
    topology_cache: dict[str, list[EmailPersona]] = {}
    global_personas: Optional[list[EmailPersona]] = None

    for decky in deckies:
        # Files are planted via the SSH service, same as TrafficAction.
        # A decky without ssh has no realism file path today (windows
        # personas / SMB writes land in a future stage).
        if not _has_ssh(decky):
            continue

        source = (decky.get("source") or "").lower()
        topology_id = decky.get("topology_id")

        personas: list[EmailPersona] = []
        if source == "topology" and topology_id:
            if topology_id not in topology_cache:
                try:
                    topology = await repo.get_topology(topology_id)
                except Exception:  # noqa: BLE001
                    topology = None
                topology_cache[topology_id] = _topology_personas(topology)
            personas = topology_cache[topology_id]
        else:
            if global_personas is None:
                # Lazy-load once per call; the global-pool cache inside
                # personas_pool already mtime-checks.
                global_personas = personas_pool.load()
            personas = global_personas

        if not personas:
            continue
        enriched.append({**decky, "_realism_personas": personas})

    return enriched


def _topology_personas(topology: Optional[dict[str, Any]]) -> list[EmailPersona]:
    if not topology:
        return []
    raw = topology.get("email_personas")
    if raw is None:
        return []
    if isinstance(raw, list):
        return parse_personas(raw, language_default=topology.get("language_default") or "en")
    if isinstance(raw, str):
        try:
            return parse_personas(json.loads(raw), language_default=topology.get("language_default") or "en")
        except json.JSONDecodeError:
            return []
    return []


# Lightweight no-op alias kept so external callers that already import
# ``Plan`` from the scheduler keep working through the migration.
__all__ = [
    "Action",
    "FileAction",
    "Plan",
    "TrafficAction",
    "pick",
    "pick_file",
]
