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
    # Canary artifacts (DOCX/PDF/honeydoc binaries) carry their bytes
    # here so re-encoding ``content`` from utf-8 doesn't mangle them.
    # When set, the SSH driver uses these bytes directly and ignores
    # ``content``.
    content_bytes: Optional[bytes] = None


@dataclass(frozen=True)
class EditAction:
    """Read-modify-write of an existing synthetic file.

    Stage 3b of the realism migration: a previously-planted ``TODO.md``
    gets a checkbox flipped, a notes file gets a new line appended, a
    cron log gets a fresh entry tacked on.  ``synthetic_file_uuid`` is
    the row in ``synthetic_files`` to update; ``previous_body`` is
    what the planner already saw so the driver doesn't double-fetch.
    """
    dst_uuid: str
    dst_name: str
    path: str
    persona: str
    content_class: str
    previous_body: str
    synthetic_file_uuid: str
    mtime: Optional[datetime] = None
    description: str = "file:edit"


Action = TrafficAction | FileAction | EditAction


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
    llm: Any = None,
    llm_breaker: Any = None,
    llm_timeout: float = 60.0,
) -> Optional[Action]:
    """Realism-driven file action — create or edit.

    Resolves personas per decky (topology pool when the decky has a
    parent topology; global pool otherwise), filters to deckies in any
    persona's work hours, optionally fetches an edit candidate from
    the synthetic_files table, and asks
    :func:`decnet.realism.planner.pick` to choose between create / edit
    / leave-alone.  Maps the resulting :class:`Plan` to a
    :class:`FileAction` (create) or :class:`EditAction` (edit) the
    SSH driver can dispatch.

    Returns ``None`` when no decky has a non-empty persona pool with a
    persona currently in its active-hours window, or when the planner
    rolled "leave alone."
    """
    rng = rand or secrets.SystemRandom()
    when = now or datetime.now(timezone.utc)

    enriched = await _resolve_personas(deckies, repo)
    if not enriched:
        return None

    # Pre-fetch a single edit candidate from a random eligible decky,
    # so the planner can decide whether to use it.  We pick the decky
    # client-side (cheap) and ask the repo for one row; if there's
    # nothing editable, planner falls back to create.
    edit_candidate = None
    if rng.random() < 0.5 and enriched:
        # Half the ticks consider an edit. Lower than the planner's
        # 30% edit weight on purpose — the repo lookup is the
        # expensive part, no point doing it on every tick.
        candidate_decky = rng.choice(enriched)
        try:
            row = await repo.pick_random_synthetic_file_for_edit(
                candidate_decky["uuid"],
            )
        except Exception:  # noqa: BLE001
            row = None
        if row is not None:
            row = {**row, "decky_name": candidate_decky["name"]}
            edit_candidate = row

    plan = _realism_pick(enriched, when, edit_candidate=edit_candidate, rand=rng)
    if plan is None:
        return None

    if plan.action == "edit":
        return EditAction(
            dst_uuid=plan.decky_uuid,
            dst_name=plan.decky_name,
            path=plan.target_path,
            persona=plan.persona,
            content_class=plan.content_class.value,
            previous_body=plan.previous_body or "",
            synthetic_file_uuid=(edit_candidate or {}).get("uuid", ""),
            mtime=plan.mtime,
        )

    # Canary branch — the cultivator builds the bytes, picks the
    # placement path, and persists the canary_tokens row.  We map
    # the resulting CanaryArtifact to a FileAction so the SSH
    # driver's plant_file path is reused unchanged.
    if plan.content_class.is_canary():
        try:
            from decnet.canary import cultivator as _cultivator
            artifact = await _cultivator.cultivate(plan, repo)
        except Exception:  # noqa: BLE001
            # Cultivation failed (no http_base/dns_zone configured,
            # generator raised, repo write failed).  Fall through to
            # an inert file plant so the tick isn't wasted.
            return FileAction(
                dst_uuid=plan.decky_uuid,
                dst_name=plan.decky_name,
                path=plan.target_path or f"/tmp/.cache-{secrets.token_hex(3)}",  # nosec B108
                content=plan.body_hint or "",
                persona=plan.persona,
                content_class=plan.content_class.value,
                mtime=plan.mtime,
            )
        return FileAction(
            dst_uuid=plan.decky_uuid,
            dst_name=plan.decky_name,
            path=artifact.path,
            content="",  # ignored when content_bytes is set
            content_bytes=artifact.content,
            persona=plan.persona,
            content_class=plan.content_class.value,
            mtime=plan.mtime,
        )

    # Create branch.  If LLM is wired, optionally swap body_hint for
    # an LLM-authored body.  Always keep the deterministic body_hint
    # as the fallback the function call returns when LLM
    # times out / errors / breaker-trips.
    body = plan.body_hint or ""
    if llm is not None and plan.content_class.is_user_class():
        persona_obj = _persona_by_name(enriched, plan.persona)
        if persona_obj is not None:
            from decnet.realism.bodies import make_body_with_llm
            body = await make_body_with_llm(
                plan.content_class,
                persona_obj,
                llm=llm,
                breaker=llm_breaker,
                timeout=llm_timeout,
                rand=rng,
            )
    return FileAction(
        dst_uuid=plan.decky_uuid,
        dst_name=plan.decky_name,
        path=plan.target_path,
        content=body,
        persona=plan.persona,
        content_class=plan.content_class.value,
        mtime=plan.mtime,
    )


def _persona_by_name(
    enriched: list[dict[str, Any]], name: str,
) -> Optional[EmailPersona]:
    """Find the persona instance the planner used; ``None`` if missing."""
    for decky in enriched:
        for persona in decky.get("_realism_personas") or []:
            if persona.name == name:
                return persona
    return None


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
    "EditAction",
    "FileAction",
    "Plan",
    "TrafficAction",
    "pick",
    "pick_file",
]
