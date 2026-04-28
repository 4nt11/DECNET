"""Attacker domain: core CRUD, behavior, sessions, smtp targets, and
log-derived activity views (commands, leaks, artifacts, transcripts).

Identity-resolution and campaign-clustering reads live in their own
modules (``identities.py`` / ``campaigns.py``) — they're conceptually
about grouping attackers, not the attackers themselves.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import desc, func, select

from decnet.web.db.models import (
    Attacker,
    AttackerBehavior,
    Bounty,
    Log,
    SessionProfile,
    SmtpTarget,
)


class AttackersMixin:
    """Mixin: composed onto ``SQLModelRepository``."""

    # ─── core attacker rows ────────────────────────────────────────────────

    async def upsert_attacker(self, data: dict[str, Any]) -> str:
        async with self._session() as session:
            result = await session.execute(
                select(Attacker).where(Attacker.ip == data["ip"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                session.add(existing)
                row_uuid = existing.uuid
            else:
                row_uuid = str(_uuid.uuid4())
                data = {**data, "uuid": row_uuid}
                session.add(Attacker(**data))
            await session.commit()
            return row_uuid

    @staticmethod
    def _deserialize_attacker(d: dict[str, Any]) -> dict[str, Any]:
        for key in ("services", "deckies", "fingerprints", "commands"):
            if isinstance(d.get(key), str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    async def get_attacker_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(Attacker).where(Attacker.uuid == uuid)
            )
            attacker = result.scalar_one_or_none()
            if not attacker:
                return None
            return self._deserialize_attacker(attacker.model_dump(mode="json"))

    async def get_attackers(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        sort_by: str = "recent",
        service: Optional[str] = None,
    ) -> List[dict[str, Any]]:
        order = {
            "active": desc(Attacker.event_count),
            "traversals": desc(Attacker.is_traversal),
        }.get(sort_by, desc(Attacker.last_seen))

        statement = select(Attacker).order_by(order).offset(offset).limit(limit)
        if search:
            statement = statement.where(Attacker.ip.like(f"%{search}%"))
        if service:
            statement = statement.where(Attacker.services.like(f'%"{service}"%'))

        async with self._session() as session:
            result = await session.execute(statement)
            return [
                self._deserialize_attacker(a.model_dump(mode="json"))
                for a in result.scalars().all()
            ]

    async def get_total_attackers(
        self, search: Optional[str] = None, service: Optional[str] = None
    ) -> int:
        statement = select(func.count()).select_from(Attacker)
        if search:
            statement = statement.where(Attacker.ip.like(f"%{search}%"))
        if service:
            statement = statement.where(Attacker.services.like(f'%"{service}"%'))

        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    # ─── attacker behavior (TCP fingerprint, timing, etc.) ────────────────

    async def upsert_attacker_behavior(
        self,
        attacker_uuid: str,
        data: dict[str, Any],
    ) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(AttackerBehavior).where(
                    AttackerBehavior.attacker_uuid == attacker_uuid
                )
            )
            existing = result.scalar_one_or_none()
            payload = {**data, "updated_at": datetime.now(timezone.utc)}
            if existing:
                for k, v in payload.items():
                    setattr(existing, k, v)
                session.add(existing)
            else:
                session.add(AttackerBehavior(attacker_uuid=attacker_uuid, **payload))
            await session.commit()

    async def get_attacker_behavior(
        self,
        attacker_uuid: str,
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(AttackerBehavior).where(
                    AttackerBehavior.attacker_uuid == attacker_uuid
                )
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            return self._deserialize_behavior(row.model_dump(mode="json"))

    async def get_behaviors_for_ips(
        self,
        ips: set[str],
    ) -> dict[str, dict[str, Any]]:
        if not ips:
            return {}
        async with self._session() as session:
            result = await session.execute(
                select(Attacker.ip, AttackerBehavior)
                .join(AttackerBehavior, Attacker.uuid == AttackerBehavior.attacker_uuid)
                .where(Attacker.ip.in_(ips))
            )
            out: dict[str, dict[str, Any]] = {}
            for ip, row in result.all():
                out[ip] = self._deserialize_behavior(row.model_dump(mode="json"))
            return out

    @staticmethod
    def _deserialize_behavior(d: dict[str, Any]) -> dict[str, Any]:
        for key in ("tcp_fingerprint", "timing_stats", "phase_sequence"):
            if isinstance(d.get(key), str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Deserialize tool_guesses JSON array; normalise None → [].
        raw = d.get("tool_guesses")
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                d["tool_guesses"] = parsed if isinstance(parsed, list) else [parsed]
            except (json.JSONDecodeError, TypeError):
                d["tool_guesses"] = []
        elif raw is None:
            d["tool_guesses"] = []
        # Same list-or-None pattern for kex_order_raw.
        raw_kex = d.get("kex_order_raw")
        if isinstance(raw_kex, str):
            try:
                parsed_kex = json.loads(raw_kex)
                d["kex_order_raw"] = parsed_kex if isinstance(parsed_kex, list) else [parsed_kex]
            except (json.JSONDecodeError, TypeError):
                d["kex_order_raw"] = []
        elif raw_kex is None:
            d["kex_order_raw"] = []
        # Same list-or-None pattern for ssh_client_banners.
        raw_banners = d.get("ssh_client_banners")
        if isinstance(raw_banners, str):
            try:
                parsed_banners = json.loads(raw_banners)
                d["ssh_client_banners"] = parsed_banners if isinstance(parsed_banners, list) else [parsed_banners]
            except (json.JSONDecodeError, TypeError):
                d["ssh_client_banners"] = []
        elif raw_banners is None:
            d["ssh_client_banners"] = []
        return d

    # ─── session profiles ────────────────────────────────────────────────

    async def upsert_session_profile(
        self,
        sid: str,
        data: dict[str, Any],
    ) -> None:
        """
        Write (or update) the session_profile row for *sid*.

        Pre-v1, the typical call is the empty-write path at session close:
        `upsert_session_profile(sid, {"log_id": <id>})` — all keystroke
        feature columns stay NULL until the V2 ingestion job populates them.
        """
        async with self._session() as session:
            result = await session.execute(
                select(SessionProfile).where(SessionProfile.sid == sid)
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                session.add(existing)
            else:
                session.add(SessionProfile(sid=sid, **data))
            await session.commit()

    async def get_session_profile(
        self,
        sid: str,
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(SessionProfile).where(SessionProfile.sid == sid)
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            return row.model_dump(mode="json")

    # ─── smtp targets ─────────────────────────────────────────────────────

    async def increment_smtp_target(self, attacker_uuid: str, domain: str) -> None:
        """Upsert an (attacker_uuid, domain) pair and bump count + last_seen.

        Read-then-write under a single session — the UNIQUE constraint on
        (attacker_uuid, domain) guards against duplicate rows if the race
        ever materialises; we accept the ~1ms extra round-trip in exchange
        for a single dialect-portable implementation.
        """
        async with self._session() as session:
            result = await session.execute(
                select(SmtpTarget)
                .where(SmtpTarget.attacker_uuid == attacker_uuid)
                .where(SmtpTarget.domain == domain)
            )
            existing = result.scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if existing:
                existing.count += 1
                existing.last_seen = now
                session.add(existing)
            else:
                session.add(SmtpTarget(
                    attacker_uuid=attacker_uuid,
                    domain=domain,
                    first_seen=now,
                    last_seen=now,
                    count=1,
                ))
            await session.commit()

    async def list_smtp_targets(self, attacker_uuid: str) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(SmtpTarget)
                .where(SmtpTarget.attacker_uuid == attacker_uuid)
                .order_by(desc(SmtpTarget.last_seen))
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def smtp_target_seen(self, domain: str) -> dict[str, Any]:
        """Aggregate rows for this domain across every attacker in the DB."""
        async with self._session() as session:
            result = await session.execute(
                select(
                    func.coalesce(func.sum(SmtpTarget.count), 0),
                    func.min(SmtpTarget.first_seen),
                    func.max(SmtpTarget.last_seen),
                ).where(SmtpTarget.domain == domain)
            )
            total, first_seen, last_seen = result.one()
            return {
                "seen": int(total) > 0,
                "count": int(total),
                "first_seen": first_seen,
                "last_seen": last_seen,
            }

    # ─── log-derived activity views ───────────────────────────────────────

    async def get_attacker_commands(
        self,
        uuid: str,
        limit: int = 50,
        offset: int = 0,
        service: Optional[str] = None,
    ) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.execute(
                select(Attacker.commands).where(Attacker.uuid == uuid)
            )
            raw = result.scalar_one_or_none()
            if raw is None:
                return {"total": 0, "data": []}

            commands: list = json.loads(raw) if isinstance(raw, str) else raw
            if service:
                commands = [c for c in commands if c.get("service") == service]

            total = len(commands)
            page = commands[offset: offset + limit]
            return {"total": total, "data": page}

    async def get_attacker_service_activity(
        self, attacker_uuid: str
    ) -> list[tuple[str, str]]:
        """Return distinct ``(service, event_type)`` pairs for an attacker.

        Resolves IP then ``SELECT DISTINCT service, event_type FROM logs
        WHERE attacker_ip = :ip`` — the result set is bounded by the
        cardinality of services × event_types (tens, not thousands), so
        this stays cheap even for attackers with long event streams.
        Caller applies `event_kinds.bucket_services` to split into
        scanned vs. interacted.
        """
        async with self._session() as session:
            ip_res = await session.execute(
                select(Attacker.ip).where(Attacker.uuid == attacker_uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return []
            rows = await session.execute(
                select(Log.service, Log.event_type)
                .where(Log.attacker_ip == ip)
                .distinct()
            )
            return [(svc, evt) for svc, evt in rows.all()]

    async def get_attacker_ip_leaks(
        self, attacker_uuid: str, *, limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return ``bounty_type='ip_leak'`` rows for this attacker, newest
        first, capped at ``limit``. Shape matches the XFF-mismatch
        payload emitted by the ingester: keys include ``real_ip_claim``,
        ``source_header``, ``headers_seen``. Use
        :meth:`count_attacker_ip_leaks` to get the unbounded total for
        rotation detection."""
        async with self._session() as session:
            ip_res = await session.execute(
                select(Attacker.ip).where(Attacker.uuid == attacker_uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return []
            rows = await session.execute(
                select(Bounty)
                .where(Bounty.attacker_ip == ip)
                .where(Bounty.bounty_type == "ip_leak")
                .order_by(desc(Bounty.timestamp))
                .limit(limit)
            )
            out: list[dict[str, Any]] = []
            for row in rows.scalars().all():
                rec = row.model_dump(mode="json")
                # Bounty.payload is stored JSON-encoded; pre-decode for UX.
                raw = rec.get("payload")
                if isinstance(raw, str):
                    try:
                        rec["payload"] = json.loads(raw)
                    except (ValueError, TypeError):
                        rec["payload"] = {}
                out.append(rec)
            return out

    async def count_attacker_ip_leaks(self, attacker_uuid: str) -> int:
        """Cheap COUNT(*) for XFF-rotation detection."""
        async with self._session() as session:
            ip_res = await session.execute(
                select(Attacker.ip).where(Attacker.uuid == attacker_uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return 0
            count_res = await session.execute(
                select(func.count(Bounty.id))
                .where(Bounty.attacker_ip == ip)
                .where(Bounty.bounty_type == "ip_leak")
            )
            return int(count_res.scalar() or 0)

    async def get_attacker_artifacts(self, uuid: str) -> list[dict[str, Any]]:
        """Return `file_captured` logs for the attacker identified by UUID.

        Resolves the attacker's IP first, then queries the logs table on two
        indexed columns (``attacker_ip`` and ``event_type``). No JSON extract
        needed — the decky/stored_as are already decoded into ``fields`` by
        the ingester and returned to the frontend for drawer rendering.
        """
        async with self._session() as session:
            ip_res = await session.execute(
                select(Attacker.ip).where(Attacker.uuid == uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return []
            rows = await session.execute(
                select(Log)
                .where(Log.attacker_ip == ip)
                .where(Log.event_type == "file_captured")
                .order_by(desc(Log.timestamp))
                .limit(200)
            )
            return [r.model_dump(mode="json") for r in rows.scalars().all()]

    async def get_attacker_stored_mail(self, uuid: str) -> list[dict[str, Any]]:
        """Return `message_stored` logs for an attacker, newest first.

        Mirrors :meth:`get_attacker_artifacts` — the SMTP template emits one
        `message_stored` row per accepted DATA body, with headers + sha256 +
        attachment manifest already decoded into ``fields`` by the ingester.
        Capped at 200 rows to match the artifact/transcript query shape.
        """
        async with self._session() as session:
            ip_res = await session.execute(
                select(Attacker.ip).where(Attacker.uuid == uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return []
            rows = await session.execute(
                select(Log)
                .where(Log.attacker_ip == ip)
                .where(Log.event_type == "message_stored")
                .order_by(desc(Log.timestamp))
                .limit(200)
            )
            return [r.model_dump(mode="json") for r in rows.scalars().all()]

    async def get_session_log(self, sid: str) -> Optional[dict[str, Any]]:
        """Look up the `session_recorded` Log row that owns a given sid.

        sid is a v4 UUID embedded in the row's ``fields`` JSON blob. Matched
        with LIKE on the textual sid substring — cheap given the bounded
        cardinality of session_recorded rows vs. the full logs table.
        """
        needle = f'"sid":"{sid}"'
        async with self._session() as session:
            rows = await session.execute(
                select(Log)
                .where(Log.event_type == "session_recorded")
                .where(Log.fields.contains(needle))
                .limit(1)
            )
            row = rows.scalars().first()
            return row.model_dump(mode="json") if row else None

    async def get_attacker_transcripts(self, uuid: str) -> list[dict[str, Any]]:
        """Return `session_recorded` logs for the attacker identified by UUID.

        Mirror of :meth:`get_attacker_artifacts` — sessions ride in the same
        Log table with event_type=session_recorded; the ingester decodes the
        RFC 5424 SD fields (sid, service, decky, src_ip, duration_s, bytes,
        truncated, shard_path) into the returned ``fields`` blob.
        """
        async with self._session() as session:
            ip_res = await session.execute(
                select(Attacker.ip).where(Attacker.uuid == uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return []
            rows = await session.execute(
                select(Log)
                .where(Log.attacker_ip == ip)
                .where(Log.event_type == "session_recorded")
                .order_by(desc(Log.timestamp))
                .limit(200)
            )
            return [r.model_dump(mode="json") for r in rows.scalars().all()]
