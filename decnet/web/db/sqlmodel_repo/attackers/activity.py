# SPDX-License-Identifier: AGPL-3.0-or-later
"""Log-derived activity views: commands, service activity, IP leaks,
artifacts, stored mail, recorded sessions, transcripts.

These read from the ``logs`` and ``bounty`` tables joined against the
``Attacker`` row to scope by IP — no separate activity table.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy import desc, func, select
from sqlmodel import col

from decnet.web.db.models import Attacker, Bounty, Log


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class AttackerActivityMixin(_MixinBase):
    async def get_attacker_commands(
        self,
        uuid: str,
        limit: int = 50,
        offset: int = 0,
        service: Optional[str] = None,
    ) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.execute(
                select(col(Attacker.commands)).where(Attacker.uuid == uuid)
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

    async def list_attacker_commands_deduped(self, uuid: str) -> list[str]:
        async with self._session() as session:
            result = await session.execute(
                select(col(Attacker.commands)).where(Attacker.uuid == uuid)
            )
            raw = result.scalar_one_or_none()
            if raw is None:
                return []
            commands: list = json.loads(raw) if isinstance(raw, str) else raw
            seen: set[str] = set()
            out: list[str] = []
            for entry in commands:
                text = str(entry.get("command_text") or entry.get("command") or "").strip()
                if text and text not in seen:
                    seen.add(text)
                    out.append(text)
            return out

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
                select(col(Attacker.ip)).where(Attacker.uuid == attacker_uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return []
            rows = await session.execute(
                select(col(Log.service), col(Log.event_type))
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
                select(col(Attacker.ip)).where(Attacker.uuid == attacker_uuid)
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
                select(col(Attacker.ip)).where(Attacker.uuid == attacker_uuid)
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
                select(col(Attacker.ip)).where(Attacker.uuid == uuid)
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
                select(col(Attacker.ip)).where(Attacker.uuid == uuid)
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
                .where(col(Log.fields).contains(needle))
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
                select(col(Attacker.ip)).where(Attacker.uuid == uuid)
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
