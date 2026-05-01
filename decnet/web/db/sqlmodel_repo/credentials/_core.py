"""Credential capture: per-attempt rows in the ``Credential`` table."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import desc, func, or_, select, update
from sqlmodel import col
from sqlmodel.sql.expression import SelectOfScalar

from decnet.web.db.models import Credential


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class CredentialsCoreMixin(_MixinBase):
    async def upsert_credential(self, data: dict[str, Any]) -> int:
        """Upsert a credential attempt; returns the row id.

        Dedup tuple: (attacker_ip, decky_name, service, secret_sha256,
        principal_or_None). On match, ``attempt_count`` += 1 and
        ``last_seen`` advances; ``first_seen`` and ``fields`` are
        preserved from the original sighting.
        """
        payload = dict(data)
        if "fields" in payload and isinstance(payload["fields"], dict):
            # ensure_ascii=True keeps utf8mb4 columns safe even when
            # service-specific keys carry non-ASCII bytes.
            payload["fields"] = json.dumps(payload["fields"], ensure_ascii=True)

        principal = payload.get("principal")
        secret_kind = payload.get("secret_kind") or "plaintext"
        async with self._session() as session:
            stmt = select(Credential).where(
                Credential.attacker_ip == payload["attacker_ip"],
                Credential.decky_name == payload["decky_name"],
                Credential.service == payload["service"],
                Credential.secret_kind == secret_kind,
                Credential.secret_sha256 == payload["secret_sha256"],
                # NULL == NULL is False under SQL — branch the predicate.
                (Credential.principal == principal) if principal is not None
                else col(Credential.principal).is_(None),
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if existing is not None:
                existing.attempt_count = (existing.attempt_count or 1) + 1
                existing.last_seen = now
                if payload.get("outcome") is not None:
                    existing.outcome = payload["outcome"]
                session.add(existing)
                await session.commit()
                return existing.id
            row = Credential(
                attacker_ip=payload["attacker_ip"],
                decky_name=payload["decky_name"],
                service=payload["service"],
                principal=principal,
                secret_kind=secret_kind,
                secret_sha256=payload["secret_sha256"],
                secret_b64=payload.get("secret_b64"),
                secret_printable=payload.get("secret_printable"),
                outcome=payload.get("outcome"),
                fields=payload.get("fields", "{}"),
                first_seen=now,
                last_seen=now,
                attempt_count=1,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id  # type: ignore[return-value]

    def _apply_credential_filters(
        self,
        statement: SelectOfScalar,
        search: Optional[str],
        service: Optional[str],
        attacker_ip: Optional[str],
    ) -> SelectOfScalar:
        if service:
            statement = statement.where(Credential.service == service)
        if attacker_ip:
            statement = statement.where(Credential.attacker_ip == attacker_ip)
        if search:
            lk = f"%{search}%"
            statement = statement.where(
                or_(
                    col(Credential.decky_name).like(lk),
                    col(Credential.service).like(lk),
                    col(Credential.principal).like(lk),
                    col(Credential.secret_printable).like(lk),
                )
            )
        return statement

    async def get_credentials(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        service: Optional[str] = None,
        attacker_ip: Optional[str] = None,
    ) -> List[dict[str, Any]]:
        statement = (
            select(Credential)
            .order_by(desc(Credential.last_seen))
            .offset(offset)
            .limit(limit)
        )
        statement = self._apply_credential_filters(
            statement, search, service, attacker_ip
        )
        async with self._session() as session:
            result = await session.execute(statement)
            out: List[dict[str, Any]] = []
            for item in result.scalars().all():
                d = item.model_dump(mode="json")
                try:
                    d["fields"] = json.loads(d["fields"])
                except (json.JSONDecodeError, TypeError):
                    pass
                out.append(d)
            return out

    async def get_total_credentials(
        self,
        search: Optional[str] = None,
        service: Optional[str] = None,
        attacker_ip: Optional[str] = None,
    ) -> int:
        statement = select(func.count()).select_from(Credential)
        statement = self._apply_credential_filters(
            statement, search, service, attacker_ip
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def get_credentials_for_attacker(
        self, attacker_ip: str
    ) -> List[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(Credential)
                .where(Credential.attacker_ip == attacker_ip)
                .order_by(desc(Credential.last_seen))
            )
            out: List[dict[str, Any]] = []
            for item in result.scalars().all():
                d = item.model_dump(mode="json")
                try:
                    d["fields"] = json.loads(d["fields"])
                except (json.JSONDecodeError, TypeError):
                    pass
                out.append(d)
            return out

    async def get_credential_attempts_for_secret(
        self, secret_sha256: str
    ) -> List[dict[str, Any]]:
        """Every (attacker_ip, decky, service, principal) row sharing this
        secret hash. Indexed lookup via ix_credentials_secret_service.
        """
        async with self._session() as session:
            result = await session.execute(
                select(Credential)
                .where(Credential.secret_sha256 == secret_sha256)
                .order_by(desc(Credential.last_seen))
            )
            out: List[dict[str, Any]] = []
            for item in result.scalars().all():
                d = item.model_dump(mode="json")
                try:
                    d["fields"] = json.loads(d["fields"])
                except (json.JSONDecodeError, TypeError):
                    pass
                out.append(d)
            return out

    async def update_credential_attacker_uuid(
        self, attacker_ip: str, attacker_uuid: str
    ) -> int:
        """Backfill ``attacker_uuid`` on every Credential row matching the
        given IP whose ``attacker_uuid`` is currently null. Run by the
        profiler after it mints/updates an Attacker row.
        """
        async with self._session() as session:
            result = await session.execute(
                update(Credential)
                .where(
                    Credential.attacker_ip == attacker_ip,
                    col(Credential.attacker_uuid).is_(None),
                )
                .values(attacker_uuid=attacker_uuid)
            )
            await session.commit()
            return int(result.rowcount or 0)
