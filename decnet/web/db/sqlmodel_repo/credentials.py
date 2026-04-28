"""Credential capture + credential-reuse correlation."""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import desc, func, or_, select, update
from sqlmodel.sql.expression import SelectOfScalar

from decnet.web.db.models import Credential, CredentialReuse


class CredentialsMixin:
    """Mixin: composed onto ``SQLModelRepository``."""

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
                else Credential.principal.is_(None),
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
                return existing.id  # type: ignore[return-value]
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
                    Credential.decky_name.like(lk),
                    Credential.service.like(lk),
                    Credential.principal.like(lk),
                    Credential.secret_printable.like(lk),
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
                    Credential.attacker_uuid.is_(None),
                )
                .values(attacker_uuid=attacker_uuid)
            )
            await session.commit()
            return int(result.rowcount or 0)

    @staticmethod
    def _merge_unique(existing_json: str, value: Optional[str]) -> tuple[str, bool]:
        """Append ``value`` to a JSON list[str] column if not present.
        Returns (new_json, changed). None values and duplicates are skipped.
        """
        if value is None:
            return existing_json, False
        try:
            current = json.loads(existing_json) if existing_json else []
            if not isinstance(current, list):
                current = []
        except (json.JSONDecodeError, TypeError):
            current = []
        if value in current:
            return existing_json, False
        current.append(value)
        return json.dumps(current, ensure_ascii=True), True

    async def upsert_credential_reuse(
        self,
        *,
        secret_sha256: str,
        secret_kind: str,
        principal: Optional[str],
        attacker_uuid: Optional[str],
        attacker_ip: str,
        decky: str,
        service: str,
        attempt_count: int,
        ts: Optional[datetime] = None,
    ) -> Optional[dict[str, Any]]:
        """Upsert a credential-reuse finding.

        The row is keyed by ``(secret_sha256, secret_kind, principal_key)``
        — ``principal_key`` is the canonicalised non-null form ("" when
        principal is null) so the unique constraint behaves the same on
        SQLite and MySQL.

        Returns the row dict augmented with ``inserted: bool`` and
        ``changed: bool`` so the correlator can decide whether to publish
        a bus event.
        """
        principal_key = principal or ""
        now = ts or datetime.now(timezone.utc)
        async with self._session() as session:
            existing = (await session.execute(
                select(CredentialReuse).where(
                    CredentialReuse.secret_sha256 == secret_sha256,
                    CredentialReuse.secret_kind == secret_kind,
                    CredentialReuse.principal_key == principal_key,
                )
            )).scalar_one_or_none()

            if existing is None:
                row = CredentialReuse(
                    id=str(_uuid.uuid4()),
                    secret_sha256=secret_sha256,
                    secret_kind=secret_kind,
                    principal=principal,
                    principal_key=principal_key,
                    attacker_uuids=json.dumps(
                        [attacker_uuid] if attacker_uuid else [], ensure_ascii=True
                    ),
                    attacker_ips=json.dumps([attacker_ip], ensure_ascii=True),
                    deckies=json.dumps([decky], ensure_ascii=True),
                    services=json.dumps([service], ensure_ascii=True),
                    target_count=1,
                    attempt_count=int(attempt_count),
                    confidence=1.0,
                    first_seen=now,
                    last_seen=now,
                    updated_at=now,
                )
                session.add(row)
                await session.commit()
                await session.refresh(row)
                d = row.model_dump(mode="json")
                d["inserted"] = True
                d["changed"] = True
                return d

            changed = False
            new_uuids, c1 = self._merge_unique(existing.attacker_uuids, attacker_uuid)
            new_ips, c2 = self._merge_unique(existing.attacker_ips, attacker_ip)
            new_deckies, c3 = self._merge_unique(existing.deckies, decky)
            new_services, c4 = self._merge_unique(existing.services, service)
            existing.attacker_uuids = new_uuids
            existing.attacker_ips = new_ips
            if c3 or c4:
                existing.deckies = new_deckies
                existing.services = new_services
                # Recount target tuples from the underlying credentials
                # table — a (decky, service) tuple only counts when both
                # were observed together, which the JSON lists alone
                # can't tell us.
                stmt = (
                    select(func.count(func.distinct(
                        Credential.decky_name + ":" + Credential.service
                    )))
                    .where(
                        Credential.secret_sha256 == secret_sha256,
                        Credential.secret_kind == secret_kind,
                        (Credential.principal == principal) if principal is not None
                        else Credential.principal.is_(None),
                    )
                )
                target_count = (await session.execute(stmt)).scalar() or 0
                existing.target_count = int(target_count)
            existing.attempt_count = (existing.attempt_count or 0) + int(attempt_count)
            existing.last_seen = now
            existing.updated_at = now
            if c1 or c2 or c3 or c4:
                changed = True
            session.add(existing)
            await session.commit()
            await session.refresh(existing)
            d = existing.model_dump(mode="json")
            d["inserted"] = False
            d["changed"] = changed
            return d

    async def find_credential_reuse_candidates(
        self, min_targets: int = 2
    ) -> List[dict[str, Any]]:
        """Find credential groups crossing the reuse threshold.

        Returns one dict per qualifying ``(secret_sha256, secret_kind,
        principal)`` group, with the keys plus a ``credentials`` list of
        the underlying rows so the correlator can fold each into
        ``CredentialReuse`` via ``upsert_credential_reuse``.
        """
        target_expr = func.count(
            func.distinct(Credential.decky_name + ":" + Credential.service)
        ).label("target_count")
        async with self._session() as session:
            group_stmt = (
                select(
                    Credential.secret_sha256,
                    Credential.secret_kind,
                    Credential.principal,
                    target_expr,
                )
                .group_by(
                    Credential.secret_sha256,
                    Credential.secret_kind,
                    Credential.principal,
                )
                .having(target_expr >= int(min_targets))
            )
            groups = (await session.execute(group_stmt)).all()
            out: List[dict[str, Any]] = []
            for sha, kind, principal, target_count in groups:
                cred_stmt = select(Credential).where(
                    Credential.secret_sha256 == sha,
                    Credential.secret_kind == kind,
                    (Credential.principal == principal)
                    if principal is not None
                    else Credential.principal.is_(None),
                )
                rows = (await session.execute(cred_stmt)).scalars().all()
                out.append({
                    "secret_sha256": sha,
                    "secret_kind": kind,
                    "principal": principal,
                    "target_count": int(target_count or 0),
                    "credentials": [r.model_dump(mode="json") for r in rows],
                })
            return out

    async def list_credential_reuses(
        self,
        limit: int = 50,
        offset: int = 0,
        min_target_count: int = 2,
        secret_kind: Optional[str] = None,
    ) -> tuple[int, List[dict[str, Any]]]:
        async with self._session() as session:
            base = select(CredentialReuse).where(
                CredentialReuse.target_count >= min_target_count
            )
            if secret_kind:
                base = base.where(CredentialReuse.secret_kind == secret_kind)
            total_stmt = select(func.count()).select_from(base.subquery())
            total = (await session.execute(total_stmt)).scalar() or 0
            list_stmt = (
                base.order_by(desc(CredentialReuse.target_count),
                              desc(CredentialReuse.last_seen))
                .offset(offset).limit(limit)
            )
            rows = (await session.execute(list_stmt)).scalars().all()
            out: List[dict[str, Any]] = []
            for r in rows:
                d = r.model_dump(mode="json")
                for key in ("attacker_uuids", "attacker_ips", "deckies", "services"):
                    try:
                        d[key] = json.loads(d[key])
                    except (json.JSONDecodeError, TypeError):
                        d[key] = []
                out.append(d)
            await self._enrich_with_secret(session, out)
            return int(total), out

    async def get_credential_reuse_by_id(
        self, reuse_id: str
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            row = (await session.execute(
                select(CredentialReuse).where(CredentialReuse.id == reuse_id)
            )).scalar_one_or_none()
            if row is None:
                return None
            d = row.model_dump(mode="json")
            for key in ("attacker_uuids", "attacker_ips", "deckies", "services"):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    d[key] = []
            await self._enrich_with_secret(session, [d])
            return d

    @staticmethod
    async def _enrich_with_secret(
        session: Any, rows: List[dict[str, Any]]
    ) -> None:
        """Tack ``secret_printable`` + ``secret_b64`` onto each reuse row.

        ``CredentialReuse`` only stores the sha256+kind hash of the
        secret — the actual printable/b64 representations live on the
        underlying ``Credential`` rows. The dashboard wants to show the
        secret in the drawer, so we lift one matching credential per
        ``(sha256, kind, principal)`` finding. One batched query for the
        whole page; rows with no surviving credential (shouldn't happen
        in practice) get nulls.
        """
        if not rows:
            return
        sha_set = {r["secret_sha256"] for r in rows}
        if not sha_set:
            return
        stmt = select(
            Credential.secret_sha256,
            Credential.secret_kind,
            Credential.principal,
            Credential.secret_printable,
            Credential.secret_b64,
        ).where(Credential.secret_sha256.in_(sha_set))
        secret_map: dict[
            tuple[str, str, Optional[str]],
            tuple[Optional[str], Optional[str]],
        ] = {}
        for sha, kind, principal, printable, b64 in (
            (await session.execute(stmt)).all()
        ):
            secret_map.setdefault((sha, kind, principal), (printable, b64))
        for r in rows:
            key = (r["secret_sha256"], r["secret_kind"], r.get("principal"))
            printable, b64 = secret_map.get(key, (None, None))
            r["secret_printable"] = printable
            r["secret_b64"] = b64
