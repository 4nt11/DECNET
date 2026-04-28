"""
Shared SQLModel-based repository implementation.

Contains all dialect-portable query code used by the SQLite and MySQL
backends.  Dialect-specific behavior lives in subclasses:

* engine/session construction (``__init__``)
* ``_migrate_attackers_table`` (legacy schema check; DDL introspection
  is not portable)
* ``get_log_histogram`` (date-bucket expression differs per dialect)
"""
from __future__ import annotations

import asyncio
import json

import orjson
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, List

from sqlalchemy import func, select, desc, asc, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from decnet.config import load_state
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.auth import get_password_hash
from decnet.web.db.repository import BaseRepository
from decnet.web.db.models import (
    User,
    Log,
    Bounty,
    State,
    Attacker,
    AttackerBehavior,
    AttackerIdentity,
    Campaign,
    SessionProfile,
    SmtpTarget,
    Topology,
    LAN,
    TopologyDecky,
    TopologyEdge,
    TopologyStatusEvent,
    TopologyMutation,
)


from decnet.web.db.sqlmodel_repo._helpers import (  # noqa: F401  (re-exported for tests/external)
    _safe_session,
    _detach_close,
    _cleanup_tasks,
    _serialize_json_fields,
    _deserialize_json_fields,
)
from decnet.web.db.sqlmodel_repo.attacker_intel import AttackerIntelMixin
from decnet.web.db.sqlmodel_repo.auth import AuthMixin
from decnet.web.db.sqlmodel_repo.bounties import BountiesMixin
from decnet.web.db.sqlmodel_repo.canary import CanaryMixin
from decnet.web.db.sqlmodel_repo.credentials import CredentialsMixin
from decnet.web.db.sqlmodel_repo.deckies import DeckiesMixin
from decnet.web.db.sqlmodel_repo.fleet import FleetMixin
from decnet.web.db.sqlmodel_repo.logs import LogsMixin
from decnet.web.db.sqlmodel_repo.orchestrator import OrchestratorMixin
from decnet.web.db.sqlmodel_repo.realism import RealismMixin
from decnet.web.db.sqlmodel_repo.swarm import SwarmMixin
from decnet.web.db.sqlmodel_repo.webhooks import WebhooksMixin


class SQLModelRepository(
    AttackerIntelMixin,
    AuthMixin,
    BountiesMixin,
    CanaryMixin,
    CredentialsMixin,
    DeckiesMixin,
    FleetMixin,
    LogsMixin,
    OrchestratorMixin,
    RealismMixin,
    SwarmMixin,
    WebhooksMixin,
    BaseRepository,
):
    """Concrete SQLModel/SQLAlchemy-async repository.

    Subclasses provide ``self.engine`` (AsyncEngine) and ``self.session_factory``
    in ``__init__``, and override the few dialect-specific helpers.
    """

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]

    def _session(self):
        """Return a cancellation-safe session context manager."""
        return _safe_session(self.session_factory)

    # ------------------------------------------------------------ lifecycle

    async def initialize(self) -> None:
        """Create tables if absent and seed the admin user."""
        from sqlmodel import SQLModel
        await self._migrate_attackers_table()
        await self._migrate_session_profile_table()
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        await self._ensure_admin_user()

    async def reinitialize(self) -> None:
        """Re-create schema (for tests / reset flows). Does NOT drop existing tables."""
        from sqlmodel import SQLModel
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        await self._ensure_admin_user()

    async def _ensure_admin_user(self) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(User).where(User.username == DECNET_ADMIN_USER)
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                session.add(User(
                    uuid=str(uuid.uuid4()),
                    username=DECNET_ADMIN_USER,
                    password_hash=get_password_hash(DECNET_ADMIN_PASSWORD),
                    role="admin",
                    must_change_password=True,
                ))
                await session.commit()
                return
            # Self-heal env drift: if admin never finalized their password,
            # re-sync the hash from DECNET_ADMIN_PASSWORD. Otherwise leave
            # the user's chosen password alone.
            if existing.must_change_password:
                existing.password_hash = get_password_hash(DECNET_ADMIN_PASSWORD)
                session.add(existing)
                await session.commit()

    async def _migrate_attackers_table(self) -> None:
        """Legacy-schema cleanup. Override per dialect (DDL introspection is non-portable)."""
        return None

    async def _migrate_session_profile_table(self) -> None:
        """Add DEBT-036 keystroke-dynamics columns to existing session_profile
        rows. Override per dialect — DDL introspection is non-portable."""
        return None

    async def get_deckies(self) -> List[dict]:
        _state = await asyncio.to_thread(load_state)
        return [_d.model_dump() for _d in _state[0].deckies] if _state else []

    # --------------------------------------------------------------- users

    async def get_state(self, key: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            statement = select(State).where(State.key == key)
            result = await session.execute(statement)
            state = result.scalar_one_or_none()
            if state:
                return json.loads(state.value)
            return None

    async def set_state(self, key: str, value: Any) -> None:  # noqa: ANN401
        async with self._session() as session:
            statement = select(State).where(State.key == key)
            result = await session.execute(statement)
            state = result.scalar_one_or_none()

            value_json = orjson.dumps(value).decode()
            if state:
                state.value = value_json
                session.add(state)
            else:
                session.add(State(key=key, value=value_json))

            await session.commit()

    # ----------------------------------------------------------- attackers

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
                row_uuid = str(uuid.uuid4())
                data = {**data, "uuid": row_uuid}
                session.add(Attacker(**data))
            await session.commit()
            return row_uuid

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

    # ─── Identity resolution reads ────────────────────────────────────────

    async def get_identity_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        # Follow merged_into_uuid up to the winner. Loop bounded by
        # _MAX_MERGE_HOPS so a (hypothetically) corrupted ring can't
        # spin the worker. Clusterer is responsible for never producing
        # a cycle; this guard is belt-and-braces.
        _MAX_MERGE_HOPS = 8
        async with self._session() as session:
            current_uuid = uuid
            for _ in range(_MAX_MERGE_HOPS):
                result = await session.execute(
                    select(AttackerIdentity).where(AttackerIdentity.uuid == current_uuid)
                )
                identity = result.scalar_one_or_none()
                if identity is None:
                    return None
                if identity.merged_into_uuid is None:
                    return identity.model_dump(mode="json")
                current_uuid = identity.merged_into_uuid
            # Hit the hop cap — surface what we have rather than recurse.
            return identity.model_dump(mode="json")

    async def list_identities(
        self, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        # Exclude merged-out rows so the list view is the de-duped truth.
        # The history is still queryable per-uuid via get_identity_by_uuid
        # and a future "merged into" endpoint when we need it.
        statement = (
            select(AttackerIdentity)
            .where(AttackerIdentity.merged_into_uuid.is_(None))
            .order_by(desc(AttackerIdentity.updated_at))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [i.model_dump(mode="json") for i in result.scalars().all()]

    async def count_identities(self) -> int:
        statement = (
            select(func.count())
            .select_from(AttackerIdentity)
            .where(AttackerIdentity.merged_into_uuid.is_(None))
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def list_observations_for_identity(
        self, identity_uuid: str, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = (
            select(Attacker)
            .where(Attacker.identity_id == identity_uuid)
            .order_by(desc(Attacker.last_seen))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                self._deserialize_attacker(a.model_dump(mode="json"))
                for a in result.scalars().all()
            ]

    async def count_observations_for_identity(self, identity_uuid: str) -> int:
        statement = (
            select(func.count())
            .select_from(Attacker)
            .where(Attacker.identity_id == identity_uuid)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    # ─── Identity resolution writes (clusterer worker) ─────────────────────

    async def list_attackers_for_clustering(
        self, limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        # Project the columns the clusterer's similarity graph reads.
        # Keep it narrow so future denormalised projections (payloads
        # joined from logs, c2 endpoints aggregated from sessions) can
        # land here without churning every caller. ``fingerprints`` is
        # the raw JSON list — the clusterer parses for JA3 / HASSH.
        statement = select(
            Attacker.uuid, Attacker.asn, Attacker.identity_id, Attacker.fingerprints,
        ).order_by(Attacker.first_seen)
        if limit is not None:
            statement = statement.limit(limit)
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                {
                    "uuid": row.uuid,
                    "asn": row.asn,
                    "identity_id": row.identity_id,
                    "fingerprints": row.fingerprints,
                }
                for row in result.all()
            ]

    async def create_attacker_identity(self, row: dict[str, Any]) -> str:
        identity = AttackerIdentity(**row)
        async with self._session() as session:
            session.add(identity)
            await session.commit()
        return identity.uuid

    async def set_attacker_identity_id(
        self, attacker_uuid: str, identity_uuid: str,
    ) -> None:
        statement = (
            update(Attacker)
            .where(Attacker.uuid == attacker_uuid)
            .values(identity_id=identity_uuid)
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

    async def list_all_identities(self) -> list[dict[str, Any]]:
        statement = select(AttackerIdentity).order_by(AttackerIdentity.created_at)
        async with self._session() as session:
            result = await session.execute(statement)
            return [i.model_dump(mode="json") for i in result.scalars().all()]

    async def update_identity_merged_into(
        self, identity_uuid: str, winner_uuid: Optional[str],
    ) -> None:
        statement = (
            update(AttackerIdentity)
            .where(AttackerIdentity.uuid == identity_uuid)
            .values(
                merged_into_uuid=winner_uuid,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

    async def update_identity_fingerprints(
        self,
        identity_uuid: str,
        *,
        ja3_hashes: Optional[str] = None,
        hassh_hashes: Optional[str] = None,
        tls_cert_sha256: Optional[str] = None,
    ) -> None:
        statement = (
            update(AttackerIdentity)
            .where(AttackerIdentity.uuid == identity_uuid)
            .values(
                ja3_hashes=ja3_hashes,
                hassh_hashes=hassh_hashes,
                tls_cert_sha256=tls_cert_sha256,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

    # ─── Campaign clustering reads ────────────────────────────────────────

    async def get_campaign_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        # Same chain-walk as get_identity_by_uuid; bounded against
        # corrupted rings.
        _MAX_MERGE_HOPS = 8
        async with self._session() as session:
            current_uuid = uuid
            for _ in range(_MAX_MERGE_HOPS):
                result = await session.execute(
                    select(Campaign).where(Campaign.uuid == current_uuid)
                )
                campaign = result.scalar_one_or_none()
                if campaign is None:
                    return None
                if campaign.merged_into_uuid is None:
                    return campaign.model_dump(mode="json")
                current_uuid = campaign.merged_into_uuid
            return campaign.model_dump(mode="json")

    async def list_campaigns(
        self, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = (
            select(Campaign)
            .where(Campaign.merged_into_uuid.is_(None))
            .order_by(desc(Campaign.updated_at))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [c.model_dump(mode="json") for c in result.scalars().all()]

    async def count_campaigns(self) -> int:
        statement = (
            select(func.count())
            .select_from(Campaign)
            .where(Campaign.merged_into_uuid.is_(None))
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def list_identities_for_campaign(
        self, campaign_uuid: str, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = (
            select(AttackerIdentity)
            .where(AttackerIdentity.campaign_id == campaign_uuid)
            .order_by(desc(AttackerIdentity.updated_at))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [i.model_dump(mode="json") for i in result.scalars().all()]

    async def count_identities_for_campaign(self, campaign_uuid: str) -> int:
        statement = (
            select(func.count())
            .select_from(AttackerIdentity)
            .where(AttackerIdentity.campaign_id == campaign_uuid)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    # ─── Campaign clustering writes (campaign-clusterer worker) ───────────

    async def list_identities_for_clustering(
        self, limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        # Project the columns the campaign clusterer's similarity
        # graph reads. Narrow on purpose — future denormalised
        # projections (commands_by_phase from log mining, decky-set
        # aggregates) can land here without churning callers.
        statement = select(
            AttackerIdentity.uuid,
            AttackerIdentity.campaign_id,
            AttackerIdentity.merged_into_uuid,
            AttackerIdentity.first_seen_at,
            AttackerIdentity.last_seen_at,
            AttackerIdentity.ja3_hashes,
            AttackerIdentity.hassh_hashes,
            AttackerIdentity.payload_simhashes,
            AttackerIdentity.c2_endpoints,
        ).order_by(AttackerIdentity.created_at)
        if limit is not None:
            statement = statement.limit(limit)
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                {
                    "uuid": row.uuid,
                    "campaign_id": row.campaign_id,
                    "merged_into_uuid": row.merged_into_uuid,
                    "first_seen_at": (
                        row.first_seen_at.isoformat()
                        if row.first_seen_at is not None
                        else None
                    ),
                    "last_seen_at": (
                        row.last_seen_at.isoformat()
                        if row.last_seen_at is not None
                        else None
                    ),
                    "ja3_hashes": row.ja3_hashes,
                    "hassh_hashes": row.hassh_hashes,
                    "payload_simhashes": row.payload_simhashes,
                    "c2_endpoints": row.c2_endpoints,
                }
                for row in result.all()
            ]

    async def create_campaign(self, row: dict[str, Any]) -> str:
        campaign = Campaign(**row)
        async with self._session() as session:
            session.add(campaign)
            await session.commit()
        return campaign.uuid

    async def set_identity_campaign_id(
        self, identity_uuid: str, campaign_uuid: Optional[str],
    ) -> None:
        statement = (
            update(AttackerIdentity)
            .where(AttackerIdentity.uuid == identity_uuid)
            .values(
                campaign_id=campaign_uuid,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

    async def list_all_campaigns(self) -> list[dict[str, Any]]:
        statement = select(Campaign).order_by(Campaign.created_at)
        async with self._session() as session:
            result = await session.execute(statement)
            return [c.model_dump(mode="json") for c in result.scalars().all()]

    async def update_campaign_merged_into(
        self, campaign_uuid: str, winner_uuid: Optional[str],
    ) -> None:
        statement = (
            update(Campaign)
            .where(Campaign.uuid == campaign_uuid)
            .values(
                merged_into_uuid=winner_uuid,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

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

    # ------------------------------------------------------------ mazenet

    async def create_topology(self, data: dict[str, Any]) -> str:
        payload = _serialize_json_fields(data, ("config_snapshot",))
        async with self._session() as session:
            row = Topology(**payload)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def get_topology(self, topology_id: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            d = row.model_dump(mode="json")
            return _deserialize_json_fields(d, ("config_snapshot",))

    async def list_topologies(
        self,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        statement = select(Topology).order_by(desc(Topology.created_at))
        if status:
            statement = statement.where(Topology.status == status)
        if offset is not None:
            statement = statement.offset(offset)
        if limit is not None:
            statement = statement.limit(limit)
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("config_snapshot",)
                )
                for r in result.scalars().all()
            ]

    async def count_topologies(self, status: Optional[str] = None) -> int:
        from sqlalchemy import func
        statement = select(func.count(Topology.id))
        if status:
            statement = statement.where(Topology.status == status)
        async with self._session() as session:
            result = await session.execute(statement)
            return int(result.scalar_one() or 0)

    async def update_topology_status(
        self,
        topology_id: str,
        new_status: str,
        reason: Optional[str] = None,
    ) -> None:
        """Update topology.status and append a TopologyStatusEvent atomically.

        Transition legality is enforced in ``decnet.topology.status``; this
        method trusts the caller.
        """
        now = datetime.now(timezone.utc)
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if topo is None:
                return
            from_status = topo.status
            topo.status = new_status
            topo.status_changed_at = now
            session.add(topo)
            session.add(
                TopologyStatusEvent(
                    topology_id=topology_id,
                    from_status=from_status,
                    to_status=new_status,
                    at=now,
                    reason=reason,
                )
            )
            await session.commit()

    async def set_topology_resync(self, topology_id: str, value: bool) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if topo is None:
                return
            topo.needs_resync = bool(value)
            session.add(topo)
            await session.commit()

    async def set_topology_email_personas(
        self, topology_id: str, personas_json: str,
    ) -> bool:
        """Replace ``Topology.email_personas`` with the supplied JSON.

        The string is stored as-is; validation/parsing is the caller's
        job (and is repeated by the emailgen scheduler each tick anyway).
        Returns True if a row was updated.
        """
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if topo is None:
                return False
            topo.email_personas = personas_json
            session.add(topo)
            await session.commit()
            return True

    async def list_topologies_needing_resync(self) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.needs_resync == True)  # noqa: E712
            )
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("config_snapshot",)
                )
                for r in result.scalars().all()
            ]

    async def delete_topology_cascade(self, topology_id: str) -> bool:
        """Delete topology and all children.  No portable ON DELETE CASCADE."""
        async with self._session() as session:
            params = {"t": topology_id}
            await session.execute(
                text("DELETE FROM topology_status_events WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM topology_edges WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM topology_deckies WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM lans WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM topology_mutations WHERE topology_id = :t"),
                params,
            )
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if not topo:
                await session.commit()
                return False
            await session.delete(topo)
            await session.commit()
            return True

    async def _assert_pending(self, session, topology_id: str) -> None:
        """Pre-deploy edits are pending-only.  Raises TopologyNotEditable."""
        from decnet.topology.status import TopologyNotEditable, TopologyStatus

        result = await session.execute(
            select(Topology).where(Topology.id == topology_id)
        )
        topo = result.scalar_one_or_none()
        if topo is None:
            raise ValueError(f"topology {topology_id!r} not found")
        if topo.status != TopologyStatus.PENDING:
            raise TopologyNotEditable(
                status=topo.status,
                reason="free-form edits are pending-only; use the "
                "mutator (topology_mutations) after deploy",
            )

    async def _check_and_bump_version(
        self,
        session,
        topology_id: str,
        expected_version: Optional[int],
    ) -> None:
        """Optimistic-concurrency guard used by child-row mutators.

        If ``expected_version`` is None, no check happens (backward-compat
        for internal callers that don't need concurrency protection).

        If supplied, loads the Topology row in the same session,
        compares ``version == expected_version``, raises VersionConflict
        on mismatch, otherwise bumps ``version += 1``.  The caller must
        commit the enclosing session.
        """
        from decnet.topology.status import VersionConflict

        if expected_version is None:
            return
        result = await session.execute(
            select(Topology).where(Topology.id == topology_id)
        )
        topo = result.scalar_one_or_none()
        if topo is None:
            raise ValueError(f"topology {topology_id!r} not found")
        if topo.version != expected_version:
            raise VersionConflict(
                current=topo.version, expected=expected_version
            )
        topo.version = topo.version + 1
        session.add(topo)

    async def add_lan(
        self,
        data: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        async with self._session() as session:
            await self._check_and_bump_version(
                session, data["topology_id"], expected_version
            )
            row = LAN(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def update_lan(
        self,
        lan_id: str,
        fields: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        enforce_pending: bool = False,
    ) -> None:
        if not fields:
            return
        async with self._session() as session:
            result = await session.execute(
                select(LAN).where(LAN.id == lan_id)
            )
            lan = result.scalar_one_or_none()
            if lan is None:
                raise ValueError(f"lan {lan_id!r} not found")
            if enforce_pending:
                await self._assert_pending(session, lan.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, lan.topology_id, expected_version
                )
            await session.execute(
                update(LAN).where(LAN.id == lan_id).values(**fields)
            )
            await session.commit()

    async def delete_lan(
        self,
        lan_id: str,
        *,
        expected_version: Optional[int] = None,
    ) -> None:
        """Cascade-delete a LAN from a pending topology.

        Rejects if any decky declares this LAN as its home (i.e. has a
        non-bridge edge to it — the only LAN that decky lives in).  The
        caller must delete or reassign the home-deckies first.
        """
        from decnet.topology.status import TopologyNotEditable  # noqa: F401

        async with self._session() as session:
            result = await session.execute(select(LAN).where(LAN.id == lan_id))
            lan = result.scalar_one_or_none()
            if lan is None:
                return
            await self._assert_pending(session, lan.topology_id)

            # Home-decky check: any decky whose only edge lands here?
            edges_result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.lan_id == lan_id)
            )
            edges_here = edges_result.scalars().all()
            decky_uuids_on_this_lan = {e.decky_uuid for e in edges_here}
            for decky_uuid in decky_uuids_on_this_lan:
                other = await session.execute(
                    select(TopologyEdge).where(
                        TopologyEdge.decky_uuid == decky_uuid,
                        TopologyEdge.lan_id != lan_id,
                    )
                )
                if other.scalars().first() is None:
                    raise ValueError(
                        f"cannot delete LAN {lan.name!r}: decky "
                        f"{decky_uuid} has no other LAN (would be orphaned)"
                    )

            if expected_version is not None:
                await self._check_and_bump_version(
                    session, lan.topology_id, expected_version
                )
            # Cascade edges → LAN.
            await session.execute(
                text("DELETE FROM topology_edges WHERE lan_id = :l"),
                {"l": lan_id},
            )
            await session.execute(text("DELETE FROM lans WHERE id = :l"), {"l": lan_id})
            await session.commit()

    async def list_lans_for_topology(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(LAN).where(LAN.topology_id == topology_id).order_by(asc(LAN.name))
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def add_topology_decky(
        self,
        data: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        payload = _serialize_json_fields(data, ("services", "decky_config"))
        async with self._session() as session:
            await self._check_and_bump_version(
                session, data["topology_id"], expected_version
            )
            row = TopologyDecky(**payload)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.uuid

    async def update_topology_decky(
        self,
        decky_uuid: str,
        fields: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        enforce_pending: bool = False,
    ) -> None:
        if not fields:
            return
        payload = _serialize_json_fields(fields, ("services", "decky_config"))
        payload.setdefault("updated_at", datetime.now(timezone.utc))
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky).where(TopologyDecky.uuid == decky_uuid)
            )
            d = result.scalar_one_or_none()
            if d is None:
                raise ValueError(f"decky {decky_uuid!r} not found")
            if enforce_pending:
                await self._assert_pending(session, d.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, d.topology_id, expected_version
                )
            await session.execute(
                update(TopologyDecky)
                .where(TopologyDecky.uuid == decky_uuid)
                .values(**payload)
            )
            await session.commit()

    async def delete_topology_decky(
        self,
        decky_uuid: str,
        *,
        expected_version: Optional[int] = None,
    ) -> None:
        """Cascade-delete a decky + all its edges from a pending topology."""
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky).where(TopologyDecky.uuid == decky_uuid)
            )
            d = result.scalar_one_or_none()
            if d is None:
                return
            await self._assert_pending(session, d.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, d.topology_id, expected_version
                )
            await session.execute(
                text("DELETE FROM topology_edges WHERE decky_uuid = :u"),
                {"u": decky_uuid},
            )
            await session.execute(
                text("DELETE FROM topology_deckies WHERE uuid = :u"),
                {"u": decky_uuid},
            )
            await session.commit()

    async def list_topology_deckies(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky)
                .where(TopologyDecky.topology_id == topology_id)
                .order_by(asc(TopologyDecky.name))
            )
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("services", "decky_config")
                )
                for r in result.scalars().all()
            ]

    async def add_topology_edge(
        self,
        data: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        async with self._session() as session:
            await self._check_and_bump_version(
                session, data["topology_id"], expected_version
            )
            row = TopologyEdge(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def delete_topology_edge(
        self,
        edge_id: str,
        *,
        expected_version: Optional[int] = None,
    ) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.id == edge_id)
            )
            edge = result.scalar_one_or_none()
            if edge is None:
                return
            await self._assert_pending(session, edge.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, edge.topology_id, expected_version
                )
            await session.execute(
                text("DELETE FROM topology_edges WHERE id = :e"),
                {"e": edge_id},
            )
            await session.commit()

    async def list_topology_edges(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.topology_id == topology_id)
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def list_topology_status_events(
        self, topology_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyStatusEvent)
                .where(TopologyStatusEvent.topology_id == topology_id)
                .order_by(desc(TopologyStatusEvent.at))
                .limit(limit)
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    # ---------------- topology_mutations (live reconciler queue) ----------------

    async def enqueue_topology_mutation(
        self,
        topology_id: str,
        op: str,
        payload: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        """Append a pending mutation row and bump the topology version.

        Intended for use while the topology is ``active|degraded``; the
        reconciler picks these rows up on its next tick.
        """
        async with self._session() as session:
            await self._check_and_bump_version(
                session, topology_id, expected_version
            )
            row = TopologyMutation(
                topology_id=topology_id,
                op=op,
                payload=orjson.dumps(payload).decode(),
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def claim_next_mutation(
        self, topology_id: str
    ) -> Optional[dict[str, Any]]:
        """Atomically claim the oldest pending mutation for ``topology_id``.

        Correctness-critical: this is ONE SQL statement.  Splitting it
        into SELECT-then-UPDATE would let two racing watch-loops both
        see the same ``pending`` row and both transition it to
        ``applying`` — double-executing the op.  With the single
        ``UPDATE ... WHERE id = (SELECT ... LIMIT 1) AND state='pending'``
        pattern the loser's UPDATE matches zero rows and returns
        ``None`` — that is the expected, non-error outcome under
        contention.
        """
        async with self._session() as session:
            now = datetime.now(timezone.utc).isoformat()
            # Single-statement atomic claim.  The inner SELECT picks the
            # oldest pending row; the outer UPDATE re-checks state so a
            # second racer that also saw that id finds state='applying'
            # and matches zero rows.
            # MySQL forbids referencing the UPDATE target inside a
            # subquery (ERROR 1093). Wrapping the inner SELECT in a
            # derived table forces materialisation and sidesteps the
            # rule. SQLite accepts both forms, so this stays portable.
            sql = text(
                """
                UPDATE topology_mutations
                SET state = 'applying'
                WHERE id = (
                    SELECT id FROM (
                        SELECT id FROM topology_mutations
                        WHERE topology_id = :t AND state = 'pending'
                        ORDER BY requested_at ASC
                        LIMIT 1
                    ) AS _next
                )
                AND state = 'pending'
                """
            )
            result = await session.execute(sql, {"t": topology_id})
            if result.rowcount == 0:
                await session.commit()
                return None
            # Re-read the row we just claimed.  The post-UPDATE SELECT is
            # safe: no racer can now transition an ``applying`` row back
            # to ``pending``.
            sel = await session.execute(
                select(TopologyMutation)
                .where(TopologyMutation.topology_id == topology_id)
                .where(TopologyMutation.state == "applying")
                .order_by(asc(TopologyMutation.requested_at))
                .limit(1)
            )
            row = sel.scalar_one_or_none()
            await session.commit()
            _ = now
            if row is None:
                return None
            return row.model_dump(mode="json")

    async def mark_mutation_applied(self, mutation_id: str) -> None:
        async with self._session() as session:
            await session.execute(
                text(
                    "UPDATE topology_mutations "
                    "SET state = 'applied', applied_at = :at "
                    "WHERE id = :i"
                ),
                {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "i": mutation_id,
                },
            )
            await session.commit()

    async def mark_mutation_failed(
        self, mutation_id: str, reason: str
    ) -> None:
        async with self._session() as session:
            await session.execute(
                text(
                    "UPDATE topology_mutations "
                    "SET state = 'failed', applied_at = :at, reason = :r "
                    "WHERE id = :i"
                ),
                {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "r": reason,
                    "i": mutation_id,
                },
            )
            await session.commit()

    async def list_topology_mutations(
        self,
        topology_id: str,
        state: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = (
                select(TopologyMutation)
                .where(TopologyMutation.topology_id == topology_id)
                .order_by(desc(TopologyMutation.requested_at))
            )
            if state is not None:
                stmt = stmt.where(TopologyMutation.state == state)
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def has_pending_topology_mutation(self) -> bool:
        """Cheap watch-loop guard: any pending mutation on a live topology?

        Uses the ``ix_topology_mutations_state_topology`` composite index
        to keep the join cheap at scale.  Returns False as soon as the
        reconciler path should be skipped.
        """
        async with self._session() as session:
            result = await session.execute(
                text(
                    "SELECT 1 FROM topology_mutations "
                    "WHERE state = 'pending' "
                    "AND topology_id IN ("
                    "    SELECT id FROM topologies "
                    "    WHERE status IN ('active', 'degraded')"
                    ") LIMIT 1"
                )
            )
            return result.first() is not None

    async def list_live_topology_ids(self) -> list[str]:
        """Return ids of topologies currently in ``active|degraded``."""
        async with self._session() as session:
            result = await session.execute(
                select(Topology.id).where(
                    Topology.status.in_(["active", "degraded"])
                )
            )
            return [r for r in result.scalars().all()]

    async def list_running_topology_deckies(self) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky).where(TopologyDecky.state == "running")
            )
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("services", "decky_config")
                )
                for r in result.scalars().all()
            ]

