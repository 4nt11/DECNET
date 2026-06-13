# SPDX-License-Identifier: AGPL-3.0-or-later
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

import json
import os

import orjson
import uuid
from typing import Any, Optional, List, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.auth import get_password_hash
from decnet.web.db.repository import BaseRepository
from decnet.web.db.models import State, User


from decnet.web.db.sqlmodel_repo._helpers import (  # noqa: F401  (re-exported for tests/external)
    _safe_session,
    _detach_close,
    _cleanup_tasks,
)
from decnet.web.db.sqlmodel_repo.attacker_intel import AttackerIntelMixin
from decnet.web.db.sqlmodel_repo.attackers import AttackersMixin
from decnet.web.db.sqlmodel_repo.attribution import AttributionMixin
from decnet.web.db.sqlmodel_repo.auth import AuthMixin
from decnet.web.db.sqlmodel_repo.bounties import BountiesMixin
from decnet.web.db.sqlmodel_repo.campaigns import CampaignsMixin
from decnet.web.db.sqlmodel_repo.canary import CanaryMixin
from decnet.web.db.sqlmodel_repo.credentials import CredentialsMixin
from decnet.web.db.sqlmodel_repo.deckies import DeckiesMixin
from decnet.web.db.sqlmodel_repo.decky_lifecycle import LifecycleMixin
from decnet.web.db.sqlmodel_repo.fleet import FleetMixin
from decnet.web.db.sqlmodel_repo.identities import IdentitiesMixin
from decnet.web.db.sqlmodel_repo.logs import LogsMixin
from decnet.web.db.sqlmodel_repo.observations import ObservationsMixin
from decnet.web.db.sqlmodel_repo.observed_attachments import ObservedAttachmentsMixin
from decnet.web.db.sqlmodel_repo.orchestrator import OrchestratorMixin
from decnet.web.db.sqlmodel_repo.realism import RealismMixin
from decnet.web.db.sqlmodel_repo.swarm import SwarmMixin
from decnet.web.db.sqlmodel_repo.topology import TopologyMixin
from decnet.web.db.sqlmodel_repo.tarpit import TarpitMixin
from decnet.web.db.sqlmodel_repo.ttp import TTPMixin
from decnet.web.db.sqlmodel_repo.webhooks import WebhooksMixin

# Fixed principal the schemathesis contract harness mints its token for; seeded
# only under DECNET_CONTRACT_TEST (see _ensure_contract_user). Kept in sync with
# tests/api/test_schemathesis.py.
CONTRACT_TEST_USER_UUID = "00000000-0000-0000-0000-000000000001"


class SQLModelRepository(
    AttackerIntelMixin,
    AttackersMixin,
    AttributionMixin,
    AuthMixin,
    BountiesMixin,
    CampaignsMixin,
    CanaryMixin,
    CredentialsMixin,
    DeckiesMixin,
    LifecycleMixin,
    FleetMixin,
    IdentitiesMixin,
    LogsMixin,
    ObservationsMixin,
    ObservedAttachmentsMixin,
    OrchestratorMixin,
    RealismMixin,
    SwarmMixin,
    TarpitMixin,
    TopologyMixin,
    TTPMixin,
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
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        await self._ensure_admin_user()
        await self._ensure_contract_user()

    async def reinitialize(self) -> None:
        """Re-create schema (for tests / reset flows). Does NOT drop existing tables."""
        from sqlmodel import SQLModel
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        await self._ensure_admin_user()
        await self._ensure_contract_user()

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

    async def _ensure_contract_user(self) -> None:
        """Seed the fixed-uuid principal the schemathesis contract/fuzz harness
        authenticates as. Gated on DECNET_CONTRACT_TEST so it NEVER runs in a
        real deployment. Since the post-revocation auth path now requires the
        token's user to exist (and not be revoked), the harness's locally-minted
        fixed-uuid token must resolve to a live, admin, non-revoked user. The
        password hash is random and unusable, so /auth/login can never
        authenticate as this principal — only the minted token works."""
        if os.environ.get("DECNET_CONTRACT_TEST") != "true":
            return
        async with self._session() as session:
            if await session.get(User, CONTRACT_TEST_USER_UUID) is not None:
                return
            session.add(User(
                uuid=CONTRACT_TEST_USER_UUID,
                username="contract-test",
                password_hash=get_password_hash(uuid.uuid4().hex),
                role="admin",
                must_change_password=False,
            ))
            await session.commit()

    async def _migrate_attackers_table(self) -> None:
        """Legacy-schema cleanup. Override per dialect (DDL introspection is non-portable)."""
        return None

    async def get_deckies(self) -> List[dict]:
        # The fleet inventory the UI/API sees is fleet_deckies — the
        # engine-mirrored table written on EVERY deploy/teardown (CLI or web),
        # per the source-of-truth model documented in fleet/reconciler.py.
        # Each row's decky_config column is a full DeckyConfig.model_dump(
        # mode="json"), so it rehydrates to the same shape load_state() used
        # to return. See development/ADR-001-FLEET-SOURCE-OF-TRUTH.md.
        rows = await self.list_fleet_deckies()
        return [r["decky_config"] for r in rows if r.get("decky_config")]

    # --------------------------------------------------------------- users

    async def get_state(self, key: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            statement = select(State).where(State.key == key)
            result = await session.execute(statement)
            state = result.scalar_one_or_none()
            if state:
                return cast(dict[str, Any], json.loads(state.value))
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

