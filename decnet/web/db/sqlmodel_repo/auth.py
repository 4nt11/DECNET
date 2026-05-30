# SPDX-License-Identifier: AGPL-3.0-or-later
"""User CRUD."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import delete, select, update

from decnet.web.db.models import RevokedToken, User


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class AuthMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``. Expects ``self._session()``.

    ``_ensure_admin_user`` stays in the package ``__init__`` so the
    ``DECNET_ADMIN_PASSWORD`` it reads remains addressable at the
    ``decnet.web.db.sqlmodel_repo`` module path (test monkeypatch surface).
    """

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        async with self._session() as session:
            result = await session.execute(
                select(User).where(User.username == username)
            )
            user = result.scalar_one_or_none()
            return user.model_dump() if user else None

    async def get_user_by_uuid(self, uuid: str) -> Optional[dict]:
        async with self._session() as session:
            result = await session.execute(
                select(User).where(User.uuid == uuid)
            )
            user = result.scalar_one_or_none()
            return user.model_dump() if user else None

    async def create_user(self, user_data: dict[str, Any]) -> None:
        async with self._session() as session:
            session.add(User(**user_data))
            await session.commit()

    async def update_user_password(
        self, uuid: str, password_hash: str, must_change_password: bool = False
    ) -> None:
        async with self._session() as session:
            await session.execute(
                update(User)
                .where(User.uuid == uuid)
                .values(
                    password_hash=password_hash,
                    must_change_password=must_change_password,
                )
            )
            await session.commit()

    async def list_users(self) -> list[dict]:
        async with self._session() as session:
            result = await session.execute(select(User))
            return [u.model_dump() for u in result.scalars().all()]

    async def delete_user(self, uuid: str) -> bool:
        async with self._session() as session:
            result = await session.execute(select(User).where(User.uuid == uuid))
            user = result.scalar_one_or_none()
            if not user:
                return False
            await session.delete(user)
            await session.commit()
            return True

    async def update_user_role(self, uuid: str, role: str) -> None:
        async with self._session() as session:
            await session.execute(
                update(User).where(User.uuid == uuid).values(role=role)
            )
            await session.commit()

    async def revoke_token(self, jti: str, user_uuid: str, expires_at: datetime) -> None:
        async with self._session() as session:
            # Opportunistic prune — the denylist only needs unexpired tokens, so
            # purge stale rows on every insert instead of a separate vacuum job.
            await session.execute(
                delete(RevokedToken).where(
                    RevokedToken.expires_at < datetime.now(timezone.utc)
                )
            )
            if await session.get(RevokedToken, jti) is None:
                session.add(
                    RevokedToken(jti=jti, user_uuid=user_uuid, expires_at=expires_at)
                )
            await session.commit()

    async def is_token_revoked(self, jti: str) -> bool:
        async with self._session() as session:
            return await session.get(RevokedToken, jti) is not None

    async def set_tokens_valid_from(self, user_uuid: str, ts: datetime) -> None:
        async with self._session() as session:
            await session.execute(
                update(User).where(User.uuid == user_uuid).values(tokens_valid_from=ts)
            )
            await session.commit()
