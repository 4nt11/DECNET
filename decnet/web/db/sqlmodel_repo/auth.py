"""User CRUD."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select, update

from decnet.web.db.models import User


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
