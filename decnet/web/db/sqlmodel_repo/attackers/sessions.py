"""Per-session profile rows (keystroke-dynamics features land here at
ingestion-time post-V2)."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select

from decnet.web.db.models import SessionProfile


class SessionProfilesMixin:
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
