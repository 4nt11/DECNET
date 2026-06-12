# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repo mixin for the ``observed_attachments`` table.

Composed onto :class:`SQLModelRepository` alongside the existing
per-domain mixins. The single public method is an upsert: if the
sha256 isn't there, insert with ``observation_count=1`` and the
caller's anchor metadata; otherwise increment ``observation_count``,
roll forward ``last_seen`` and ``last_seen_attacker_uuid``, dedupe a
new ``extension`` into ``extensions``, and stick the
``mal_hash_match`` verdict if either the row had no verdict or the
caller is upgrading ``False/None`` to ``True``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, cast

from sqlalchemy import select

from decnet.web.db.models import ObservedAttachment
from decnet.web.db.sqlmodel_repo._helpers import _MixinBase


class ObservedAttachmentsMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def upsert_observed_attachment(
        self,
        *,
        sha256: str,
        decky_uuid: Optional[str],
        attacker_uuid: Optional[str],
        extension: Optional[str],
        subject: Optional[str],
        mal_hash_match: Optional[bool],
        mal_hash_match_provider: Optional[str],
    ) -> str:
        """Record one observation of *sha256*. Returns the row ``uuid``.

        Verdict semantics:

        * Row has no verdict (``None``) → write whatever the caller has,
          including ``None`` (no-op) or ``False`` (provider checked and
          said clean).
        * Row already has ``False`` → upgrade to ``True`` if the caller
          says so; otherwise leave alone.
        * Row already has ``True`` → never downgrade. A hash a feed
          later forgets is still a hash that feed once flagged.
        """
        sha = sha256.lower()
        ext = extension.lower() if extension else None
        now = datetime.now(timezone.utc)

        async with self._session() as session:
            stmt = select(ObservedAttachment).where(
                ObservedAttachment.sha256 == sha,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                row = ObservedAttachment(
                    sha256=sha,
                    first_seen=now,
                    last_seen=now,
                    observation_count=1,
                    first_seen_decky_uuid=decky_uuid,
                    first_seen_attacker_uuid=attacker_uuid,
                    last_seen_attacker_uuid=attacker_uuid,
                    extensions=[ext] if ext else [],
                    first_subject=subject,
                    mal_hash_match=mal_hash_match,
                    mal_hash_match_provider=(
                        mal_hash_match_provider
                        if mal_hash_match is not None
                        else None
                    ),
                    mal_hash_match_at=(
                        now if mal_hash_match is not None else None
                    ),
                )
                session.add(row)
                await session.commit()
                await session.refresh(row)
                return row.uuid

            row.observation_count = (row.observation_count or 0) + 1
            row.last_seen = now
            if attacker_uuid:
                row.last_seen_attacker_uuid = attacker_uuid
            if ext:
                exts = list(row.extensions or [])
                if ext not in exts:
                    exts.append(ext)
                    row.extensions = exts
            # Verdict: only write if the row had no opinion, or the
            # caller is upgrading to True. Never downgrade True.
            if mal_hash_match is True and row.mal_hash_match is not True:
                row.mal_hash_match = True
                row.mal_hash_match_provider = mal_hash_match_provider
                row.mal_hash_match_at = now
            elif (
                mal_hash_match is not None
                and row.mal_hash_match is None
            ):
                row.mal_hash_match = mal_hash_match
                row.mal_hash_match_provider = mal_hash_match_provider
                row.mal_hash_match_at = now
            session.add(row)
            await session.commit()
            return cast(str, row.uuid)
