"""TTP-tagging repository — `ttp_tag` reads + idempotent inserts.

Contract step E.1.10 of `development/TTP_TAGGING.md`. Method bodies
raise ``NotImplementedError``; the SQL lands at E.3 implementation
phase. The shape — argument types, return types, idempotency
semantics on ``insert_tags`` — is the public contract from this
commit forward.

Per the dual-DB-backend project convention, dialect-specific behavior
(``INSERT OR IGNORE`` on SQLite vs ``INSERT IGNORE`` on MySQL) is
overridden in the per-dialect subclasses (``decnet.web.db.sqlite``,
``decnet.web.db.mysql``); the shared base lives here.
"""
from __future__ import annotations

from decnet.web.db.models import (
    CampaignTechniqueRow,
    IdentityTechniqueRow,
    TechniqueRollupRow,
    TTPTag,
)
from decnet.web.db.sqlmodel_repo._helpers import _MixinBase


class TTPMixin(_MixinBase):
    """Mixin: TTP-tag query + insert methods composed onto
    :class:`SQLModelRepository`.

    Expects ``self._session()`` from the base mixin. Adding a new
    ``ttp_tag`` query method here requires adding a contract test in
    ``tests/web/db/test_ttp_repo.py`` (E.2.13) AND a parametrized run
    against both SQLite and MySQL via the existing ``db_backends``
    fixture.
    """

    async def insert_tags(self, rows: list[TTPTag]) -> int:
        """Bulk-upsert tags with ``INSERT OR IGNORE`` semantics.

        Returns the number of rows actually inserted (i.e. that were
        not already present at their deterministic
        :func:`compute_tag_uuid` PK). The idempotency property is the
        load-bearing contract: replaying the same source events must
        converge to the same tag set without writing duplicates and
        without raising. See TTP_TAGGING.md §"Idempotency" + §"Bus
        topics — Loop-prevention invariant".
        """
        raise NotImplementedError(
            "insert_tags lands at E.3 implementation phase",
        )

    async def list_techniques_by_identity(
        self,
        uuid: str,
    ) -> list[IdentityTechniqueRow]:
        """Per-Identity TTP rollup. Joins ``ttp_tag`` on
        ``identity_uuid`` and groups by ``(technique_id,
        sub_technique_id)``. Includes identity-rollup tags (with NULL
        ``attacker_uuid``) and per-event tags whose denormalised
        ``identity_uuid`` matches.
        """
        raise NotImplementedError(
            "list_techniques_by_identity lands at E.3",
        )

    async def list_techniques_by_attacker(
        self,
        uuid: str,
    ) -> list[IdentityTechniqueRow]:
        """Per-Attacker (per-IP) TTP rollup. Reads ``ttp_tag`` filtered
        on ``attacker_uuid``. Identity-rollup tags (NULL attacker
        anchor) are deliberately excluded — those belong to the
        Identity, not any one IP underneath it.
        """
        raise NotImplementedError(
            "list_techniques_by_attacker lands at E.3",
        )

    async def list_techniques_by_campaign(
        self,
        uuid: str,
    ) -> list[CampaignTechniqueRow]:
        """Campaign-wide TTP rollup. Joins ``ttp_tag`` -> Identity ->
        ``campaign_uuid`` and groups across all member Identities.
        """
        raise NotImplementedError(
            "list_techniques_by_campaign lands at E.3",
        )

    async def list_techniques_by_session(
        self,
        sid: str,
    ) -> list[IdentityTechniqueRow]:
        """Session-scoped TTP timeline. Filtered on ``ttp_tag.session_id``.
        Used by the SessionDetail page (post-v0).
        """
        raise NotImplementedError(
            "list_techniques_by_session lands at E.3",
        )

    async def list_distinct_techniques(self) -> list[TechniqueRollupRow]:
        """Fleet-wide distinct-technique rollup with counts +
        most-recent-seen timestamps. Backs ``GET /api/v1/ttp/techniques``.
        """
        raise NotImplementedError(
            "list_distinct_techniques lands at E.3",
        )
