"""Attacker repository methods.

Per-concern submixins composed onto ``AttackersMixin``. The legacy
``SessionProfilesMixin`` was dropped when the BEHAVE-SHELL
``observations`` table replaced the ``session_profile`` column-zoo
(see DEBT-050 → ``decnet/web/db/sqlmodel_repo/observations.py``).

``_deserialize_attacker`` lives on ``AttackersCoreMixin`` and is reached
from ``IdentitiesMixin.list_observations_for_identity`` via ``self.`` —
Python's MRO resolves it to the core mixin on the composed
``SQLModelRepository`` class.
"""
from __future__ import annotations

from decnet.web.db.sqlmodel_repo.attackers._core import AttackersCoreMixin
from decnet.web.db.sqlmodel_repo.attackers.activity import AttackerActivityMixin
from decnet.web.db.sqlmodel_repo.attackers.behavior import AttackerBehaviorMixin
from decnet.web.db.sqlmodel_repo.attackers.smtp import SmtpTargetsMixin


class AttackersMixin(
    AttackerActivityMixin,
    AttackerBehaviorMixin,
    SmtpTargetsMixin,
    AttackersCoreMixin,
):
    """Composed attackers mixin — see submixins for the actual methods."""


__all__ = ["AttackersMixin"]
