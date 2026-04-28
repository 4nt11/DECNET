"""Attacker repository methods.

The full domain spans ~500 lines of methods across attacker rows,
behavior signals, session profiles, SMTP victim tracking, and
log-derived activity views.  Each concern lives in its own submixin;
``AttackersMixin`` composes them.

``_deserialize_attacker`` lives on ``AttackersCoreMixin`` and is reached
from ``IdentitiesMixin.list_observations_for_identity`` via ``self.`` —
Python's MRO resolves it to the core mixin on the composed
``SQLModelRepository`` class.
"""
from __future__ import annotations

from decnet.web.db.sqlmodel_repo.attackers._core import AttackersCoreMixin
from decnet.web.db.sqlmodel_repo.attackers.activity import AttackerActivityMixin
from decnet.web.db.sqlmodel_repo.attackers.behavior import AttackerBehaviorMixin
from decnet.web.db.sqlmodel_repo.attackers.sessions import SessionProfilesMixin
from decnet.web.db.sqlmodel_repo.attackers.smtp import SmtpTargetsMixin


class AttackersMixin(
    AttackerActivityMixin,
    AttackerBehaviorMixin,
    SessionProfilesMixin,
    SmtpTargetsMixin,
    AttackersCoreMixin,
):
    """Composed attackers mixin — see submixins for the actual methods."""


__all__ = ["AttackersMixin"]
