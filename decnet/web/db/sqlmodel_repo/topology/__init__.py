# SPDX-License-Identifier: AGPL-3.0-or-later
"""MazeNET topology repository methods.

The full domain spans ~700 lines of methods across topologies, LANs,
deckies, edges, the status-event log, and the live reconciler mutation
queue.  Each concern lives in its own submixin; ``TopologyMixin``
composes them.

The optimistic-locking helpers (``_assert_pending``,
``_check_and_bump_version``) live on ``TopologyCoreMixin`` and are
reached from sibling submixins via ``self.`` — Python's MRO resolves
them to the core mixin no matter which submixin holds the caller.
"""
from __future__ import annotations

from decnet.web.db.sqlmodel_repo.topology._core import TopologyCoreMixin
from decnet.web.db.sqlmodel_repo.topology.deckies import TopologyDeckiesMixin
from decnet.web.db.sqlmodel_repo.topology.edges import TopologyEdgesMixin
from decnet.web.db.sqlmodel_repo.topology.lans import LansMixin
from decnet.web.db.sqlmodel_repo.topology.mutations import TopologyMutationsMixin


class TopologyMixin(
    TopologyDeckiesMixin,
    TopologyEdgesMixin,
    LansMixin,
    TopologyMutationsMixin,
    TopologyCoreMixin,
):
    """Composed topology mixin — see submixins for the actual methods."""


__all__ = ["TopologyMixin"]
