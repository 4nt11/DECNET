"""MazeNET topology status state machine.

Seven states — six active in v1.  ``degraded`` is schema-reserved for the
future Healer worker and has no transitions into it from v1 code paths.
"""
from __future__ import annotations


class TopologyStatus:
    PENDING = "pending"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    DEGRADED = "degraded"
    FAILED = "failed"
    TEARING_DOWN = "tearing_down"
    TORN_DOWN = "torn_down"

    ALL: frozenset[str] = frozenset(
        {PENDING, DEPLOYING, ACTIVE, DEGRADED, FAILED, TEARING_DOWN, TORN_DOWN}
    )


# Directed transitions.  torn_down is terminal.  degraded is unreachable
# in v1 (Healer would be the only writer), but its outbound edges stay
# defined so when Healer lands the state machine already accepts them.
_LEGAL: dict[str, frozenset[str]] = {
    TopologyStatus.PENDING: frozenset(
        {TopologyStatus.DEPLOYING, TopologyStatus.TORN_DOWN}
    ),
    TopologyStatus.DEPLOYING: frozenset(
        {
            TopologyStatus.ACTIVE,
            TopologyStatus.FAILED,
            TopologyStatus.DEGRADED,
            TopologyStatus.TEARING_DOWN,
        }
    ),
    TopologyStatus.ACTIVE: frozenset(
        {TopologyStatus.DEGRADED, TopologyStatus.TEARING_DOWN}
    ),
    TopologyStatus.DEGRADED: frozenset(
        {TopologyStatus.ACTIVE, TopologyStatus.TEARING_DOWN}
    ),
    TopologyStatus.FAILED: frozenset({TopologyStatus.TEARING_DOWN}),
    TopologyStatus.TEARING_DOWN: frozenset(
        {TopologyStatus.TORN_DOWN, TopologyStatus.DEGRADED}
    ),
    TopologyStatus.TORN_DOWN: frozenset(),
}


class TopologyStatusError(ValueError):
    """Raised when an illegal topology status transition is attempted."""


class VersionConflict(RuntimeError):
    """Raised when a topology write is supplied a stale ``expected_version``.

    Optimistic concurrency guard: the caller passed the version it last
    observed, and the topology has since been mutated by someone else.
    The caller should re-read and retry.
    """

    def __init__(self, *, current: int, expected: int) -> None:
        self.current = current
        self.expected = expected
        super().__init__(
            f"topology version conflict: expected {expected}, current is {current}"
        )


def assert_transition(current: str, new: str) -> None:
    """Validate ``current → new`` or raise :class:`TopologyStatusError`."""
    if current not in TopologyStatus.ALL:
        raise TopologyStatusError(f"unknown current status: {current!r}")
    if new not in TopologyStatus.ALL:
        raise TopologyStatusError(f"unknown new status: {new!r}")
    if new not in _LEGAL[current]:
        raise TopologyStatusError(
            f"illegal transition: {current!r} → {new!r}"
        )


def legal_next(current: str) -> frozenset[str]:
    """Return the set of legal successor statuses from ``current``."""
    if current not in _LEGAL:
        raise TopologyStatusError(f"unknown status: {current!r}")
    return _LEGAL[current]
