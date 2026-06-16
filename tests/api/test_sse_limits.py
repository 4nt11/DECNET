# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-user SSE connection cap — F6/D mitigation."""
import pytest
from fastapi import HTTPException

from decnet.web import sse_limits


@pytest.mark.asyncio
async def test_slot_under_cap_enters_cleanly(monkeypatch):
    monkeypatch.setattr(sse_limits, "_MAX_PER_USER", 2)
    sse_limits._reset_for_tests()

    async with sse_limits.sse_connection_slot("u1"):
        assert sse_limits.current_count("u1") == 1
        async with sse_limits.sse_connection_slot("u1"):
            assert sse_limits.current_count("u1") == 2

    assert sse_limits.current_count("u1") == 0


@pytest.mark.asyncio
async def test_slot_over_cap_raises_429(monkeypatch):
    monkeypatch.setattr(sse_limits, "_MAX_PER_USER", 1)
    sse_limits._reset_for_tests()

    async with sse_limits.sse_connection_slot("u1"):
        with pytest.raises(HTTPException) as exc:
            async with sse_limits.sse_connection_slot("u1"):
                pass
        assert exc.value.status_code == 429

    # Released after the outer context exits → fresh slot works.
    async with sse_limits.sse_connection_slot("u1"):
        assert sse_limits.current_count("u1") == 1


@pytest.mark.asyncio
async def test_slot_per_user_isolation(monkeypatch):
    monkeypatch.setattr(sse_limits, "_MAX_PER_USER", 1)
    sse_limits._reset_for_tests()

    async with sse_limits.sse_connection_slot("u1"):
        async with sse_limits.sse_connection_slot("u2"):
            assert sse_limits.current_count("u1") == 1
            assert sse_limits.current_count("u2") == 1


@pytest.mark.asyncio
async def test_slot_decrements_on_exception(monkeypatch):
    monkeypatch.setattr(sse_limits, "_MAX_PER_USER", 1)
    sse_limits._reset_for_tests()

    with pytest.raises(ValueError):
        async with sse_limits.sse_connection_slot("u1"):
            raise ValueError("boom")

    assert sse_limits.current_count("u1") == 0
    # Slot is free again after exception path.
    async with sse_limits.sse_connection_slot("u1"):
        pass
