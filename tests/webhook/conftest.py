"""Shared fixtures for webhook worker tests."""
from __future__ import annotations

from typing import AsyncIterator

import pytest_asyncio

from decnet.bus.fake import FakeBus


@pytest_asyncio.fixture
async def fake_bus() -> AsyncIterator[FakeBus]:
    bus = FakeBus()
    await bus.connect()
    try:
        yield bus
    finally:
        await bus.close()
