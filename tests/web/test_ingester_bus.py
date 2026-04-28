"""Bus wiring for the ingester (DEBT-031, worker 6).

The ingester emits one ``system.log`` event per DB-committed batch via
``_publish_batch``.  Per-line noise lives on the collector side; the
ingester's job is to signal "N rows landed in the DB up to offset P" so
heartbeat / federation consumers can tail DB progress without polling
the state table.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.web.ingester import _publish_batch


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


@pytest.mark.asyncio
async def test_publish_batch_fires_on_nonempty_flush(bus: FakeBus) -> None:
    sub = bus.subscribe("system.log")
    async with sub:
        await _publish_batch(bus, flushed=17, position=4096)
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "system.log"
    assert event.type == "batch_committed"
    assert event.payload == {
        "component": "ingester",
        "flushed": 17,
        "position": 4096,
    }


@pytest.mark.asyncio
async def test_publish_batch_skips_zero_row_flush(bus: FakeBus) -> None:
    # An empty batch shouldn't pollute the topic — nothing to signal.
    sub = bus.subscribe("system.log")
    async with sub:
        await _publish_batch(bus, flushed=0, position=0)
        # Expect nothing within a short window.  asyncio.wait_for raises
        # TimeoutError when no event arrives.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.__anext__(), timeout=0.2)


@pytest.mark.asyncio
async def test_publish_batch_is_noop_when_bus_is_none() -> None:
    # Bus-disabled path: ingester passes bus=None into _publish_batch.
    # Must be a safe no-op; no exceptions, no hangs.
    await _publish_batch(None, flushed=5, position=123)


@pytest.mark.asyncio
async def test_publish_batch_swallows_bus_failures(monkeypatch) -> None:
    # A dead bus must never break the ingestion loop.
    class _ExplodingBus:
        async def publish(self, *_args, **_kwargs):
            raise RuntimeError("transport exploded")

    await _publish_batch(_ExplodingBus(), flushed=3, position=42)


@pytest.mark.asyncio
async def test_credential_captured_published_on_upsert(bus: FakeBus) -> None:
    """A successful credential ingest publishes ``credential.captured`` once
    with the secret hash, kind, attacker IP, decky, and service.
    """
    from unittest.mock import AsyncMock

    from decnet.web.ingester import _ingest_credential_native

    repo = AsyncMock()
    repo.upsert_credential = AsyncMock(return_value=1)

    sub = bus.subscribe("credential.captured")
    async with sub:
        await _ingest_credential_native(
            repo,
            log_data={
                "attacker_ip": "10.0.0.5",
                "decky": "decky-01",
                "service": "ssh",
            },
            fields={
                "secret_b64": "aHVudGVyMg==",
                "secret_kind": "plaintext",
                "principal": "root",
                "secret_printable": "hunter2",
            },
            bus=bus,
        )
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "credential.captured"
    assert event.type == "captured"
    assert event.payload["secret_kind"] == "plaintext"
    assert event.payload["attacker_ip"] == "10.0.0.5"
    assert event.payload["decky"] == "decky-01"
    assert event.payload["service"] == "ssh"
    # Hash is sha256 of decoded "hunter2".
    import hashlib
    assert event.payload["secret_sha256"] == hashlib.sha256(b"hunter2").hexdigest()
    repo.upsert_credential.assert_awaited_once()


@pytest.mark.asyncio
async def test_credential_captured_silent_on_validation_failure(bus: FakeBus) -> None:
    """A dropped credential (invalid b64) must not publish anything."""
    from unittest.mock import AsyncMock

    from decnet.web.ingester import _ingest_credential_native

    repo = AsyncMock()
    repo.upsert_credential = AsyncMock()

    sub = bus.subscribe("credential.captured")
    async with sub:
        await _ingest_credential_native(
            repo,
            log_data={"attacker_ip": "10.0.0.5", "decky": "d", "service": "ssh"},
            fields={"secret_b64": "not-valid-base64!!!"},
            bus=bus,
        )
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.__anext__(), timeout=0.2)

    repo.upsert_credential.assert_not_awaited()


@pytest.mark.asyncio
async def test_ingester_degrades_cleanly_when_bus_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from decnet.bus.factory import get_bus

    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    b = get_bus(client_name="ingester")
    await b.connect()
    await b.publish("system.log", {"component": "ingester"}, event_type="batch_committed")
    await b.close()
