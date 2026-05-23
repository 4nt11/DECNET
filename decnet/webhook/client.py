# SPDX-License-Identifier: AGPL-3.0-or-later
"""HMAC-signed HTTP POST delivery for webhook events.

The delivery function is shared between the worker's normal dispatch
loop and the `/webhooks/{uuid}/test` admin route — same payload shape,
same signing, same headers. Retry policy is configurable by the caller
so manual tests can skip retries entirely while the worker retries
with backoff.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

import httpx
import orjson

from decnet.logging import get_logger

log = get_logger("webhook.client")


_DEFAULT_TIMEOUT_S = 10.0
_DEFAULT_RETRY_SCHEDULE = (1.0, 2.0, 4.0)
_JITTER_LOW = 0.8
_JITTER_HIGH = 1.2
_PAYLOAD_VERSION = 1


@dataclass(frozen=True)
class SyntheticEvent:
    """Structural match for decnet.bus.base.Event — avoids importing the
    bus dependency into the HTTP egress layer."""

    topic: str
    type: str
    ts: str
    id: str
    payload: dict[str, Any]


@dataclass
class DeliveryResult:
    ok: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    attempts: int = 0


def _canonical_ts(value: Any) -> str:
    """Normalize bus-event ts (epoch float / ISO str / None) to ISO-8601 UTC."""
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def _event_id(event: Any) -> str:
    explicit = getattr(event, "id", None)
    if isinstance(explicit, str) and explicit:
        return explicit
    return str(uuid4())


def build_payload(event: Any) -> bytes:
    """Serialize an event to the canonical JSON body sent on the wire.

    Stable key order (`orjson.OPT_SORT_KEYS`) matters because the HMAC
    signs the exact byte sequence — receivers recomputing the hash must
    see the same bytes we did.
    """
    body = {
        "v": _PAYLOAD_VERSION,
        "id": _event_id(event),
        "ts": _canonical_ts(getattr(event, "ts", None)),
        "topic": getattr(event, "topic", ""),
        "type": getattr(event, "type", "") or "",
        "payload": getattr(event, "payload", None) or {},
    }
    return orjson.dumps(body, option=orjson.OPT_SORT_KEYS)


def sign(secret: str, body: bytes) -> str:
    """Return `sha256=<hex>` — the value of the `X-DECNET-Signature` header."""
    digest = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return f"sha256={digest}"


def _build_headers(secret: str, body: bytes, topic: str, event_id: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "User-Agent": "decnet-webhook/1.0",
        "X-DECNET-Signature": sign(secret, body),
        "X-DECNET-Event-Id": event_id,
        "X-DECNET-Event-Topic": topic,
        "X-DECNET-Timestamp": str(int(datetime.now(timezone.utc).timestamp())),
    }


def _should_retry(status_code: int) -> bool:
    """Retry on network error, 5xx, and 429. 4xx (other) is terminal —
    the receiver is telling us the request itself is wrong; retrying
    won't help."""
    if status_code == 429:
        return True
    return status_code >= 500


def _jittered(delay: float) -> float:
    # Jitter is a load-smoothing knob, not a secret — non-crypto random is
    # fine. Using secrets.SystemRandom here would burn entropy for no gain.
    return delay * random.uniform(_JITTER_LOW, _JITTER_HIGH)  # nosec B311


async def deliver(
    sub: dict[str, Any],
    event: Any,
    *,
    retry_schedule: Optional[list[float] | tuple[float, ...]] = None,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
    client: Optional[httpx.AsyncClient] = None,
) -> DeliveryResult:
    """POST *event* to *sub['url']* with HMAC signing and bounded retries.

    *sub* is a subscription row dict (from `repo.get_webhook_subscription`).
    *retry_schedule* is the between-attempt delays in seconds; `None` uses
    the default `(1, 2, 4)`, `[]` disables retries entirely (one attempt).
    *client* allows tests to inject a mock `httpx.AsyncClient`.
    """
    schedule = (
        list(retry_schedule) if retry_schedule is not None
        else list(_DEFAULT_RETRY_SCHEDULE)
    )
    max_attempts = 1 + len(schedule)

    body = build_payload(event)
    topic = getattr(event, "topic", "")
    eid = _event_id(event)
    headers = _build_headers(sub["secret"], body, topic, eid)
    url = sub["url"]

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_s)

    last_status: Optional[int] = None
    last_error: Optional[str] = None
    try:
        for attempt in range(1, max_attempts + 1):
            try:
                resp = await client.post(url, content=body, headers=headers)
                last_status = resp.status_code
                if 200 <= resp.status_code < 300:
                    return DeliveryResult(
                        ok=True, status_code=resp.status_code, attempts=attempt
                    )
                if not _should_retry(resp.status_code):
                    return DeliveryResult(
                        ok=False,
                        status_code=resp.status_code,
                        error=f"non-retryable {resp.status_code}",
                        attempts=attempt,
                    )
                last_error = f"http {resp.status_code}"
            except (httpx.RequestError, asyncio.TimeoutError) as e:
                last_error = f"{type(e).__name__}: {e}"
                last_status = None

            if attempt < max_attempts:
                await asyncio.sleep(_jittered(schedule[attempt - 1]))

        return DeliveryResult(
            ok=False,
            status_code=last_status,
            error=last_error or "exhausted retries",
            attempts=max_attempts,
        )
    finally:
        if owns_client:
            await client.aclose()
