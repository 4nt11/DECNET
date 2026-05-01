"""``decnet canary`` worker — HTTP + DNS callback receivers.

Two surfaces, one process:

* **HTTP** — a tiny FastAPI app on its own port (default 8088).  The
  only useful route is ``GET /c/{slug}`` which looks up the slug in
  the canary token table, persists a :class:`CanaryTrigger` row,
  publishes ``canary.<token_id>.triggered`` on the bus, and returns
  a 1×1 transparent GIF (or 204 if the client's ``Accept`` doesn't
  list any image type).
* **DNS** — an authoritative UDP server (default 5353 if non-root,
  53 if root) for ``*.<canary_zone>``.  Same lookup + persist +
  publish flow, plus a sinkhole A record so the attacker's resolver
  doesn't loop on NXDOMAIN.

Both surfaces are **stealth** by policy
(:mod:`feedback_stealth`): no DECNET strings in headers / banners /
error pages.  The HTTP app strips the default ``Server: uvicorn``
header in middleware; FastAPI's docs/openapi UI is disabled because
discovering them would tip off the attacker that this is a honeypot.

The worker is supervised by its own systemd unit
(``decnet-canary.service``); like every other DECNET worker, it
crashes loudly rather than masking failures.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, Response

from decnet.bus import topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.canary.dns_server import CanaryDNSProtocol, DNSQuery
from decnet.logging import get_logger
from decnet.web.db.factory import get_repository
from decnet.web.db.repository import BaseRepository

log = get_logger("canary.worker")

# 1×1 transparent GIF — public-domain canonical bytes.  Returning the
# same image every time is fine: the body has no information the
# attacker shouldn't see, and image clients cache it.
_TRANSPARENT_GIF = bytes.fromhex(
    "47494638396101000100800100000000ffffff21f90401000001002c00000000010001000002024401003b"
)


def _http_base() -> str:
    return os.environ.get("DECNET_CANARY_HTTP_BASE", "http://localhost:8088").rstrip("/")


def _dns_zone() -> str:
    return os.environ.get("DECNET_CANARY_DNS_ZONE", "").strip(".").lower()


def _http_port() -> int:
    return int(os.environ.get("DECNET_CANARY_HTTP_PORT", "8088"))


def _dns_port() -> int:
    # Default 5353 (mDNS-ish, non-privileged) — operators pin :53 via
    # NAT or a CAP_NET_BIND_SERVICE-enabled unit.
    return int(os.environ.get("DECNET_CANARY_DNS_PORT", "5353"))


def _dns_bind() -> str:
    return os.environ.get("DECNET_CANARY_DNS_BIND", "0.0.0.0")  # nosec B104 — attacker-facing decoy listener, internet exposure is the design


def _http_bind() -> str:
    return os.environ.get("DECNET_CANARY_HTTP_BIND", "0.0.0.0")  # nosec B104 — same rationale


# ---------------------------- HTTP surface --------------------------------


def _build_app(repo: BaseRepository, bus: BaseBus) -> FastAPI:
    """Construct the FastAPI app.

    Disables docs / openapi / redoc — operators query the canary
    surface via the *main* DECNET API, never directly.  Anyone hitting
    these paths is either misconfigured or scanning for a honeypot.
    """
    app = FastAPI(
        title="",  # don't leak "DECNET" in OpenAPI
        docs_url=None, redoc_url=None, openapi_url=None,
    )

    @app.middleware("http")
    async def _stealth_headers(request: Request, call_next):
        response: Response = await call_next(request)
        # Strip the uvicorn / starlette banner; replace with a
        # generic Server line that matches what most CDNs return.
        response.headers["Server"] = "nginx"
        # Don't leak request id / process id headers.
        if "x-process-time" in response.headers:
            del response.headers["x-process-time"]
        return response

    @app.get("/c/{slug}")
    async def callback(slug: str, request: Request) -> Response:
        await _record_hit(
            repo, bus,
            slug=slug,
            src_ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            request_path=str(request.url.path),
            dns_qname=None,
            raw_headers=dict(request.headers),
        )
        # Always 200 with a tiny image so the attacker's client sees
        # a "success" — same return regardless of whether the slug is
        # known. Stealth: do NOT distinguish unknown vs known via
        # status code or response body.
        return Response(content=_TRANSPARENT_GIF, media_type="image/gif")

    @app.get("/")
    async def root() -> Response:
        # Bare root returns a generic 404. The decoy posture: pretend
        # to be an empty static-file host that just happens to resolve
        # /c/<slug> when it matches.
        return Response(status_code=404)

    return app


def _client_ip(request: Request) -> str:
    # Honor X-Forwarded-For if the operator deployed behind a reverse
    # proxy. Take the leftmost address in the chain; everything after
    # is upstream-proxy noise.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    if request.client:
        return request.client.host
    return "0.0.0.0"  # nosec B104 — sentinel for "unknown remote"


# ---------------------------- shared persistence -------------------------


async def _record_hit(
    repo: BaseRepository,
    bus: BaseBus,
    *,
    slug: str,
    src_ip: str,
    user_agent: Optional[str],
    request_path: Optional[str],
    dns_qname: Optional[str],
    raw_headers: Optional[dict],
) -> None:
    """Resolve slug -> token, persist a trigger, publish on the bus.

    Unknown slugs are silently swallowed: returning the same response
    for known and unknown slugs is the stealth posture, and persisting
    every random scan would clutter the DB.
    """
    token = await repo.get_canary_token_by_slug(slug)
    if token is None:
        return
    trigger_id = await repo.record_canary_trigger({
        "token_uuid": token["uuid"],
        "occurred_at": datetime.now(timezone.utc),
        "src_ip": src_ip,
        "user_agent": user_agent,
        "request_path": request_path,
        "dns_qname": dns_qname,
        "raw_headers": raw_headers or {},
    })
    try:
        await bus.publish(
            topics.canary(token["uuid"], topics.CANARY_TRIGGERED),
            {
                "token_id": token["uuid"],
                "trigger_id": trigger_id,
                "decky_name": token["decky_name"],
                "src_ip": src_ip,
                "user_agent": user_agent,
                "request_path": request_path,
                "dns_qname": dns_qname,
            },
        )
    except Exception as e:  # noqa: BLE001 — best effort
        log.warning("canary.triggered publish failed slug=%s err=%s", slug, e)


# ---------------------------- DNS surface --------------------------------


async def _start_dns_server(
    repo: BaseRepository, bus: BaseBus, *, loop: asyncio.AbstractEventLoop,
) -> Optional[asyncio.DatagramTransport]:
    zone = _dns_zone()
    if not zone:
        log.info("canary.dns disabled (DECNET_CANARY_DNS_ZONE unset)")
        return None

    async def _hook(slug: str, query: DNSQuery, src_ip: str) -> None:
        await _record_hit(
            repo, bus,
            slug=slug, src_ip=src_ip, user_agent=None,
            request_path=None, dns_qname=query.qname,
            raw_headers=None,
        )

    transport, _proto = await loop.create_datagram_endpoint(
        lambda: CanaryDNSProtocol(zone, _hook),
        local_addr=(_dns_bind(), _dns_port()),
    )
    log.info("canary.dns listening zone=%s port=%d", zone, _dns_port())
    return transport


# ---------------------------- entry point --------------------------------


async def run() -> None:
    """Worker entry point — kicked off by ``decnet canary``."""
    import uvicorn

    repo = get_repository()
    await repo.initialize()
    bus = get_bus()
    await bus.connect()

    app = _build_app(repo, bus)
    config = uvicorn.Config(
        app,
        host=_http_bind(),
        port=_http_port(),
        log_level="warning",
        access_log=False,  # stealth: no per-request lines
        server_header=False,  # we set Server: nginx in middleware
    )
    server = uvicorn.Server(config)
    loop = asyncio.get_running_loop()
    dns_transport = await _start_dns_server(repo, bus, loop=loop)
    try:
        await server.serve()
    finally:
        if dns_transport is not None:
            dns_transport.close()
        await bus.close()


def main() -> None:
    """CLI entry point — synchronous wrapper for ``asyncio.run``."""
    asyncio.run(run())
