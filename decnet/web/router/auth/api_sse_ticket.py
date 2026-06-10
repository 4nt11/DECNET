# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mint a single-use, short-lived SSE stream ticket (V3.1.1).

EventSource cannot send an Authorization header, so SSE auth used to ride in
``?token=<JWT>`` — leaking the full-lifetime bearer into access/proxy logs,
browser history, and Referer. This endpoint lets an already-authenticated
client (gated by the NORMAL header JWT via ``require_viewer``) exchange that
header credential for an opaque ``secrets.token_urlsafe(32)`` ticket, valid for
60s and single-use, which it then passes to the SSE endpoint as ``?ticket=``.
The JWT never appears in any URL.

The ticket store lives in-process (decnet.web.dependencies); multi-process
deployments need a shared store — out of scope, see that module's note.
"""
from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import mint_sse_ticket, require_viewer, _SSE_TICKET_TTL
from decnet.web.db.models.auth import SSETicketResponse

router = APIRouter()


@router.post(
    "/auth/sse-ticket",
    tags=["Authentication"],
    response_model=SSETicketResponse,
    responses={
        400: {"description": "Malformed request body"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Authenticated but not authorized"},
    },
)
@_traced("api.sse_ticket")
async def mint_stream_ticket(user: dict = Depends(require_viewer)) -> SSETicketResponse:
    """Exchange the presented header JWT for a single-use 60s SSE ticket bound to
    this user's uuid + role. Any authenticated (viewer or admin) user may mint."""
    ticket = mint_sse_ticket(user["uuid"], user["role"])
    return SSETicketResponse(ticket=ticket, expires_in=int(_SSE_TICKET_TTL))
