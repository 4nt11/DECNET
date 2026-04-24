"""Webhook subscription CRUD.

Admin-gated management of external-egress webhook subscriptions. The
actual delivery happens in the `decnet webhook` worker, which watches
the DB + bus and POSTs matching events out. This module is the API
surface operators use to configure destinations.

Mounted under `/api/v1/webhooks` by the main api router.
"""
from fastapi import APIRouter

from .api_manage_webhooks import router as manage_webhooks_router
from .api_test_webhook import router as test_webhook_router

webhooks_router = APIRouter(prefix="/webhooks")

webhooks_router.include_router(manage_webhooks_router)
webhooks_router.include_router(test_webhook_router)
