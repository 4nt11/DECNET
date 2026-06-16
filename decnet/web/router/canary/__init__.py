# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canary tokens — operator-facing CRUD.

Mounted under ``/api/v1/canary``.  Covers:

* ``POST /blobs`` — upload an artifact (multipart);
  ``GET /blobs``, ``DELETE /blobs/{id}`` — listing + cleanup
* ``POST /tokens`` — generate + plant a token on a target decky;
  ``GET /tokens``, ``GET /tokens/{id}``, ``DELETE /tokens/{id}``
  — listing + detail + revoke
* ``GET /tokens/{id}/preview`` — instrumented bytes for sanity-check
* ``GET /tokens/{id}/triggers`` — paged callback log

The ``decnet canary`` worker runs the ATTACKER-facing surface (HTTP
slug + DNS); this module is the OPERATOR-facing surface only.
"""
from fastapi import APIRouter

from .api_blobs import router as blobs_router
from .api_tokens import router as tokens_router

canary_router = APIRouter(prefix="/canary")
canary_router.include_router(blobs_router)
canary_router.include_router(tokens_router)
