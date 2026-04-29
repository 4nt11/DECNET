"""Cross-cutting decky operation endpoints.

These routes apply to both fleet and MazeNET (topology) deckies; the
MazeNET case is selected by passing ``topology_id`` in the request body.

Compare with:

* :mod:`decnet.web.router.fleet` — fleet-only CRUD (deploy, mutate,
  list).
* :mod:`decnet.web.router.topology` — topology-only CRUD.
"""
from __future__ import annotations

from fastapi import APIRouter

from .api_file_drop import router as file_drop_router

deckies_router = APIRouter()
deckies_router.include_router(file_drop_router)

__all__ = ["deckies_router"]
