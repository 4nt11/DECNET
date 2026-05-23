# SPDX-License-Identifier: AGPL-3.0-or-later
"""DECNET worker agent — runs on every SWARM worker host.

Exposes an mTLS-protected FastAPI service the master's SWARM controller
calls to deploy, mutate, and tear down deckies locally.  The agent reuses
the existing `decnet.engine.deployer` code path unchanged, so a worker runs
deckies the same way `decnet deploy --mode unihost` does today.
"""
