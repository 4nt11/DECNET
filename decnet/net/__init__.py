# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared network helpers.

Currently houses :mod:`decnet.net.http` — the canonical stealth-egress
``httpx.AsyncClient`` factory for outbound calls to 3rd-party services
that should NOT see "DECNET" in their access logs (threat-intel
providers, future TI lookups, etc.).
"""
