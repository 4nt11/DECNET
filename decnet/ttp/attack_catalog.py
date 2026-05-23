# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backward-compatible shim over :mod:`decnet.ttp.attack_stix`.

Historically this module exposed a hand-maintained
``TECHNIQUE_NAMES`` dict pinned to ATT&CK Enterprise v15.1. Names now
come from the official STIX 2.1 bundle loaded by
:mod:`decnet.ttp.attack_stix`; this module preserves the
``technique_name(...)`` import path the rest of DECNET reaches for so
call sites in the web router, repo layer, and per-tag inspector keep
working unchanged.

``TECHNIQUE_NAMES`` is **gone**: there is no static dict to import.
Anything that needs an exhaustive list should iterate ATT&CK objects
through :mod:`decnet.ttp.attack_stix`.
"""
from __future__ import annotations

from decnet.ttp.attack_stix import technique_name

__all__ = ["technique_name"]
