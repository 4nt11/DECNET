"""Asciinema event types.

The on-disk shard format is a list of 3-tuples ``(t, kind, data)`` where
``t`` is seconds since session start (float), ``kind`` is ``'i'`` (input)
or ``'o'`` (output), and ``data`` is the captured bytes decoded as a
Python ``str``. Step 0 ships only the type aliases — Step 1 fills the
parsing helpers and paste-burst detector.
"""
from __future__ import annotations

from typing import Literal, Tuple

EventKind = Literal["i", "o"]
AsciinemaEvent = Tuple[float, EventKind, str]
