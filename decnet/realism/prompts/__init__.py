"""Prompt builders for LLM-enriched content.

* :mod:`decnet.realism.prompts.email` — corporate-email body builder.

Stage 6 of the realism migration adds ``filebody.py``, ``filename.py``,
and a ``_style.py`` helper so em-dash suppression sits in one place
across email + file-class prompts.
"""
from __future__ import annotations
