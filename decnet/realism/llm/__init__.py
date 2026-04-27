"""LLM backend ABC + factory + impls.

Populated in stage 2 of the realism migration: lifts the existing
``orchestrator.emailgen.llm`` subpackage as-is (``base``, ``factory``,
``impl/ollama``, ``impl/fake``).  Stage 6 adds ``circuit.py`` for
cross-call breaker behaviour.
"""
from __future__ import annotations
