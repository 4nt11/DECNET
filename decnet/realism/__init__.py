"""Realism library — synthetic content + scheduling primitives.

A shared, importable library that produces *plausible* artifacts (file
names, file bodies, email content) and the diurnal/persona machinery
that decides *when* and *for whom* to produce them.

Workers (orchestrator, canary cultivator, future-emailgen-equivalents)
import from here.  This package owns:

* :mod:`decnet.realism.taxonomy` — :class:`ContentClass` enum and the
  :class:`Plan` dataclass that planners emit.
* :mod:`decnet.realism.diurnal` — work-hours gating and a backdated
  ``mtime`` sampler so planted files don't all stamp at wall-clock-now.
* :mod:`decnet.realism.planner` — picks ``(decky, persona, class,
  action, mtime)`` tuples for the orchestrator's tick loop.
* :mod:`decnet.realism.personas` — persona schema (lifted from
  ``orchestrator.emailgen.personas`` in stage 2 of the migration).
* :mod:`decnet.realism.prompts` — prompt builders, one per content
  class, sharing an em-dash-suppression style helper.
* :mod:`decnet.realism.llm` — :class:`LLMBackend` ABC + factory + impl
  subpackage; pluggable text-generation backend.

The library has **no worker, no systemd unit, no CLI of its own** —
it's plain Python that consumers import.  The CLI surface that does
exist (``decnet realism import-personas``) is registered by
:mod:`decnet.cli.realism` after stage 5 of the migration.
"""
