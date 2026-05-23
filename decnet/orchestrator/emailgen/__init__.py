# SPDX-License-Identifier: AGPL-3.0-or-later
"""Emailgen — email-specific delivery, scheduling, and threading.

After stage 5 of the realism migration, ``emailgen`` is no longer a
separate worker / systemd unit / CLI subcommand.  It exposes:

* :mod:`decnet.orchestrator.emailgen.scheduler` — the
  ``EmailAction`` shape and the ``pick(repo)`` policy that decides
  which mail decky / sender / recipient / thread an email belongs to.
* :mod:`decnet.orchestrator.emailgen.threads` — RFC 2822 thread chain
  helpers (Message-ID generation, Re: / In-Reply-To bookkeeping).
* :mod:`decnet.orchestrator.emailgen.events` — DB-row + bus-topic
  builders for email events.

The orchestrator's main worker (:mod:`decnet.orchestrator.worker`)
calls into these modules per tick.  LLM glue, persona schema, prompt
builder, and the global persona pool moved to :mod:`decnet.realism`
in stage 2 of the migration; this package keeps only the
email-specific delivery surface.
"""
from __future__ import annotations
