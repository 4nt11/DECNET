"""Content classes and the :class:`Plan` dataclass.

The planner emits :class:`Plan` instances; drivers consume them.  Every
planted artifact (inert noise file, email, callback-bearing canary)
maps to exactly one :class:`ContentClass` member, which is what the
realism engine uses to dispatch to the right namer / body generator /
prompt template.

Categories:

* **User content** (LLM-eligible): ``note``, ``todo``, ``draft``,
  ``script``.  Created by humans on workstations; LLM enrichment makes
  them feel lived-in.
* **System content** (deterministic only): ``log_cron``, ``log_daemon``,
  ``cache_tmp``.  These are *supposed* to look formulaic — that's how
  cron/journald actually write them.  LLM here would harm realism.
* **Email** (LLM-eligible): one persona writing to another.  Owned by
  the email driver, not the file driver.
* **Canary** (deterministic, callback-bearing): one ``canary_*`` member
  per :mod:`decnet.canary.factory.KNOWN_GENERATORS` entry.  Picked
  rarely and rate-limited per-decky by the planner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Literal, Optional


class ContentClass(StrEnum):
    """The kind of artifact a planner has decided to produce.

    Values are stable over the wire — they're persisted on
    ``synthetic_files.content_class`` and used as bus-event discriminants
    so renaming a member is a schema change.  Add new members at the
    bottom; never reorder.
    """

    # User-generated, LLM-enrichable
    NOTE = "note"
    TODO = "todo"
    DRAFT = "draft"
    SCRIPT = "script"

    # System-generated, template-only (LLM would harm realism)
    LOG_CRON = "log_cron"
    LOG_DAEMON = "log_daemon"
    CACHE_TMP = "cache_tmp"

    # Email — owned by the email driver, planner picks the action shape
    EMAIL = "email"

    # Callback-bearing — provided by decnet.canary.cultivator at
    # dispatch time, not by realism.bodies.  One member per generator
    # in decnet.canary.factory.KNOWN_GENERATORS.
    CANARY_AWS_CREDS = "canary_aws_creds"
    CANARY_ENV_FILE = "canary_env_file"
    CANARY_GIT_CONFIG = "canary_git_config"
    CANARY_SSH_KEY = "canary_ssh_key"
    CANARY_HONEYDOC = "canary_honeydoc"
    CANARY_HONEYDOC_DOCX = "canary_honeydoc_docx"
    CANARY_HONEYDOC_PDF = "canary_honeydoc_pdf"
    CANARY_MYSQL_DUMP = "canary_mysql_dump"
    CANARY_FINGERPRINT_HTML = "canary_fingerprint_html"
    CANARY_FINGERPRINT_SVG = "canary_fingerprint_svg"

    def is_canary(self) -> bool:
        return self.value.startswith("canary_")

    def is_user_class(self) -> bool:
        return self in (
            ContentClass.NOTE,
            ContentClass.TODO,
            ContentClass.DRAFT,
            ContentClass.SCRIPT,
        )

    def is_system_class(self) -> bool:
        return self in (
            ContentClass.LOG_CRON,
            ContentClass.LOG_DAEMON,
            ContentClass.CACHE_TMP,
        )


PlanAction = Literal["create", "edit", "rotate"]


@dataclass(frozen=True)
class Plan:
    """One realism decision: what to do, where, as whom, when.

    Frozen so the planner can return the same instance to multiple
    consumers (e.g. orchestrator dispatcher + canary cultivator) without
    them stomping each other's view of the schedule.

    Attributes
    ----------
    decky_uuid, decky_name :
        Target decky.  Both carried so drivers don't need a repo
        round-trip to map UUID → container name.
    persona :
        Persona name (``EmailPersona.name``) — this is the user the
        action is "performed by."  Sampled from the topology's persona
        pool at plan time.
    content_class :
        :class:`ContentClass` member.  Drives namer/body dispatch.
    action :
        ``"create"`` mints a new artifact; ``"edit"`` mutates a
        previously-planted one (read-modify-write — requires
        :attr:`previous_body`); ``"rotate"`` is the log-rotation shape
        (``cron.log`` → ``cron.log.1``).
    target_path :
        Absolute container-side path the driver should write.  Already
        persona-aware (e.g. ``/home/admin/TODO.md`` not
        ``/home/{user}/TODO.md``).
    mtime :
        Backdated wall-clock the driver should ``touch -d`` after
        writing.  Sampled by :func:`decnet.realism.diurnal.sample_mtime`
        so files don't all stamp at the moment they were created.
    body_hint :
        Deterministic body the engine has *already* committed to.  LLM
        enrichment, when enabled, may replace it but on timeout/failure
        the driver falls back to this — so the tick never blocks
        unboundedly.
    previous_body :
        Required for ``action="edit"``.  The bytes the driver read back
        from the decky before mutating; passed to
        :func:`decnet.realism.bodies.next_iteration`.
    """

    decky_uuid: str
    decky_name: str
    persona: str
    content_class: ContentClass
    action: PlanAction
    target_path: str
    mtime: datetime
    body_hint: Optional[str] = None
    previous_body: Optional[str] = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.action == "edit" and self.previous_body is None:
            # Belt-and-braces: the planner produced an edit Plan without
            # the prior body. The driver would either have to make a
            # second docker exec to re-read or silently degrade to
            # create. Both bad. Fail loudly at construction.
            raise ValueError(
                "Plan.action='edit' requires previous_body; got None"
            )
