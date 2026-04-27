"""Email driver — pluggable-LLM EML generation + decky-side delivery.

One :class:`EmailAction` becomes one EML written into the mail decky's
configured emailgen spool directory (``/var/spool/decnet-emails/`` by
default).  The IMAP/POP3 service templates read that spool at request
time so attackers see the generated mail in their MUA.

The LLM call goes through :mod:`decnet.orchestrator.emailgen.llm` —
backend-agnostic by construction so swapping Ollama for the Anthropic
API, vLLM, or llama.cpp is a config change, not a driver rewrite.
Output is parsed-and-repaired into a valid EML using
:mod:`email.mime.*`; the worker then ``docker exec``\\s a ``tee`` to
drop the file inside the target container, followed by a
``touch -d <Date>`` so the file's mtime matches the email's RFC 2822
``Date:`` header.

Per CLAUDE.md "no shell strings": every subprocess invocation uses an
argv list, never ``shell=True``.  EML payloads are piped via ``stdin``,
not interpolated into argv.
"""
from __future__ import annotations

import asyncio
import shlex
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Any, Optional

from decnet.logging import get_logger
from decnet.orchestrator.drivers.base import ActivityResult
from decnet.orchestrator.emailgen.llm import LLMBackend, LLMTimeout, get_llm
from decnet.orchestrator.emailgen.prompt import PromptInputs, build as build_prompt
from decnet.orchestrator.emailgen.scheduler import EmailAction
from decnet.orchestrator.emailgen.threads import new_message_id

log = get_logger("orchestrator.email")

_DOCKER = "docker"
# docker-exec wall-clock cap for the per-EML write.
_DOCKER_TIMEOUT = 8.0
# Container suffix for the IMAP service on a mail decky.
_IMAP_CONTAINER_SUFFIX = "-imap"
_POP3_CONTAINER_SUFFIX = "-pop3"
# Spool path inside the container.  Match the IMAP template's stubbed
# IMAP_EMAIL_SEED location once wiring lands; shipping the constant now
# lets that integration land independently.
_SPOOL_DIR = "/var/spool/decnet-emails"


async def _run_capture(
    argv: list[str],
    *,
    stdin_data: Optional[bytes] = None,
    timeout: float = _DOCKER_TIMEOUT,
) -> tuple[int, str, str]:
    """Spawn *argv*, optionally feeding *stdin_data*.  Never raises."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return 127, "", f"argv[0] not found: {exc}"
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(stdin_data), timeout=timeout,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return 124, "", "timeout"
    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )


def _container_for(decky_name: str, services: list[str]) -> str:
    """Pick the IMAP container if present, else POP3.  Names follow the
    ``<decky_name>-<service>`` convention from the service templates."""
    if "imap" in services:
        return f"{decky_name}{_IMAP_CONTAINER_SUFFIX}"
    return f"{decky_name}{_POP3_CONTAINER_SUFFIX}"


def _parse_subject_and_body(ollama_output: str) -> tuple[str, str]:
    """Split LLM output into (subject, body).

    The prompt asks for ``Subject: <subject>\\n\\n<body>``.  When the
    model misbehaves (e.g. wraps in markdown fences or skips the
    Subject line), fall back to a generic subject and treat the whole
    output as body.  Never raises.
    """
    text = ollama_output.strip()
    # Strip code fences if the model wrapped output.
    if text.startswith("```"):
        nl = text.find("\n")
        if nl > 0:
            text = text[nl + 1:]
        if text.endswith("```"):
            text = text[: -3]
        text = text.strip()
    lines = text.splitlines()
    if lines and lines[0].lower().startswith("subject:"):
        subject = lines[0].split(":", 1)[1].strip()
        # Drop the (possibly empty) blank line after Subject.
        body_lines = lines[1:]
        if body_lines and not body_lines[0].strip():
            body_lines = body_lines[1:]
        body = "\n".join(body_lines).strip()
        if not subject:
            subject = "Business Communication"
        return subject, body
    return "Business Communication", text


def _build_eml(
    *,
    sender_name: str,
    sender_email: str,
    recipient_name: str,
    recipient_email: str,
    subject: str,
    body: str,
    message_id: str,
    in_reply_to: Optional[str],
    references: str,
    ts: datetime,
) -> bytes:
    """Assemble a valid plain-text RFC 2822 EML."""
    msg = MIMEText(body, "plain", "utf-8")
    msg["From"] = f"{sender_name} <{sender_email}>"
    msg["To"] = f"{recipient_name} <{recipient_email}>"
    msg["Subject"] = subject
    msg["Date"] = formatdate(ts.timestamp(), localtime=False)
    msg["Message-ID"] = message_id
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    msg["MIME-Version"] = "1.0"
    return msg.as_bytes()


class EmailDriver:
    """Concrete driver for :class:`EmailAction`.

    Stateless across calls — the LLM backend is constructed once at
    init time (or injected for tests).  The driver itself does *not*
    know about the bus or DB; it returns an :class:`ActivityResult`
    that the worker pipes onward.
    """

    def __init__(
        self,
        *,
        llm: Optional[LLMBackend] = None,
        model: Optional[str] = None,
        spool_dir: str = _SPOOL_DIR,
    ) -> None:
        # *llm* takes precedence so tests can inject a FakeBackend
        # without env-var trickery.  *model* lets the worker honour
        # ``--model`` from the CLI without each backend needing to know
        # about CLI flags.
        self._llm = llm if llm is not None else get_llm(model=model)
        self.spool_dir = spool_dir

    @property
    def model(self) -> str:
        """Convenience accessor for telemetry / logging."""
        return self._llm.model

    async def run(self, action: EmailAction) -> ActivityResult:
        return await self._run_email(action)

    async def _run_email(self, action: EmailAction) -> ActivityResult:
        prompt, mannerisms_used = build_prompt(
            PromptInputs(
                sender=action.sender,
                recipient=action.recipient,
                context_hint=action.context_hint,
                parent_subject=action.subject_hint,
                parent_excerpt=action.parent_excerpt,
            )
        )
        try:
            llm_result = await self._llm.generate(prompt)
        except LLMTimeout as exc:
            log.warning("emailgen llm timeout model=%s: %s", self._llm.model, exc)
            return ActivityResult(
                success=False,
                payload={
                    "stage": "llm",
                    "error": "timeout",
                    "model": self._llm.model,
                    "thread_id": action.thread_id,
                },
            )

        gen_ms = llm_result.latency_ms
        if not llm_result.success or not llm_result.text.strip():
            log.warning(
                "emailgen llm produced no usable output model=%s extra=%r",
                self._llm.model, llm_result.extra,
            )
            return ActivityResult(
                success=False,
                payload={
                    "stage": "llm",
                    "model": self._llm.model,
                    "generation_ms": gen_ms,
                    "thread_id": action.thread_id,
                    **{
                        k: v for k, v in llm_result.extra.items()
                        if k in ("rc", "stderr")
                    },
                },
            )

        subject, body = _parse_subject_and_body(llm_result.text)
        message_id = new_message_id(action.sender.email.split("@", 1)[1])
        ts = datetime.now(timezone.utc)
        eml_bytes = _build_eml(
            sender_name=action.sender.name,
            sender_email=action.sender.email,
            recipient_name=action.recipient.name,
            recipient_email=action.recipient.email,
            subject=subject,
            body=body,
            message_id=message_id,
            in_reply_to=action.parent_message_id,
            references=action.references,
            ts=ts,
        )

        # Drop the EML into the mail decky's spool dir over docker exec.
        # File path: <spool>/<thread_id>/<uuid-from-message-id>.eml.
        # Per-thread sub-directory keeps `ls` in the spool readable by
        # operators inspecting the running decoy.
        eml_filename = message_id.strip("<>").replace("@", "_at_") + ".eml"
        eml_dir = f"{self.spool_dir.rstrip('/')}/{action.thread_id}"
        eml_path = f"{eml_dir}/{eml_filename}"
        container = _container_for(
            action.mail_decky_name, list(action.mail_decky_services),
        )
        # Stamp the file's mtime + atime to match the EML's Date: header
        # so an attacker `ls -lt`'ing the spool doesn't see a wall of
        # files all created within the worker's tick window — the cluster
        # itself is a tell.  ``touch -d`` on GNU coreutils accepts RFC
        # 2822 dates directly via the same formatdate() string we wrote
        # into the header, so no extra parsing on the container side.
        eml_date_header = formatdate(ts.timestamp(), localtime=False)
        sh_cmd = (
            f"mkdir -p {shlex.quote(eml_dir)} && "
            f"tee {shlex.quote(eml_path)} >/dev/null && "
            f"touch -d {shlex.quote(eml_date_header)} {shlex.quote(eml_path)}"
        )
        argv = [_DOCKER, "exec", "-i", container, "sh", "-c", sh_cmd]
        rc2, _stdout2, stderr2 = await _run_capture(
            argv, stdin_data=eml_bytes, timeout=_DOCKER_TIMEOUT,
        )
        success = rc2 == 0
        payload: dict[str, Any] = {
            "stage": "delivered" if success else "delivery",
            "model": self.model,
            "generation_ms": gen_ms,
            "bytes": len(eml_bytes),
            "thread_id": action.thread_id,
            "message_id": message_id,
            "subject": subject,
            "language": action.sender.language or "en",
            "mannerisms_used": mannerisms_used,
            "is_reply": action.is_reply,
            "container": container,
            "eml_path": eml_path,
            "rc": rc2,
            "stderr": stderr2.strip()[:256] if not success else None,
        }
        if not success:
            log.warning(
                "emailgen delivery failed container=%s rc=%d stderr=%r",
                container, rc2, stderr2[:200],
            )
        return ActivityResult(success=success, payload=payload)
