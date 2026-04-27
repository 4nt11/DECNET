"""EmailDriver: inject a fake LLM backend + stub docker exec; verify
EML parse-and-repair and payload metadata."""
from __future__ import annotations

import pytest

from decnet.orchestrator.drivers import email as email_driver
from decnet.orchestrator.emailgen.scheduler import EmailAction
from decnet.realism.llm.base import LLMResult, LLMTimeout
from decnet.realism.llm.impl.fake import FakeBackend
from decnet.realism.personas import EmailPersona


class _RaisingBackend:
    """Async stub that raises LLMTimeout on every call."""
    model = "stuck-model"
    timeout = 0.1

    async def generate(self, prompt: str) -> LLMResult:    # noqa: ARG002
        raise LLMTimeout("stuck")


class _FailingBackend:
    """Async stub that returns success=False."""
    model = "broken-model"
    timeout = 1.0

    async def generate(self, prompt: str) -> LLMResult:    # noqa: ARG002
        return LLMResult(
            success=False,
            text="",
            model=self.model,
            latency_ms=5,
            extra={"rc": 1, "stderr": "model not found"},
        )


def _persona(name="John", email="john@corp.com"):
    return EmailPersona(
        name=name,
        email=email,
        role="COO",
        tone="formal",
        mannerisms=["uses 'Best regards'"],
        language="en",
    )


def _action(is_reply=False):
    return EmailAction(
        mail_decky_uuid="d1",
        mail_decky_name="mailhost",
        mail_decky_services=("imap",),
        sender=_persona(),
        recipient=_persona(name="Sarah", email="sarah@corp.com"),
        thread_id="thr1",
        parent_message_id="<old@corp.com>" if is_reply else None,
        references="" if not is_reply else "<old@corp.com>",
        subject_hint="Re: budget" if is_reply else None,
        parent_excerpt=None,
        context_hint="Q3 budget" if not is_reply else "Re: budget",
        is_reply=is_reply,
    )


def test_parse_subject_and_body_extracts_subject_line():
    out = "Subject: Quick update\n\nHi Sarah,\nNumbers attached.\n"
    subject, body = email_driver._parse_subject_and_body(out)
    assert subject == "Quick update"
    assert body.startswith("Hi Sarah")


def test_parse_subject_strips_code_fences():
    out = "```\nSubject: Quick update\n\nbody\n```\n"
    subject, body = email_driver._parse_subject_and_body(out)
    assert subject == "Quick update"
    assert body == "body"


def test_parse_subject_falls_back_when_missing():
    out = "Just a body, no subject\n"
    subject, body = email_driver._parse_subject_and_body(out)
    assert subject == "Business Communication"
    assert "body" in body.lower()


def test_build_eml_includes_required_headers():
    from datetime import datetime, timezone

    eml = email_driver._build_eml(
        sender_name="John",
        sender_email="john@corp.com",
        recipient_name="Sarah",
        recipient_email="sarah@corp.com",
        subject="Q3 budget",
        body="Hi Sarah,\nNumbers attached.",
        message_id="<m1@corp.com>",
        in_reply_to=None,
        references="",
        ts=datetime(2026, 4, 26, 12, 0, tzinfo=timezone.utc),
    ).decode("utf-8")
    assert "From: John <john@corp.com>" in eml
    assert "To: Sarah <sarah@corp.com>" in eml
    assert "Subject: Q3 budget" in eml
    assert "Message-ID: <m1@corp.com>" in eml
    assert "MIME-Version: 1.0" in eml
    assert "In-Reply-To" not in eml


def test_build_eml_threads_carry_in_reply_to_and_references():
    from datetime import datetime, timezone

    eml = email_driver._build_eml(
        sender_name="John",
        sender_email="john@corp.com",
        recipient_name="Sarah",
        recipient_email="sarah@corp.com",
        subject="Re: Q3",
        body="Following up.",
        message_id="<m2@corp.com>",
        in_reply_to="<m1@corp.com>",
        references="<m1@corp.com>",
        ts=datetime(2026, 4, 26, 12, 0, tzinfo=timezone.utc),
    ).decode("utf-8")
    assert "In-Reply-To: <m1@corp.com>" in eml
    assert "References: <m1@corp.com>" in eml


def test_container_for_imap_takes_priority():
    assert email_driver._container_for("mailhost", ["imap", "pop3"]) == "mailhost-imap"


def test_container_for_pop3_only():
    assert email_driver._container_for("mailhost", ["pop3"]) == "mailhost-pop3"


@pytest.mark.asyncio
async def test_driver_run_success_path(monkeypatch):
    """Inject a FakeBackend + stub docker exec; success end-to-end."""
    docker_calls: list[list[str]] = []

    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        docker_calls.append(list(argv))
        return 0, "", ""

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    llm = FakeBackend(
        model="llama3.1",
        output="Subject: Q3 budget\n\nHi Sarah,\nNumbers attached.\n",
    )
    drv = email_driver.EmailDriver(llm=llm)
    result = await drv.run(_action())
    assert result.success is True
    assert result.payload["model"] == "llama3.1"
    assert result.payload["subject"] == "Q3 budget"
    assert result.payload["language"] == "en"
    assert result.payload["mannerisms_used"]
    assert result.payload["message_id"].startswith("<")
    assert result.payload["eml_path"].endswith(".eml")
    assert result.payload["container"] == "mailhost-imap"
    # Only docker exec is shelled out now — the LLM call is in-process
    # via the FakeBackend.
    assert len(docker_calls) == 1
    assert docker_calls[0][0] == "docker"
    docker_sh = docker_calls[0][-1]
    assert "touch -d" in docker_sh
    assert "tee" in docker_sh
    assert docker_sh.index("tee") < docker_sh.index("touch -d")


@pytest.mark.asyncio
async def test_driver_run_llm_failure_short_circuits(monkeypatch):
    """When the backend reports success=False, no docker exec should fire."""
    docker_called = False

    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        nonlocal docker_called
        docker_called = True
        return 0, "", ""

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    drv = email_driver.EmailDriver(llm=_FailingBackend())
    result = await drv.run(_action())
    assert result.success is False
    assert result.payload["stage"] == "llm"
    assert "stderr" in result.payload
    assert "model not found" in result.payload["stderr"]
    assert docker_called is False


@pytest.mark.asyncio
async def test_driver_run_llm_timeout_reported_distinctly(monkeypatch):
    drv = email_driver.EmailDriver(llm=_RaisingBackend())
    result = await drv.run(_action())
    assert result.success is False
    assert result.payload["stage"] == "llm"
    assert result.payload["error"] == "timeout"


@pytest.mark.asyncio
async def test_driver_run_delivery_failure(monkeypatch):
    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        return 1, "", "no such container"

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    drv = email_driver.EmailDriver(
        llm=FakeBackend(output="Subject: hi\n\nbody\n"),
    )
    result = await drv.run(_action())
    assert result.success is False
    assert result.payload["stage"] == "delivery"
    assert "no such container" in result.payload["stderr"]
