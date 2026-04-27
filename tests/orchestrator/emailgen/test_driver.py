"""EmailDriver: stub the Ollama subprocess + docker exec; verify EML
parse-and-repair and payload metadata."""
from __future__ import annotations

import pytest

from decnet.orchestrator.drivers import email as email_driver
from decnet.orchestrator.emailgen.personas import EmailPersona
from decnet.orchestrator.emailgen.scheduler import EmailAction


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
    """Stub both subprocess calls (ollama + docker exec) as success."""
    calls: list[list[str]] = []

    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        calls.append(list(argv))
        if argv[0] == "ollama":
            return 0, "Subject: Q3 budget\n\nHi Sarah,\nNumbers attached.\n", ""
        # docker exec
        return 0, "", ""

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    drv = email_driver.EmailDriver(model="llama3.1", ollama_timeout=1.0)
    result = await drv.run(_action())
    assert result.success is True
    assert result.payload["model"] == "llama3.1"
    assert result.payload["subject"] == "Q3 budget"
    assert result.payload["language"] == "en"
    assert result.payload["mannerisms_used"]
    assert result.payload["message_id"].startswith("<")
    assert result.payload["eml_path"].endswith(".eml")
    assert result.payload["container"] == "mailhost-imap"
    # Two subprocess calls: ollama, then docker exec.
    assert calls[0][0] == "ollama"
    assert calls[1][0] == "docker"


@pytest.mark.asyncio
async def test_driver_run_ollama_failure_short_circuits(monkeypatch):
    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        if argv[0] == "ollama":
            return 1, "", "ollama: model not found"
        return 0, "", ""

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    drv = email_driver.EmailDriver()
    result = await drv.run(_action())
    assert result.success is False
    assert result.payload["stage"] == "ollama"
    assert "model not found" in result.payload["stderr"]


@pytest.mark.asyncio
async def test_driver_run_delivery_failure(monkeypatch):
    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        if argv[0] == "ollama":
            return 0, "Subject: hi\n\nbody\n", ""
        return 1, "", "no such container"

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    drv = email_driver.EmailDriver()
    result = await drv.run(_action())
    assert result.success is False
    assert result.payload["stage"] == "delivery"
    assert "no such container" in result.payload["stderr"]
