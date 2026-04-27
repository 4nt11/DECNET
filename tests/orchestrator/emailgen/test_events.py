"""events.to_row / topic_for / event_type_for."""
from __future__ import annotations

from decnet.bus import topics as _topics
from decnet.orchestrator.drivers.base import ActivityResult
from decnet.orchestrator.emailgen import events
from decnet.orchestrator.emailgen.personas import EmailPersona
from decnet.orchestrator.emailgen.scheduler import EmailAction


def _persona(email="john@corp.com"):
    return EmailPersona(
        name="John", email=email, role="COO", tone="formal",
        mannerisms=[], language="en",
    )


def _action():
    return EmailAction(
        mail_decky_uuid="d1",
        mail_decky_name="mailhost",
        mail_decky_services=("imap",),
        sender=_persona(),
        recipient=_persona(email="sarah@corp.com"),
        thread_id="thr1",
        parent_message_id=None,
        references="",
        subject_hint=None,
        parent_excerpt=None,
        context_hint="Q3 budget",
        is_reply=False,
    )


def test_to_row_pulls_message_id_subject_from_payload():
    res = ActivityResult(
        success=True,
        payload={
            "message_id": "<m1@corp.com>",
            "subject": "Q3 budget",
            "language": "en",
            "eml_path": "/var/spool/decnet-emails/thr1/m1.eml",
            "model": "llama3.1",
        },
    )
    row = events.to_row(_action(), res)
    assert row["mail_decky_uuid"] == "d1"
    assert row["thread_id"] == "thr1"
    assert row["message_id"] == "<m1@corp.com>"
    assert row["subject"] == "Q3 budget"
    assert row["sender_email"] == "john@corp.com"
    assert row["recipient_email"] == "sarah@corp.com"
    assert row["language"] == "en"
    assert row["eml_path"].endswith(".eml")
    assert row["success"] is True
    assert row["payload"]["model"] == "llama3.1"


def test_to_row_falls_back_to_persona_language():
    res = ActivityResult(success=True, payload={})
    row = events.to_row(_action(), res)
    assert row["language"] == "en"
    assert row["message_id"] == ""


def test_topic_for_uses_orchestrator_email_root():
    topic = events.topic_for(_action())
    assert topic == f"orchestrator.{_topics.ORCHESTRATOR_EMAIL}.d1"


def test_event_type_for_returns_email_constant():
    assert events.event_type_for(_action()) == _topics.ORCHESTRATOR_EMAIL
