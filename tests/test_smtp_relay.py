"""
Tests for SMTP Relay service.
"""

from decnet.services.smtp_relay import SMTPRelayService

def test_smtp_relay_compose_fragment():
    svc = SMTPRelayService()
    fragment = svc.compose_fragment("test-decky", log_target="log-server")

    assert fragment["container_name"] == "test-decky-smtp_relay"
    assert fragment["environment"]["SMTP_OPEN_RELAY"] == "1"
    assert fragment["environment"]["LOG_TARGET"] == "log-server"

def test_smtp_relay_custom_cfg():
    svc = SMTPRelayService()
    fragment = svc.compose_fragment(
        "test-decky",
        service_cfg={"banner": "Welcome", "mta": "Postfix"}
    )
    assert fragment["environment"]["SMTP_BANNER"] == "Welcome"
    assert fragment["environment"]["SMTP_MTA"] == "Postfix"

def test_smtp_relay_dockerfile_context():
    svc = SMTPRelayService()
    ctx = svc.dockerfile_context()
    assert ctx.name == "smtp"
    assert ctx.is_dir()
