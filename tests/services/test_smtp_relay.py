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


def test_smtp_relay_upstream_cfg():
    svc = SMTPRelayService()
    fragment = svc.compose_fragment(
        "test-decky",
        service_cfg={
            "upstream_host": "smtp.sendgrid.net",
            "upstream_port": 587,
            "upstream_user": "apikey",
            "upstream_pass": "SG.secret",
            "probe_limit": 2,
        },
    )
    env = fragment["environment"]
    assert env["SMTP_UPSTREAM_HOST"] == "smtp.sendgrid.net"
    assert env["SMTP_UPSTREAM_PORT"] == "587"
    assert env["SMTP_UPSTREAM_USER"] == "apikey"
    assert env["SMTP_UPSTREAM_PASS"] == "SG.secret"
    assert env["SMTP_PROBE_LIMIT"] == "2"


def test_smtp_relay_upstream_not_set_by_default():
    svc = SMTPRelayService()
    fragment = svc.compose_fragment("test-decky")
    env = fragment["environment"]
    assert "SMTP_UPSTREAM_HOST" not in env
    assert "SMTP_PROBE_LIMIT" not in env


def test_smtp_relay_quarantine_bind_mount():
    """Full-message capture: each decky gets its own host quarantine dir
    bind-mounted into the container, and the in-container path is exposed
    via SMTP_QUARANTINE_DIR so the server can write .eml files."""
    svc = SMTPRelayService()
    fragment = svc.compose_fragment("test-decky")
    volumes = fragment["volumes"]
    assert len(volumes) == 1
    host, container, mode = volumes[0].split(":")
    assert host.endswith("/test-decky/smtp")
    assert container == fragment["environment"]["SMTP_QUARANTINE_DIR"]
    assert mode == "rw"
