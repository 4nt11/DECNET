"""Schema-driven service config: descriptors, validation, compose round-trip."""

import base64

import pytest

from decnet.services.base import (
    BaseService,
    ConfigValidationError,
    ServiceConfigField,
)
from decnet.services.http import HTTPService
from decnet.services.https import HTTPSService
from decnet.services.mysql import MySQLService
from decnet.services.rdp import RDPService
from decnet.services.redis import RedisService
from decnet.services.smtp import SMTPService
from decnet.services.smtp_relay import SMTPRelayService
from decnet.services.ssh import SSHService
from decnet.services.telnet import TelnetService


class _Dummy(BaseService):
    name = "dummy"
    ports = [9999]
    default_image = "alpine"
    config_schema = [
        ServiceConfigField(key="text", label="Text", type="string"),
        ServiceConfigField(key="port", label="Port", type="int", default=8080),
        ServiceConfigField(key="enabled", label="Enabled", type="bool"),
        ServiceConfigField(
            key="mode",
            label="Mode",
            type="enum",
            enum=["a", "b", "c"],
        ),
        ServiceConfigField(key="body", label="Body", type="textarea"),
        ServiceConfigField(key="pw", label="Pw", type="password", secret=True),
    ]

    def compose_fragment(self, decky_name, log_target=None, service_cfg=None):
        return {"environment": dict(service_cfg or {})}


def test_unknown_keys_are_dropped():
    cfg = _Dummy().validate_cfg({"text": "hi", "wat": "nope"})
    assert cfg == {"text": "hi"}


def test_empty_string_drops_optional_key():
    # compose_fragment guards on `if "key" in cfg`, so empty strings must
    # not slip through as the literal "".
    cfg = _Dummy().validate_cfg({"text": "", "port": 1234})
    assert "text" not in cfg
    assert cfg["port"] == 1234


def test_int_coercion_from_string():
    cfg = _Dummy().validate_cfg({"port": "8443"})
    assert cfg == {"port": 8443}


def test_int_rejects_garbage():
    with pytest.raises(ConfigValidationError):
        _Dummy().validate_cfg({"port": "eighty"})


def test_bool_coercion():
    s = _Dummy()
    assert s.validate_cfg({"enabled": "true"}) == {"enabled": True}
    assert s.validate_cfg({"enabled": "0"}) == {"enabled": False}
    assert s.validate_cfg({"enabled": True}) == {"enabled": True}


def test_enum_rejects_out_of_set():
    with pytest.raises(ConfigValidationError):
        _Dummy().validate_cfg({"mode": "z"})


def test_enum_accepts_valid():
    assert _Dummy().validate_cfg({"mode": "b"}) == {"mode": "b"}


def test_none_cfg_returns_empty_dict():
    assert _Dummy().validate_cfg(None) == {}


def test_field_to_json_omits_unused_enum():
    f = ServiceConfigField(key="x", label="X", type="string")
    assert "enum" not in f.to_json()
    g = ServiceConfigField(key="m", label="M", type="enum", enum=["a", "b"])
    assert g.to_json()["enum"] == ["a", "b"]


# --- Real services -----------------------------------------------------------


def test_ssh_schema_keys_match_compose_reads():
    # SSHService.compose_fragment reads cfg.get("password") and cfg.get("hostname")
    # — the schema must expose exactly those.
    keys = {f.key for f in SSHService.config_schema}
    assert keys == {"password", "hostname"}


def test_ssh_compose_round_trip_through_validator():
    svc = SSHService()
    cfg = svc.validate_cfg({"password": "hunter2", "hostname": "mail-01"})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    env = frag["environment"]
    assert env["SSH_ROOT_PASSWORD"] == "hunter2"
    assert env["SSH_HOSTNAME"] == "mail-01"
    assert env["NODE_NAME"] == "decky-test"


def test_ssh_default_password_when_unset():
    svc = SSHService()
    cfg = svc.validate_cfg({})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    # Default fallback in compose_fragment is "admin"; validator returns {}
    assert frag["environment"]["SSH_ROOT_PASSWORD"] == "admin"


def test_http_schema_covers_compose_keys():
    keys = {f.key for f in HTTPService.config_schema}
    # These are the keys HTTPService.compose_fragment branches on.
    assert {"server_header", "response_code", "fake_app", "extra_headers", "custom_body"} <= keys


def test_http_response_code_int_coercion():
    svc = HTTPService()
    cfg = svc.validate_cfg({"response_code": "418"})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert frag["environment"]["RESPONSE_CODE"] == "418"


def test_https_schema_includes_tls_fields():
    keys = {f.key for f in HTTPSService.config_schema}
    assert {"tls_cn", "tls_cert", "tls_key"} <= keys
    secrets = {f.key for f in HTTPSService.config_schema if f.secret}
    assert {"tls_cert", "tls_key"} <= secrets


# --- Schemas added in this batch --------------------------------------------


def test_telnet_schema_keys_match_compose_reads():
    assert {f.key for f in TelnetService.config_schema} == {"password", "hostname"}


def test_telnet_compose_round_trip():
    svc = TelnetService()
    cfg = svc.validate_cfg({"password": "hunter2", "hostname": "mail-01"})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    env = frag["environment"]
    assert env["TELNET_ROOT_PASSWORD"] == "hunter2"
    assert env["TELNET_HOSTNAME"] == "mail-01"


def test_rdp_schema_matches_and_bool_coerces():
    assert {f.key for f in RDPService.config_schema} == {"nla"}
    svc = RDPService()
    cfg = svc.validate_cfg({"nla": "true"})
    assert cfg == {"nla": True}
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert frag["environment"]["RDP_ENABLE_NLA"] == "true"


def test_rdp_nla_off_drops_env_var():
    svc = RDPService()
    cfg = svc.validate_cfg({"nla": "false"})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert "RDP_ENABLE_NLA" not in frag["environment"]


def test_mysql_schema_and_round_trip():
    assert {f.key for f in MySQLService.config_schema} == {"version"}
    svc = MySQLService()
    cfg = svc.validate_cfg({"version": "8.0.36"})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert frag["environment"]["MYSQL_VERSION"] == "8.0.36"


def test_redis_schema_and_round_trip():
    assert {f.key for f in RedisService.config_schema} == {"version", "os_string"}
    svc = RedisService()
    cfg = svc.validate_cfg({"version": "7.2.4", "os_string": "Linux 5.15.0 x86_64"})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert frag["environment"]["REDIS_VERSION"] == "7.2.4"
    assert frag["environment"]["REDIS_OS"] == "Linux 5.15.0 x86_64"


def test_smtp_schema_and_round_trip():
    assert {f.key for f in SMTPService.config_schema} == {"banner", "mta"}
    svc = SMTPService()
    cfg = svc.validate_cfg({"banner": "mail.corp ESMTP", "mta": "exim"})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert frag["environment"]["SMTP_BANNER"] == "mail.corp ESMTP"
    assert frag["environment"]["SMTP_MTA"] == "exim"


def test_smtp_mta_enum_rejects_unknown():
    with pytest.raises(ConfigValidationError):
        SMTPService().validate_cfg({"mta": "qmail"})


def test_smtp_relay_schema_matches_smtp():
    assert (
        {f.key for f in SMTPRelayService.config_schema}
        == {f.key for f in SMTPService.config_schema}
    )
    svc = SMTPRelayService()
    frag = svc.compose_fragment(
        "decky-test", service_cfg=svc.validate_cfg({"banner": "x", "mta": "postfix"})
    )
    assert frag["environment"]["SMTP_OPEN_RELAY"] == "1"
    assert frag["environment"]["SMTP_BANNER"] == "x"


# --- Textarea base64 transport ----------------------------------------------


def _b64(s: str) -> str:
    return "b64:" + base64.b64encode(s.encode("utf-8")).decode("ascii")


def test_textarea_b64_decoded():
    cfg = _Dummy().validate_cfg({"body": _b64("line1\nline2\nline3")})
    assert cfg == {"body": "line1\nline2\nline3"}


def test_textarea_b64_malformed_rejected():
    with pytest.raises(ConfigValidationError):
        _Dummy().validate_cfg({"body": "b64:not-valid-base64!!"})


def test_textarea_plain_passthrough_for_api_callers():
    # Direct API submitters don't base64-wrap; raw multi-line strings
    # must pass through unchanged.
    cfg = _Dummy().validate_cfg({"body": "raw\nstuff"})
    assert cfg == {"body": "raw\nstuff"}


def test_https_pem_round_trip_through_b64():
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxxx\n"
        "-----END CERTIFICATE-----\n"
    )
    svc = HTTPSService()
    cfg = svc.validate_cfg({"tls_cert": _b64(pem)})
    assert cfg["tls_cert"] == pem  # newlines restored
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert frag["environment"]["TLS_CERT"] == pem


def test_textarea_b64_handles_utf8():
    s = "héllo\nwörld\n☃"
    cfg = _Dummy().validate_cfg({"body": _b64(s)})
    assert cfg == {"body": s}
