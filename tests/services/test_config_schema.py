"""Schema-driven service config: descriptors, validation, compose round-trip."""

import pytest

from decnet.services.base import (
    BaseService,
    ConfigValidationError,
    ServiceConfigField,
)
from decnet.services.http import HTTPService
from decnet.services.https import HTTPSService
from decnet.services.ssh import SSHService


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
