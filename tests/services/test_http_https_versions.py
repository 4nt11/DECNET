"""http_versions multi_enum field: coercion, compose env, UDP port gate."""
import json

import pytest

from decnet.services.base import ConfigValidationError, ServiceConfigField, _coerce
from decnet.services.http import HTTPService
from decnet.services.https import HTTPSService


# ---------------------------------------------------------------------------
# multi_enum coercion via base._coerce
# ---------------------------------------------------------------------------

_FIELD = ServiceConfigField(
    key="http_versions",
    label="HTTP versions",
    type="multi_enum",
    enum=["http/1.1", "http/2", "http/3"],
)


def test_multi_enum_accepts_valid_list():
    assert _coerce(_FIELD, ["http/1.1", "http/2"]) == ["http/1.1", "http/2"]


def test_multi_enum_single_item():
    assert _coerce(_FIELD, ["http/1.1"]) == ["http/1.1"]


def test_multi_enum_all_three():
    assert _coerce(_FIELD, ["http/1.1", "http/2", "http/3"]) == [
        "http/1.1", "http/2", "http/3"
    ]


def test_multi_enum_deduplicates():
    result = _coerce(_FIELD, ["http/1.1", "http/2", "http/1.1"])
    assert result == ["http/1.1", "http/2"]


def test_multi_enum_rejects_non_list():
    with pytest.raises(ConfigValidationError, match="expected list"):
        _coerce(_FIELD, "http/1.1")


def test_multi_enum_rejects_non_list_int():
    with pytest.raises(ConfigValidationError, match="expected list"):
        _coerce(_FIELD, 1)


def test_multi_enum_rejects_empty_list():
    with pytest.raises(ConfigValidationError, match="must not be empty"):
        _coerce(_FIELD, [])


def test_multi_enum_rejects_unknown_value():
    with pytest.raises(ConfigValidationError, match="not in allowed values"):
        _coerce(_FIELD, ["http/1.1", "http/4"])


def test_multi_enum_coerces_items_to_str():
    # Submitters may send ints or mixed types; each item is str-coerced before lookup.
    field_no_enum = ServiceConfigField(
        key="tags", label="Tags", type="multi_enum", enum=None
    )
    assert _coerce(field_no_enum, [1, 2]) == ["1", "2"]


# ---------------------------------------------------------------------------
# HTTPService: http_versions in schema, env propagation, no h3 option
# ---------------------------------------------------------------------------

def test_http_schema_includes_http_versions():
    keys = {f.key for f in HTTPService.config_schema}
    assert "http_versions" in keys


def test_http_schema_no_h3_in_enum():
    field = next(f for f in HTTPService.config_schema if f.key == "http_versions")
    assert "http/3" not in (field.enum or [])


def test_http_compose_http_versions_env():
    svc = HTTPService()
    cfg = svc.validate_cfg({"http_versions": ["http/1.1", "http/2"]})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    versions = json.loads(frag["environment"]["HTTP_VERSIONS"])
    assert versions == ["http/1.1", "http/2"]


def test_http_compose_no_versions_no_env_key():
    frag = HTTPService().compose_fragment("decky-test", service_cfg={})
    assert "HTTP_VERSIONS" not in frag["environment"]


# ---------------------------------------------------------------------------
# HTTPSService: http_versions in schema, env propagation, UDP port for h3
# ---------------------------------------------------------------------------

def test_https_schema_includes_http_versions():
    keys = {f.key for f in HTTPSService.config_schema}
    assert "http_versions" in keys


def test_https_schema_has_h3():
    field = next(f for f in HTTPSService.config_schema if f.key == "http_versions")
    assert "http/3" in (field.enum or [])


def test_https_compose_http_versions_env():
    svc = HTTPSService()
    cfg = svc.validate_cfg({"http_versions": ["http/1.1", "http/2"]})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    versions = json.loads(frag["environment"]["HTTP_VERSIONS"])
    assert versions == ["http/1.1", "http/2"]


def test_https_compose_h3_adds_udp_port():
    svc = HTTPSService()
    cfg = svc.validate_cfg({"http_versions": ["http/1.1", "http/2", "http/3"]})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert "443:443/udp" in frag.get("ports", [])


def test_https_compose_no_h3_no_udp_port():
    svc = HTTPSService()
    cfg = svc.validate_cfg({"http_versions": ["http/1.1", "http/2"]})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert "443:443/udp" not in frag.get("ports", [])


def test_https_compose_h3_only_still_adds_udp_port():
    svc = HTTPSService()
    cfg = svc.validate_cfg({"http_versions": ["http/3"]})
    frag = svc.compose_fragment("decky-test", service_cfg=cfg)
    assert "443:443/udp" in frag.get("ports", [])
