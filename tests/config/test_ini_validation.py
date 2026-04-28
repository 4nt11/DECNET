import pytest
from decnet.ini_loader import load_ini_from_string, validate_ini_string

def test_validate_ini_string_too_large():
    content = "[" + "a" * (512 * 1024 + 1) + "]"
    with pytest.raises(ValueError, match="too large"):
        validate_ini_string(content)

def test_validate_ini_string_empty():
    with pytest.raises(ValueError, match="is empty"):
        validate_ini_string("")
    with pytest.raises(ValueError, match="is empty"):
        validate_ini_string("   ")

def test_validate_ini_string_no_sections():
    with pytest.raises(ValueError, match="no sections found"):
        validate_ini_string("key=value")

def test_load_ini_from_string_amount_limit():
    content = """
[general]
net=192.168.1.0/24

[decky-01]
amount=101
archetype=linux-server
"""
    with pytest.raises(ValueError, match="exceeds maximum allowed"):
        load_ini_from_string(content)

def test_load_ini_from_string_valid():
    content = """
[general]
net=192.168.1.0/24

[decky-01]
amount=5
archetype=linux-server
"""
    cfg = load_ini_from_string(content)
    assert len(cfg.deckies) == 5
