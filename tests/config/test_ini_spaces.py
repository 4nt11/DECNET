from decnet.ini_loader import load_ini_from_string

def test_load_ini_with_spaces_around_equals():
    content = """
[general]
interface = eth0

[omega-decky]
services = http, ssh
"""
    cfg = load_ini_from_string(content)
    assert cfg.interface == "eth0"
    assert len(cfg.deckies) == 1
    assert cfg.deckies[0].name == "omega-decky"
    assert cfg.deckies[0].services == ["http", "ssh"]

def test_load_ini_with_tabs_and_spaces():
    content = """
[general]
interface	=	eth0

[omega-decky]
services	=	http, ssh
"""
    cfg = load_ini_from_string(content)
    assert cfg.interface == "eth0"
    assert cfg.deckies[0].services == ["http", "ssh"]
