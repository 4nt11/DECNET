"""DECNET — honeypot deception-network framework.

This __init__ runs once, on the first `import decnet.*`. It seeds
os.environ from /etc/decnet/decnet.ini (if present) so that later
module-level reads in decnet.env pick up the INI values as if they had
been exported by the shell. Real env vars always win via setdefault().

Kept minimal on purpose — any heavier work belongs in a submodule.
"""
from decnet.config_ini import load_ini_config as _load_ini_config

_load_ini_config()
