"""
Regression guards for workers that duplicate standalone daemons.

`decnet deploy` starts standalone `decnet sniffer --daemon` and
`decnet profiler --daemon` processes. The API's lifespan must not spawn
its own copies unless the operator explicitly opts in via env flags.

These tests are intentionally static: we don't spin up lifespan, because
scapy's sniff thread doesn't cooperate with asyncio cancellation and
hangs pytest teardown.
"""
import importlib
import inspect


def test_embed_sniffer_defaults_off(monkeypatch):
    monkeypatch.delenv("DECNET_EMBED_SNIFFER", raising=False)
    import decnet.env
    importlib.reload(decnet.env)
    assert decnet.env.DECNET_EMBED_SNIFFER is False


def test_embed_sniffer_flag_is_truthy_on_opt_in(monkeypatch):
    monkeypatch.setenv("DECNET_EMBED_SNIFFER", "true")
    import decnet.env
    importlib.reload(decnet.env)
    assert decnet.env.DECNET_EMBED_SNIFFER is True


def test_api_lifespan_gates_sniffer_on_embed_flag():
    """The lifespan source must reference the gate flag before spawning the
    sniffer task — catches accidental removal of the guard in future edits."""
    import decnet.web.api
    src = inspect.getsource(decnet.web.api.lifespan)
    assert "DECNET_EMBED_SNIFFER" in src, "sniffer gate removed from lifespan"
    assert "sniffer_worker" in src
    # Gate must appear before the task creation.
    assert src.index("DECNET_EMBED_SNIFFER") < src.index("sniffer_worker")


def test_api_lifespan_gates_profiler_on_embed_flag():
    import decnet.web.api
    src = inspect.getsource(decnet.web.api.lifespan)
    assert "DECNET_EMBED_PROFILER" in src
    assert src.index("DECNET_EMBED_PROFILER") < src.index("attacker_profile_worker")
