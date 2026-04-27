"""LLM backend factory + Ollama implementation."""
from __future__ import annotations

import asyncio

import pytest

from decnet.orchestrator.emailgen.llm import LLMTimeout, get_llm
from decnet.orchestrator.emailgen.llm.impl.fake import FakeBackend
from decnet.orchestrator.emailgen.llm.impl.ollama import OllamaBackend


# ── factory dispatch ─────────────────────────────────────────────────────────


def test_factory_default_is_ollama(monkeypatch):
    monkeypatch.delenv("DECNET_EMAILGEN_LLM", raising=False)
    backend = get_llm()
    assert isinstance(backend, OllamaBackend)


def test_factory_selects_fake(monkeypatch):
    monkeypatch.setenv("DECNET_EMAILGEN_LLM", "fake")
    backend = get_llm()
    assert isinstance(backend, FakeBackend)


def test_factory_unknown_raises(monkeypatch):
    monkeypatch.setenv("DECNET_EMAILGEN_LLM", "vllm-someday")
    with pytest.raises(ValueError, match="Unsupported"):
        get_llm()


def test_factory_passes_model_through(monkeypatch):
    monkeypatch.setenv("DECNET_EMAILGEN_LLM", "ollama")
    backend = get_llm(model="qwen2:7b")
    assert backend.model == "qwen2:7b"


# ── FakeBackend ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fake_backend_returns_canned_output():
    fb = FakeBackend(output="Subject: hi\n\nbody")
    result = await fb.generate("any prompt")
    assert result.success is True
    assert result.text.startswith("Subject:")
    assert result.model == "fake-model"


@pytest.mark.asyncio
async def test_fake_backend_can_simulate_failure():
    fb = FakeBackend(success=False)
    result = await fb.generate("prompt")
    assert result.success is False
    assert result.text == ""


# ── OllamaBackend (subprocess stubbed) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_ollama_backend_success(monkeypatch):
    """Stub asyncio.create_subprocess_exec to return canned stdout."""

    class _StubProc:
        returncode = 0

        async def communicate(self, _stdin):
            return b"Subject: hi\n\nbody\n", b""

    async def fake_create(*args, **kwargs):    # noqa: ARG001
        return _StubProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    backend = OllamaBackend(model="m1", timeout=1.0)
    result = await backend.generate("hello")
    assert result.success is True
    assert "Subject:" in result.text
    assert result.model == "m1"


@pytest.mark.asyncio
async def test_ollama_backend_non_zero_rc_marks_failure(monkeypatch):
    class _StubProc:
        returncode = 1

        async def communicate(self, _stdin):
            return b"", b"model not found"

    async def fake_create(*args, **kwargs):    # noqa: ARG001
        return _StubProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    backend = OllamaBackend(model="m1", timeout=1.0)
    result = await backend.generate("hello")
    assert result.success is False
    assert result.extra["rc"] == 1
    assert "model not found" in result.extra["stderr"]


@pytest.mark.asyncio
async def test_ollama_backend_timeout_raises(monkeypatch):
    class _StubProc:
        returncode = None

        async def communicate(self, _stdin):
            await asyncio.sleep(10)    # well past the timeout
            return b"", b""

        def kill(self):
            pass

    async def fake_create(*args, **kwargs):    # noqa: ARG001
        return _StubProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    backend = OllamaBackend(model="m1", timeout=0.05)
    with pytest.raises(LLMTimeout):
        await backend.generate("hello")


@pytest.mark.asyncio
async def test_ollama_backend_missing_binary_returns_failure(monkeypatch):
    async def fake_create(*args, **kwargs):    # noqa: ARG001
        raise FileNotFoundError("ollama: not found")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    backend = OllamaBackend(model="m1", timeout=1.0)
    result = await backend.generate("hello")
    assert result.success is False
    assert result.extra["rc"] == 127
