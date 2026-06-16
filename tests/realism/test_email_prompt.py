# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prompt builder behaviour: language constraint, em-dash suppression,
deterministic mannerism injection."""
from __future__ import annotations

import random

from decnet.realism.personas import EmailPersona
from decnet.realism.prompts.email import (
    PromptInputs,
    build,
    select_mannerisms,
)


def _persona(**over) -> EmailPersona:
    base = dict(
        name="John Smith",
        email="john@corp.com",
        role="COO",
        tone="formal",
        mannerisms=[
            "opens with 'I hope this finds you well'",
            "uses 'Best regards' exclusively",
            "references policy by number",
            "ccs legal",
        ],
        language="en",
    )
    base.update(over)
    return EmailPersona(**base)


class _SeededRng:
    """Adapter so prompt code thinks it has a SystemRandom."""

    def __init__(self, seed: int):
        self._r = random.Random(seed)

    def shuffle(self, seq):
        self._r.shuffle(seq)

    def random(self):
        return self._r.random()

    def choice(self, seq):
        return self._r.choice(seq)


def test_select_mannerisms_returns_subset_of_pool():
    persona = _persona()
    picks = select_mannerisms(persona, rng=_SeededRng(0), n=2)
    assert len(picks) == 2
    assert all(m in persona.mannerisms for m in picks)


def test_select_mannerisms_deterministic_under_same_seed():
    persona = _persona()
    a = select_mannerisms(persona, rng=_SeededRng(42), n=2)
    b = select_mannerisms(persona, rng=_SeededRng(42), n=2)
    assert a == b


def test_select_mannerisms_returns_all_when_pool_smaller_than_n():
    persona = _persona(mannerisms=["a"])
    picks = select_mannerisms(persona, rng=_SeededRng(0), n=2)
    assert picks == ["a"]


def test_select_mannerisms_empty_pool():
    persona = _persona(mannerisms=[])
    assert select_mannerisms(persona) == []


def test_build_includes_language_constraint_english():
    sender = _persona(language="en")
    recip = _persona(name="Sarah", email="sarah@corp.com", role="PM")
    prompt, _ = build(
        PromptInputs(sender=sender, recipient=recip, context_hint="budget"),
        rng=_SeededRng(0),
    )
    assert "in English" in prompt


def test_build_includes_language_constraint_spanish():
    sender = _persona(language="es")
    recip = _persona(name="Sarah", email="sarah@corp.com", role="PM")
    prompt, _ = build(
        PromptInputs(sender=sender, recipient=recip, context_hint="budget"),
        rng=_SeededRng(0),
    )
    assert "in Spanish" in prompt


def test_build_em_dash_suppression_default():
    sender = _persona()
    recip = _persona(name="Sarah", email="sarah@corp.com", role="PM")
    prompt, _ = build(
        PromptInputs(sender=sender, recipient=recip, context_hint="budget"),
        rng=_SeededRng(0),
    )
    assert "Do NOT use em-dashes" in prompt


def test_build_em_dash_lifted_for_llm_heavy_persona():
    sender = _persona(uses_llms_heavily=True)
    recip = _persona(name="Sarah", email="sarah@corp.com", role="PM")
    prompt, _ = build(
        PromptInputs(sender=sender, recipient=recip, context_hint="budget"),
        rng=_SeededRng(0),
    )
    assert "Do NOT use em-dashes" not in prompt
    assert "fine" in prompt.lower()


def test_build_reply_thread_block_prefixes_re():
    sender = _persona()
    recip = _persona(name="Sarah", email="sarah@corp.com", role="PM")
    prompt, _ = build(
        PromptInputs(
            sender=sender,
            recipient=recip,
            context_hint="budget",
            parent_subject="Re: Q3 budget",
            parent_excerpt="Numbers attached.",
        ),
        rng=_SeededRng(0),
    )
    assert "REPLY in an ongoing thread" in prompt
    assert "Re: Q3 budget" in prompt
    assert "Numbers attached" in prompt
    assert "prefixed with 'Re: '" in prompt


def test_build_returns_mannerisms_used_metadata():
    sender = _persona()
    recip = _persona(name="Sarah", email="sarah@corp.com", role="PM")
    _, used = build(
        PromptInputs(sender=sender, recipient=recip, context_hint="budget"),
        rng=_SeededRng(7),
    )
    assert used
    assert all(m in sender.mannerisms for m in used)


def test_build_uses_explicit_signature_when_provided():
    sender = _persona(signature="-- John\\nCOO")
    recip = _persona(name="Sarah", email="sarah@corp.com", role="PM")
    prompt, _ = build(
        PromptInputs(sender=sender, recipient=recip, context_hint="budget"),
        rng=_SeededRng(0),
    )
    assert "Use this exact signature block" in prompt
