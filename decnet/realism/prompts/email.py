"""Prompt builder for the email content class.

The LLM gets a tightly-scoped instruction and a small handful of
deterministic constraints.  Persona mannerisms are *pre-selected* in
Python (1–2 of the persona's full list) and injected as hard rules —
small models otherwise treat the mannerism list as flavour text and
ignore it, and the corpus collapses into one voice.

**Em-dash suppression** is on by default; suppression is lifted only
for personas that opt in via ``uses_llms_heavily``.  Em-dashes are a
strong stylometric tell for LLM-authored prose, and a honeypot mailbox
where every author uses them is a tell.  Stage 6 of the realism
migration extracts the suppression block into a shared
``decnet.realism.prompts._style`` helper so file-class prompts pick
it up too.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Optional

from decnet.realism.personas import EmailPersona


@dataclass(frozen=True)
class PromptInputs:
    sender: EmailPersona
    recipient: EmailPersona
    context_hint: str
    parent_subject: Optional[str] = None      # set when replying
    parent_excerpt: Optional[str] = None      # short snippet of last msg


_LANGUAGE_NAMES = {
    "en": "English",
    "es": "Spanish",
    "pt": "Portuguese",
    "fr": "French",
    "de": "German",
    "it": "Italian",
    "nl": "Dutch",
    "ja": "Japanese",
    "zh": "Chinese",
}


def _lang_label(code: str) -> str:
    return _LANGUAGE_NAMES.get(code.lower(), code)


def select_mannerisms(
    persona: EmailPersona,
    *,
    rng: Optional[secrets.SystemRandom] = None,
    n: int = 2,
) -> list[str]:
    """Pick *n* mannerisms deterministically given *rng*.

    Returns up to *n*; falls back to the full list when the persona
    declares fewer.  Determinism (under a seeded RNG) is what makes
    tests practical — otherwise mannerism injection is unverifiable.
    """
    rnd = rng or secrets.SystemRandom()
    pool = list(persona.mannerisms)
    if not pool:
        return []
    if len(pool) <= n:
        return pool
    rnd.shuffle(pool)
    return pool[:n]


def build(
    inputs: PromptInputs,
    *,
    rng: Optional[secrets.SystemRandom] = None,
) -> tuple[str, list[str]]:
    """Return ``(prompt, mannerisms_used)``.

    ``mannerisms_used`` flows back into the persisted ``payload`` JSON
    so an analyst can see *why* a given email reads the way it does.
    """
    sender = inputs.sender
    recipient = inputs.recipient
    language = _lang_label(sender.language or "en")
    mannerisms = select_mannerisms(sender, rng=rng)
    mannerism_block = (
        "\n".join(f"- {m}" for m in mannerisms)
        if mannerisms
        else "- (no specific mannerisms; write in the persona's tone)"
    )

    if sender.uses_llms_heavily:
        em_dash_rule = (
            "Em-dashes are fine — this persona uses them naturally. "
            "Write in your usual style."
        )
    else:
        em_dash_rule = (
            "Do NOT use em-dashes (—). Use commas, periods, or "
            "parentheses instead. Em-dashes are a tell."
        )

    sig_block = (
        f"Use this exact signature block:\n{sender.signature}"
        if sender.signature
        else "End with a short, plausible signature for the persona's role."
    )

    if inputs.parent_subject:
        thread_block = (
            f"This is a REPLY in an ongoing thread.\n"
            f"- Parent subject: {inputs.parent_subject}\n"
            f"- Parent excerpt: {inputs.parent_excerpt or '(no excerpt)'}\n"
            f"- Begin the body assuming the recipient already read the parent.\n"
        )
        subject_rule = (
            "Subject must be the parent subject prefixed with 'Re: ' "
            "(no double 'Re: Re:')."
        )
    else:
        thread_block = "This is a NEW thread (no prior context)."
        subject_rule = (
            "Generate a short, specific subject line (≤ 80 chars) "
            "appropriate to the context."
        )

    prompt = f"""You are writing one corporate email, RFC 2822 plain-text body only.

Persona — sender:
- Name: {sender.name}
- Role: {sender.role}
- Tone: {sender.tone_custom if sender.tone == "custom" and sender.tone_custom else sender.tone}
- Mannerisms (must show through):
{mannerism_block}

Persona — recipient:
- Name: {recipient.name}
- Role: {recipient.role}

Context hint: {inputs.context_hint}

Thread context:
{thread_block}

Hard rules:
1. Write the email body in {language}. Do not translate or code-switch.
2. {em_dash_rule}
3. {subject_rule}
4. {sig_block}
5. Output ONLY the email — first line is "Subject: <subject>", then a blank line, then the body. No commentary, no markdown fences, no preamble.
"""
    return prompt.strip(), mannerisms
