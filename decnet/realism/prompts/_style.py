"""Shared stylometric guards for LLM-bound prompts.

Lifted from the original ``orchestrator.emailgen.prompt`` em-dash
block so file-class prompts (note / todo / draft / script bodies)
pick up the same suppression.  Per the
``feedback_em_dash_llm_tell.md`` memory: em-dashes (—) are a strong
LLM-authorship tell, suppress by default; allow only for personas
explicitly opted in via ``EmailPersona.uses_llms_heavily``.
"""
from __future__ import annotations

from decnet.realism.personas import EmailPersona


_SUPPRESS_RULE = (
    "Do NOT use em-dashes (—). Use commas, periods, or "
    "parentheses instead. Em-dashes are a tell."
)
_ALLOW_RULE = (
    "Em-dashes are fine — this persona uses them naturally. "
    "Write in your usual style."
)


def em_dash_rule(persona: EmailPersona) -> str:
    """Return the em-dash instruction line for *persona*'s prompt."""
    if persona.uses_llms_heavily:
        return _ALLOW_RULE
    return _SUPPRESS_RULE


def strip_em_dashes(text: str, persona: EmailPersona) -> str:
    """Belt-and-braces: even with the prompt rule, small models leak
    em-dashes occasionally.  Substitute with comma+space so the
    output reads naturally; opt-in personas pass through unchanged.
    """
    if persona.uses_llms_heavily:
        return text
    return text.replace("—", ", ").replace("–", ", ")
