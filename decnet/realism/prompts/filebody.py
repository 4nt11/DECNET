"""Class-conditioned prompt builder for user-class file bodies.

Stage 6 of the realism migration.  Only user-classes (``note``,
``todo``, ``draft``, ``script``) get LLM enrichment — system-class
content (cron logs, daemon logs, /tmp caches) is *supposed* to look
formulaic, and an LLM-authored cron log is more suspicious than a
templated one.

The prompt asks for *short* output (LLM-authored ten-page essays in
``~/notes.txt`` are an instant tell) and pins the exit shape so the
worker doesn't need to scrape boilerplate.  Em-dash suppression
flows through :mod:`decnet.realism.prompts._style`.
"""
from __future__ import annotations

from decnet.realism.personas import EmailPersona
from decnet.realism.prompts._style import em_dash_rule
from decnet.realism.taxonomy import ContentClass


_LANGUAGE_NAMES = {
    "en": "English", "es": "Spanish", "pt": "Portuguese",
    "fr": "French", "de": "German", "it": "Italian",
    "nl": "Dutch", "ja": "Japanese", "zh": "Chinese",
}


def _lang_label(code: str) -> str:
    return _LANGUAGE_NAMES.get((code or "en").lower(), code or "English")


_CLASS_GUIDANCE: dict[ContentClass, str] = {
    ContentClass.NOTE: (
        "A personal note file the persona keeps on their dev box.  "
        "2–6 short lines.  Mix of TODOs, half-formed thoughts, "
        "shorthand reminders.  NOT a polished document.  No headers "
        "or markdown sections."
    ),
    ContentClass.TODO: (
        "A markdown TODO list the persona keeps on their dev box.  "
        "3–8 items in `- [ ] item` / `- [x] item` form.  Some checked, "
        "some not.  Items are short, work-flavoured, lowercase, no "
        "prose paragraphs.  No headers.  No introductory sentence."
    ),
    ContentClass.DRAFT: (
        "A short draft email or memo the persona is working on.  "
        "2–4 short paragraphs, conversational tone.  No subject line, "
        "no headers — this is the body in a notes file, not a sent "
        "email.  Sign off the way the persona would in their voice."
    ),
    ContentClass.SCRIPT: (
        "A short utility script the persona wrote.  Pick a plausible "
        "interpreter (bash or python3) and start with the matching "
        "shebang.  10–25 lines.  Real-feeling intent (a backup, a "
        "log rotation, a cleanup).  Inline comments allowed but sparse."
    ),
}


def build(
    content_class: ContentClass,
    persona: EmailPersona,
) -> str:
    """Return a prompt for one body of *content_class* by *persona*.

    Output the LLM is expected to produce: *just the file body*, no
    commentary, no markdown fences.  Caller substitutes em-dashes
    server-side via :func:`decnet.realism.prompts._style.strip_em_dashes`
    as a belt-and-braces guard.
    """
    guidance = _CLASS_GUIDANCE.get(content_class)
    if guidance is None:
        raise KeyError(
            f"no filebody prompt registered for content_class={content_class!r}"
        )
    language = _lang_label(persona.language or "en")
    return (
        f"You are writing one short file the persona below would "
        f"plausibly keep on their dev box.\n\n"
        f"Persona:\n"
        f"- Name: {persona.name}\n"
        f"- Role: {persona.role}\n"
        f"- Tone: {persona.tone_custom if persona.tone == 'custom' and persona.tone_custom else persona.tone}\n\n"
        f"File class: {content_class.value}\n"
        f"Guidance: {guidance}\n\n"
        f"Hard rules:\n"
        f"1. Write the file body in {language}. Do not translate or code-switch.\n"
        f"2. {em_dash_rule(persona)}\n"
        f"3. Output ONLY the file body. No commentary, no markdown "
        f"   fences, no preamble like 'Here is the file:'.\n"
    ).strip()
