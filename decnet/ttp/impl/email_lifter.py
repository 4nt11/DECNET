"""Email lifter — SMTP message-level technique tagger (E.3.12).

Reads pre-parsed SMTP message payload (headers as a name-only list,
body sha + body text already truncated/scrubbed by the upstream worker,
attachment hashes + names) and emits Initial-Access / Phishing /
Resource-Development techniques per Appendix A.6.

PII discipline (TTP_TAGGING.md §"Hard parts §6") is enforced at the
lifter layer: emitted ``TTPTag.evidence`` only carries fields that
conform to :class:`~decnet.web.db.models.ttp.EmailEvidence`
(``body_sha256``, ``matched_headers`` — names not values,
``rcpt_domain_set`` — domains not addresses, ``attachment_sha256s``,
``rcpt_count``) plus a small set of match-discriminator strings
(``matched_kit``, ``matched_trigger``, ``matched_url``). Raw From /
Return-Path / RCPT addresses, raw body bytes, and decoded payload
previews NEVER appear in evidence.
"""
from __future__ import annotations

import base64
import binascii
import email
import email.errors
import email.message
import email.policy
import hashlib
import re
from collections.abc import Callable
from typing import Any, Final

from decnet.artifacts.paths import ArtifactPathError, resolve_artifact_path
from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import is_active
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleStore
from decnet.web.db.models.ttp import TTPTag


Predicate = Callable[
    [dict[str, Any], dict[str, Any]],
    "dict[str, Any] | None",
]


# ── Helpers ─────────────────────────────────────────────────────────


def _domain(addr_or_domain: str | None) -> str | None:
    if not isinstance(addr_or_domain, str):
        return None
    if not addr_or_domain:
        return None
    if "@" in addr_or_domain:
        return addr_or_domain.split("@", 1)[1].lower().strip()
    return addr_or_domain.lower().strip()


def _safe_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Build the EmailEvidence-conformant base evidence dict.

    Only PII-safe keys: body sha (already a hash), header NAMES (not
    values), recipient DOMAINS (not addresses), attachment hashes,
    rcpt count. Raw addresses, raw body, raw header values explicitly
    excluded.
    """
    rcpt_domains_raw = payload.get("rcpt_domains") or []
    rcpt_domains = [
        d.lower() for d in rcpt_domains_raw if isinstance(d, str)
    ]
    attachment_hashes = payload.get("attachment_sha256s") or []
    if not isinstance(attachment_hashes, list):
        attachment_hashes = []
    body_sha = payload.get("body_sha256") or ""
    if not isinstance(body_sha, str):
        body_sha = ""
    rcpt_count = payload.get("rcpt_count")
    if not isinstance(rcpt_count, int):
        rcpt_count = 0
    return {
        "body_sha256": body_sha,
        "matched_headers": [],
        "rcpt_domain_set": sorted(set(rcpt_domains)),
        "attachment_sha256s": [
            h for h in attachment_hashes if isinstance(h, str)
        ],
        "rcpt_count": rcpt_count,
    }


# ── Per-rule predicates ─────────────────────────────────────────────


def _p_open_relay(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    threshold = int(spec.get("rcpt_threshold", 10))
    rcpt_count = payload.get("rcpt_count")
    if not isinstance(rcpt_count, int) or rcpt_count < threshold:
        return None
    if spec.get("require_foreign_from"):
        from_domain = _domain(payload.get("from_domain") or payload.get("from"))
        mail_from = _domain(
            payload.get("mail_from_domain") or payload.get("mail_from"),
        )
        if not from_domain or not mail_from or from_domain == mail_from:
            return None
    return {"matched_headers": ["From", "Mail-From"]}


def _p_mass_phish(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    threshold = int(spec.get("rcpt_threshold", 25))
    rcpt_count = payload.get("rcpt_count")
    if not isinstance(rcpt_count, int) or rcpt_count < threshold:
        return None
    # The "campaign" half: upstream must have observed body simhash
    # recurring across recipients. Without that signal, high-RCPT alone
    # is open-relay territory (R0041), not mass-phish. The simhash
    # derivation lives in the SMTP worker (out of scope here).
    if not isinstance(payload.get("body_simhash"), (str, int)):
        return None
    return {}


def _p_xmailer_kit(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    x_mailer = payload.get("x_mailer")
    if not isinstance(x_mailer, str) or not x_mailer:
        return None
    matched_kit = payload.get("matched_kit")
    if isinstance(matched_kit, str) and matched_kit:
        return {"matched_kit": matched_kit, "matched_headers": ["X-Mailer"]}
    # Catalogue match flag — upstream marks it via xmailer_kit_match.
    if payload.get("xmailer_kit_match") is True:
        return {"matched_headers": ["X-Mailer"]}
    return None


_PUNYCODE_PREFIX_DEFAULT: Final[str] = "xn--"


def _p_idn_url(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    prefix = spec.get("punycode_prefix") or _PUNYCODE_PREFIX_DEFAULT
    if not isinstance(prefix, str):
        prefix = _PUNYCODE_PREFIX_DEFAULT
    urls = payload.get("urls") or []
    if not isinstance(urls, list):
        return None
    for url in urls:
        if isinstance(url, str) and prefix in url:
            # Carry only the punycode-bearing host portion as a match
            # discriminator. NEVER carry the full URL (could contain
            # credential-harvest path with PII).
            host = _extract_host(url)
            return {
                "matched_url_host": host or "",
                "matched_headers": ["body"],
            }
    return None


def _extract_host(url: str) -> str | None:
    m = re.match(r"https?://([^/]+)", url)
    if m:
        return m.group(1).lower()
    return None


def _p_sender_masquerade(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    signals_raw = spec.get("signals", [])
    if not isinstance(signals_raw, list):
        return None
    signals = {s for s in signals_raw if isinstance(s, str)}
    matched: list[str] = []
    if "from_returnpath_mismatch" in signals:
        if (
            _domain(payload.get("from_domain")) is not None
            and _domain(payload.get("return_path_domain")) is not None
            and _domain(payload.get("from_domain"))
            != _domain(payload.get("return_path_domain"))
        ):
            matched.append("from_returnpath_mismatch")
    if "from_mailfrom_mismatch" in signals:
        if (
            _domain(payload.get("from_domain")) is not None
            and _domain(payload.get("mail_from_domain")) is not None
            and _domain(payload.get("from_domain"))
            != _domain(payload.get("mail_from_domain"))
        ):
            matched.append("from_mailfrom_mismatch")
    if "dkim_fail" in signals and payload.get("dkim_signed") is False:
        matched.append("dkim_fail")
    if "spf_fail" in signals and payload.get("spf_pass") is False:
        matched.append("spf_fail")
    if not matched:
        return None
    headers: list[str] = []
    if any("from_" in m for m in matched):
        headers.extend(["From", "Return-Path"])
    if "dkim_fail" in matched:
        headers.append("DKIM-Signature")
    if "spf_fail" in matched:
        headers.append("Authentication-Results")
    return {
        "matched_signals": matched,
        "matched_headers": sorted(set(headers)),
    }


def _p_malicious_attachment(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    triggers_raw = spec.get("triggers", [])
    triggers = (
        {t for t in triggers_raw if isinstance(t, str)}
        if isinstance(triggers_raw, list)
        else set()
    )
    if "office_macro" in triggers and payload.get("attachment_macros") is True:
        return {"matched_trigger": "office_macro"}
    if (
        "protected_archive" in triggers
        and payload.get("attachment_password_protected") is True
    ):
        return {"matched_trigger": "protected_archive"}
    if "html_smuggling" in triggers and payload.get("html_smuggling") is True:
        return {"matched_trigger": "html_smuggling"}
    if "mal_hash_match" in triggers and payload.get("mal_hash_match") is True:
        return {"matched_trigger": "mal_hash_match"}
    extensions = payload.get("attachment_extensions") or []
    if isinstance(extensions, list):
        ext_set = {
            e.lower().lstrip(".") for e in extensions if isinstance(e, str)
        }
        for ext_trigger in ("lnk", "iso", "img"):
            if ext_trigger in triggers and ext_trigger in ext_set:
                return {"matched_trigger": ext_trigger}
    return None


def _extract_body_text(msg: email.message.EmailMessage) -> str | None:
    """Best-effort plain-text body extraction from a parsed email.

    Prefers ``text/plain``. Falls back to ``text/html`` (raw — predicates
    here are substring-matchers, no need to de-tag). Returns None when
    the message has no readable text part. Requires the message to have
    been parsed with ``policy=email.policy.default`` so parts are
    ``EmailMessage`` instances (``get_content`` is policy-conditional).
    """
    candidates: list[email.message.EmailMessage] = list(msg.walk())
    for content_type in ("text/plain", "text/html"):
        for part in candidates:
            if part.get_content_type() != content_type:
                continue
            try:
                content = part.get_content()
            except (LookupError, ValueError, KeyError):
                continue
            if isinstance(content, str):
                return content
    return None


def _load_body_text(payload: dict[str, Any]) -> str | None:
    """Return the email body text for predicates that need it.

    If the bus payload already carries ``body_text`` (older deployments
    or master-side producers), use it. Otherwise disk-reach: open the
    ``.eml`` from ``/var/lib/decnet/artifacts/{decky_id}/smtp/{stored_as}``
    and parse the body in-process.

    The decoded body is memoized back into the payload dict so the next
    predicate on the same event reuses it without re-opening the file.
    The bus envelope only carries the artifact pointer (``decky_id`` +
    ``stored_as``); raw body bytes never cross the host boundary
    (DEBT-047). Returns None on any failure — predicates then short
    circuit to no-match, matching pre-disk-reach behavior when fields
    were absent.
    """
    existing = payload.get("body_text")
    if isinstance(existing, str):
        return existing
    decky_id = payload.get("decky_id")
    stored_as = payload.get("stored_as")
    if not isinstance(decky_id, str) or not isinstance(stored_as, str):
        return None
    try:
        path = resolve_artifact_path(decky_id, stored_as, "smtp")
    except ArtifactPathError:
        return None
    try:
        with open(path, "rb") as fh:
            msg = email.message_from_binary_file(
                fh, policy=email.policy.default,
            )
    except (OSError, email.errors.MessageError):
        return None
    body = _extract_body_text(msg)
    if body is None:
        return None
    payload["body_text"] = body
    return body


def _p_bec(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    subject = payload.get("subject")
    if not isinstance(subject, str):
        return None
    body_text = _load_body_text(payload)
    if body_text is None:
        return None
    subj_kws = spec.get("subject_keywords", [])
    body_kws = spec.get("body_action_keywords", [])
    if not isinstance(subj_kws, list) or not isinstance(body_kws, list):
        return None
    subj_l = subject.lower()
    body_l = body_text.lower()
    subj_hit = next(
        (k for k in subj_kws if isinstance(k, str) and k.lower() in subj_l),
        None,
    )
    body_hit = next(
        (k for k in body_kws if isinstance(k, str) and k.lower() in body_l),
        None,
    )
    if not subj_hit or not body_hit:
        return None
    return {
        "matched_subject_kw": subj_hit,
        "matched_body_kw": body_hit,
        "matched_headers": ["Subject"],
    }


_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")


def _p_encoded_payload(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    min_bytes = int(spec.get("min_bytes", 4096))
    body_text = _load_body_text(payload)
    if not body_text:
        return None
    # Upstream may pre-compute the largest decoded base64 length.
    body_b64_bytes = payload.get("body_base64_bytes")
    if isinstance(body_b64_bytes, int) and body_b64_bytes >= min_bytes:
        return {"encoded_byte_count": body_b64_bytes}
    # Fallback: best-effort scan of the body text. Cap the work at the
    # first match >= threshold to avoid quadratic behavior on a hostile
    # body. Decoded bytes are NEVER returned — only the count.
    for m in _BASE64_RE.finditer(body_text):
        chunk = m.group(0)
        try:
            decoded = base64.b64decode(chunk, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) >= min_bytes:
            return {"encoded_byte_count": len(decoded)}
    return None


_PREDICATES: Final[dict[str, Predicate]] = {
    "lifter:email_open_relay": _p_open_relay,
    "lifter:email_mass_phish": _p_mass_phish,
    "lifter:email_xmailer_kit": _p_xmailer_kit,
    "lifter:email_idn_url": _p_idn_url,
    "lifter:email_sender_masquerade": _p_sender_masquerade,
    "lifter:email_malicious_attachment": _p_malicious_attachment,
    "lifter:email_bec": _p_bec,
    "lifter:email_encoded_payload": _p_encoded_payload,
}


# Allowed keys in TTPTag.evidence for source_kind=email. Used both as
# the assembly contract here AND by tests/ttp/test_email_lifter.py to
# guard against a future predicate accidentally leaking PII.
_EMAIL_EVIDENCE_ALLOWED_KEYS: Final[frozenset[str]] = frozenset({
    # EmailEvidence base
    "body_sha256",
    "matched_headers",
    "rcpt_domain_set",
    "attachment_sha256s",
    "rcpt_count",
    # PII-safe match discriminators
    "matched_kit",
    "matched_trigger",
    "matched_url_host",
    "matched_signals",
    "matched_subject_kw",
    "matched_body_kw",
    "encoded_byte_count",
})


def _filter_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Drop any key not in the PII-safe allowlist.

    Defense-in-depth: even if a predicate accidentally returns a raw
    address or body field, this filter strips it before the tag is
    constructed. Asserted by ``test_email_lifter.py``.
    """
    return {
        k: v for k, v in evidence.items()
        if k in _EMAIL_EVIDENCE_ALLOWED_KEYS
    }


class EmailLifter(TolerantTagger):
    name = "email"
    HANDLES = frozenset({"email"})
    OWNED_PREFIX: Final[str] = "lifter:email_"

    def __init__(self, store: RuleStore) -> None:
        self._store = store
        self._index = RuleIndex()

    @classmethod
    def _owns(cls, rule: CompiledRule) -> bool:
        kind = rule.match_spec.get("kind", "")
        return isinstance(kind, str) and kind.startswith(cls.OWNED_PREFIX)

    async def watch_store(self) -> None:
        await self._index.watch(self._store, predicate=self._owns)

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        out: list[TTPTag] = []
        base_evidence = _safe_evidence(event.payload)
        for rule in self._index.values():
            if event.source_kind not in rule.applies_to:
                continue
            if not is_active(rule.state):
                continue
            kind = rule.match_spec.get("kind", "")
            handler = _PREDICATES.get(kind)
            if handler is None:
                continue
            extra = handler(rule.match_spec, event.payload)
            if extra is None:
                continue
            evidence = dict(base_evidence)
            # Allow predicates to extend matched_headers without
            # clobbering the base list.
            extra_headers = extra.pop("matched_headers", None)
            if isinstance(extra_headers, list):
                merged = list(evidence.get("matched_headers", []))
                merged.extend(h for h in extra_headers if isinstance(h, str))
                evidence["matched_headers"] = sorted(set(merged))
            evidence.update(extra)
            evidence = _filter_evidence(evidence)
            # Body sha is required by EmailEvidence; if upstream
            # didn't supply one, derive from body_text (best-effort).
            if not evidence.get("body_sha256"):
                body_text = event.payload.get("body_text")
                if isinstance(body_text, str) and body_text:
                    evidence["body_sha256"] = hashlib.sha256(
                        body_text.encode("utf-8", errors="replace"),
                    ).hexdigest()
            out.extend(emit_tags(rule, event, evidence))
        return out


__all__ = ["EmailLifter"]
