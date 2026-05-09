import type { ApiError } from '../../utils/api';
import type { EmailPersona, ReplyLatency, Tone } from './types';

export const TONES: Tone[] = ['formal', 'direct', 'casual', 'technical', 'custom'];
export const LATENCIES: ReplyLatency[] = ['fast', 'normal', 'slow'];

export const BLANK: EmailPersona = {
  name: '',
  email: '',
  role: '',
  tone: 'formal',
  tone_custom: null,
  mannerisms: [],
  language: 'en',
  signature: null,
  active_hours: '09:00-18:00',
  reply_latency: 'normal',
  uses_llms_heavily: false,
};

export const TEMPLATE: { personas: EmailPersona[] } = {
  personas: [
    {
      name: 'Jane Operator',
      email: 'jane@example.com',
      role: 'Network Admin',
      tone: 'formal',
      tone_custom: null,
      mannerisms: ["uses bullet points", "signs off with 'Best regards'"],
      language: 'en',
      signature: 'Jane Operator\nNetwork Admin',
      active_hours: '09:00-18:00',
      reply_latency: 'normal',
      uses_llms_heavily: false,
    },
  ],
};

export function extractErrorDetail(err: unknown, fallback: string): string {
  const e = err as ApiError;
  if (e?.response?.data?.detail) return e.response.data.detail;
  if (e?.response?.status === 403) return 'Insufficient permissions (admin only)';
  if (e?.response?.status === 401) return 'Session expired — please log in again';
  if (e?.message) return e.message;
  return fallback;
}

/** Light client-side validation — server re-validates with the same
 *  Pydantic schema the worker uses, this is just the early-warn UX. */
export function validate(p: EmailPersona): string | null {
  if (!p.name.trim()) return 'name is required';
  if (!p.email.trim()) return 'email is required';
  if (!p.email.includes('@') || !p.email.split('@')[1]?.includes('.')) {
    return 'email must look like user@domain.tld';
  }
  if (!p.role.trim()) return 'role is required';
  if (p.tone === 'custom' && !(p.tone_custom ?? '').trim()) {
    return 'custom tone requires a description';
  }
  if (p.mannerisms.length > 12) return 'at most 12 mannerisms per persona';
  return null;
}

/** Soft client-side normalizer for an uploaded persona entry.
 *  Mirrors the Pydantic rules in decnet/realism/personas.py.
 *  Server re-validates on save, so this is just early-warn UX. */
export function coercePersona(raw: unknown): { ok: EmailPersona } | { error: string } {
  if (!raw || typeof raw !== 'object') return { error: 'entry is not an object' };
  const r = raw as Record<string, unknown>;
  const name = typeof r.name === 'string' ? r.name.trim() : '';
  const email = typeof r.email === 'string' ? r.email.trim() : '';
  const role = typeof r.role === 'string' ? r.role.trim() : '';
  if (!name) return { error: 'missing name' };
  if (!email) return { error: 'missing email' };
  if (!email.includes('@') || !email.split('@')[1]?.includes('.')) {
    return { error: `invalid email "${email}"` };
  }
  if (!role) return { error: 'missing role' };
  const tone = TONES.includes(r.tone as Tone) ? (r.tone as Tone) : 'formal';
  const tone_custom = typeof r.tone_custom === 'string' && r.tone_custom.trim()
    ? r.tone_custom.slice(0, 128) : null;
  if (tone === 'custom' && !tone_custom) {
    return { error: 'tone="custom" requires a non-empty tone_custom' };
  }
  const reply_latency = LATENCIES.includes(r.reply_latency as ReplyLatency)
    ? (r.reply_latency as ReplyLatency) : 'normal';
  const mannerisms = Array.isArray(r.mannerisms)
    ? r.mannerisms.filter((m): m is string => typeof m === 'string').slice(0, 12)
    : [];
  const language = typeof r.language === 'string' && r.language
    ? r.language.slice(0, 8) : null;
  const signature = typeof r.signature === 'string' && r.signature
    ? r.signature : null;
  const active_hours = typeof r.active_hours === 'string' && r.active_hours
    ? r.active_hours : '09:00-18:00';
  return {
    ok: {
      name, email, role, tone, tone_custom, mannerisms, language, signature,
      active_hours, reply_latency,
      uses_llms_heavily: r.uses_llms_heavily === true,
    },
  };
}

export interface MergeResult {
  merged: EmailPersona[];
  added: number;
  replaced: number;
}

/** Dedupe by lowercased email; uploaded entries replace existing matches. */
export function mergePersonas(current: EmailPersona[], incoming: EmailPersona[]): MergeResult {
  const byEmail = new Map<string, EmailPersona>();
  for (const p of current) byEmail.set(p.email.toLowerCase(), p);
  let added = 0;
  let replaced = 0;
  for (const p of incoming) {
    const key = p.email.toLowerCase();
    if (byEmail.has(key)) replaced += 1;
    else added += 1;
    byEmail.set(key, p);
  }
  return { merged: Array.from(byEmail.values()), added, replaced };
}
