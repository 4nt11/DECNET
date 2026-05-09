import type { ApiError } from '../../utils/api';
import type { FormState, SimpleEvent } from './types';

// Server-side canonical expansions (mirrors decnet/webhook/enums.py). Kept
// in sync manually; this is the sugar layer, not the source of truth.
export const SIMPLE_PRESETS: Record<SimpleEvent, string[]> = {
  AttackerDetail: ['attacker.>'],
  DeckyStatus: ['decky.*.state', 'decky.*.traffic'],
  SystemStatus: ['system.>'],
};

export const BLANK_FORM: FormState = {
  name: '',
  url: '',
  secret: '',
  simple_events: [],
  topic_patterns: '',
  enabled: true,
};

export function extractErrorDetail(err: unknown, fallback: string): string {
  const e = err as ApiError;
  if (e?.response?.data?.detail) return e.response.data.detail;
  if (e?.response?.status === 403) return 'Insufficient permissions (admin only)';
  if (e?.response?.status === 401) return 'Session expired — please log in again';
  if (e?.message) return e.message;
  return fallback;
}

/** Derive which simple-event checkboxes should show as ticked for a given
 *  persisted pattern list. Only ticks when the intersection is exact —
 *  mixed custom + preset leaves everything unticked and the textarea is
 *  the source of truth. */
export function deriveSimpleEvents(patterns: string[]): SimpleEvent[] {
  const ticked: SimpleEvent[] = [];
  const remaining = new Set(patterns);
  for (const [name, preset] of Object.entries(SIMPLE_PRESETS) as [SimpleEvent, string[]][]) {
    if (preset.every((p) => remaining.has(p))) {
      ticked.push(name);
      preset.forEach((p) => remaining.delete(p));
    }
  }
  // If anything outside the presets remains, don't tick — user sees raw.
  if (remaining.size > 0) return [];
  return ticked;
}

export function formatDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Translate the on-screen form state into the request body the API
 *  expects. Splits the textarea into a clean string[]. */
export function formToPayload(form: FormState): {
  name: string;
  url: string;
  secret?: string;
  simple_events: SimpleEvent[];
  topic_patterns: string[];
  enabled: boolean;
} {
  const rawPatterns = form.topic_patterns
    .split('\n').map((s) => s.trim()).filter(Boolean);
  return {
    name: form.name.trim(),
    url: form.url.trim(),
    secret: form.secret ? form.secret : undefined,
    simple_events: form.simple_events,
    topic_patterns: rawPatterns,
    enabled: form.enabled,
  };
}
