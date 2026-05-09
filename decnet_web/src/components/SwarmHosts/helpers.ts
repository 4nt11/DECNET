import type { ApiError } from '../../utils/api';

export const AGENT_NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export const shortFp = (fp: string): string =>
  (fp ? fp.slice(0, 16) + '…' : '—');

export function extractErrorDetail(err: unknown, fallback: string): string {
  const e = err as ApiError;
  if (e?.response?.data?.detail) return e.response.data.detail;
  if (e?.response?.status === 403) return 'Insufficient permissions (admin only)';
  if (e?.response?.status === 401) return 'Session expired — please log in again';
  if (e?.message) return e.message;
  return fallback;
}

/** Seconds remaining until the bundle expires, clamped to >= 0. */
export function bundleSecondsLeft(expiresAt: string, now: number): number {
  const t = new Date(expiresAt).getTime();
  if (Number.isNaN(t)) return 0;
  return Math.max(0, Math.floor((t - now) / 1000));
}

export function formatMmSs(seconds: number): { mm: string; ss: string } {
  return {
    mm: Math.floor(seconds / 60).toString().padStart(2, '0'),
    ss: (seconds % 60).toString().padStart(2, '0'),
  };
}
