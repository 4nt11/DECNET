// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ApiError } from '../../utils/api';

/** Normalize an axios error into operator-friendly text, with role
 *  hints when the wire shape carries no detail. */
export function extractError(err: unknown, fallback: string): string {
  const e = err as ApiError;
  if (e?.response?.data?.detail) return e.response.data.detail;
  if (e?.response?.status === 403) return 'Insufficient permissions (admin only).';
  if (e?.response?.status === 401) return 'Session expired — please log in again.';
  return fallback;
}

/** Compact local-time YYYY-MM-DD HH:mm; returns "—" for null and the
 *  raw input back when it's not a parseable ISO string. */
export function fmt(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** B / KiB / MiB binary-prefix file-size renderer. */
export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}
