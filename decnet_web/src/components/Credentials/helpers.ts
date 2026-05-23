// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CredentialEntry, CredentialReuseRow, SortDir } from './types';

export const CREDS_LIMIT = 50;
export const REUSE_LIMIT = 25;
export const REUSE_MAP_CAP = 500;

export const truncHash = (h: string | null | undefined, n = 12): string =>
  h ? `${h.slice(0, n)}…` : '—';

export const reuseKey = (
  sha: string,
  kind: string,
  principal: string | null,
): string => `${sha}|${kind}|${principal ?? ''}`;

type CredSortCol = 'seen' | 'decky' | 'svc' | 'attacker' | 'principal' | 'kind' | 'hits' | '';

export function sortCreds(
  rows: CredentialEntry[],
  col: CredSortCol,
  dir: SortDir,
): CredentialEntry[] {
  if (!col) return rows;
  const pick = (r: CredentialEntry): string | number => {
    switch (col) {
      case 'seen': return r.last_seen;
      case 'decky': return r.decky_name;
      case 'svc': return r.service;
      case 'attacker': return r.attacker_ip;
      case 'principal': return r.principal ?? '';
      case 'kind': return r.secret_kind;
      case 'hits': return r.attempt_count;
      default: return '';
    }
  };
  return [...rows].sort((a, b) => {
    const av = pick(a); const bv = pick(b);
    const cmp = typeof av === 'number' && typeof bv === 'number'
      ? av - bv
      : String(av).localeCompare(String(bv));
    return dir === 'asc' ? cmp : -cmp;
  });
}

type ReuseSortCol = 'seen' | 'principal' | 'kind' | 'targets' | 'attempts' | '';

export function sortReuse(
  rows: CredentialReuseRow[],
  col: ReuseSortCol,
  dir: SortDir,
): CredentialReuseRow[] {
  if (!col) return rows;
  const pick = (r: CredentialReuseRow): string | number => {
    switch (col) {
      case 'seen': return r.last_seen;
      case 'principal': return r.principal ?? '';
      case 'kind': return r.secret_kind;
      case 'targets': return r.target_count;
      case 'attempts': return r.attempt_count;
      default: return '';
    }
  };
  return [...rows].sort((a, b) => {
    const av = pick(a); const bv = pick(b);
    const cmp = typeof av === 'number' && typeof bv === 'number'
      ? av - bv
      : String(av).localeCompare(String(bv));
    return dir === 'asc' ? cmp : -cmp;
  });
}

/** Cycle a sort column through asc → desc → off when clicked. */
export function nextSortState(
  current: { col: string; dir: SortDir },
  clicked: string,
): { col: string; dir: SortDir } {
  if (current.col !== clicked) return { col: clicked, dir: 'asc' };
  if (current.dir === 'asc') return { col: clicked, dir: 'desc' };
  return { col: '', dir: 'asc' };
}
