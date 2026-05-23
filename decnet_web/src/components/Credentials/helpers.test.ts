// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import {
  nextSortState, reuseKey, sortCreds, sortReuse, truncHash,
} from './helpers';
import type { CredentialEntry, CredentialReuseRow } from './types';

describe('truncHash', () => {
  it('truncates and appends ellipsis', () => {
    expect(truncHash('abcdef1234567890fedcba')).toBe('abcdef123456…');
    expect(truncHash('abcdef1234567890', 4)).toBe('abcd…');
  });
  it('returns em-dash for null/undefined', () => {
    expect(truncHash(null)).toBe('—');
    expect(truncHash(undefined)).toBe('—');
  });
});

describe('reuseKey', () => {
  it('joins sha|kind|principal with empty string for null principal', () => {
    expect(reuseKey('abc', 'plaintext', 'admin')).toBe('abc|plaintext|admin');
    expect(reuseKey('abc', 'sha512crypt', null)).toBe('abc|sha512crypt|');
  });
});

describe('nextSortState', () => {
  it('switches to a new column with asc', () => {
    expect(nextSortState({ col: '', dir: 'asc' }, 'svc')).toEqual({ col: 'svc', dir: 'asc' });
    expect(nextSortState({ col: 'kind', dir: 'desc' }, 'svc')).toEqual({ col: 'svc', dir: 'asc' });
  });
  it('cycles asc → desc → off on the same column', () => {
    expect(nextSortState({ col: 'svc', dir: 'asc' }, 'svc')).toEqual({ col: 'svc', dir: 'desc' });
    expect(nextSortState({ col: 'svc', dir: 'desc' }, 'svc')).toEqual({ col: '', dir: 'asc' });
  });
});

const cred = (over: Partial<CredentialEntry> = {}): CredentialEntry => ({
  id: 1, last_seen: '2026-05-01T00:00:00Z', decky_name: 'd1', service: 'ssh',
  attacker_ip: '1.2.3.4', principal: 'root', secret_sha256: 'a',
  secret_kind: 'plaintext', secret_printable: 'p', attempt_count: 5,
  ...over,
} as CredentialEntry);

describe('sortCreds', () => {
  it('returns the input untouched for empty col', () => {
    const rows = [cred({ id: 1 }), cred({ id: 2 })];
    expect(sortCreds(rows, '', 'asc')).toBe(rows);
  });
  it('sorts numbers numerically (asc/desc)', () => {
    const rows = [cred({ attempt_count: 3 }), cred({ attempt_count: 10 }), cred({ attempt_count: 1 })];
    expect(sortCreds(rows, 'hits', 'asc').map((r) => r.attempt_count)).toEqual([1, 3, 10]);
    expect(sortCreds(rows, 'hits', 'desc').map((r) => r.attempt_count)).toEqual([10, 3, 1]);
  });
  it('sorts strings via localeCompare', () => {
    const rows = [cred({ decky_name: 'beta' }), cred({ decky_name: 'alpha' })];
    expect(sortCreds(rows, 'decky', 'asc').map((r) => r.decky_name)).toEqual(['alpha', 'beta']);
  });
});

const reuse = (over: Partial<CredentialReuseRow> = {}): CredentialReuseRow => ({
  id: '1', last_seen: '2026-05-01T00:00:00Z', principal: null,
  secret_sha256: 'a', secret_kind: 'plaintext',
  target_count: 1, attempt_count: 1, deckies: [], services: [],
  ...over,
} as CredentialReuseRow);

describe('sortReuse', () => {
  it('sorts target counts desc', () => {
    const rows = [reuse({ target_count: 1 }), reuse({ target_count: 9 }), reuse({ target_count: 3 })];
    expect(sortReuse(rows, 'targets', 'desc').map((r) => r.target_count)).toEqual([9, 3, 1]);
  });
});
