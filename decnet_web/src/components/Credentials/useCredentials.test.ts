// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { useCredentials, type UseCredentialsArgs } from './useCredentials';
import type { CredentialEntry, CredentialReuseRow } from './types';

const cred = (over: Partial<CredentialEntry> = {}): CredentialEntry => ({
  id: 'c-1', last_seen: '2026-05-01T00:00:00Z', decky_name: 'd1', service: 'ssh',
  attacker_ip: '1.2.3.4', principal: 'root', secret_sha256: 'a',
  secret_kind: 'plaintext', secret_printable: 'p', attempt_count: 1,
  ...over,
} as CredentialEntry);

const reuse = (over: Partial<CredentialReuseRow> = {}): CredentialReuseRow => ({
  id: 'r-1', last_seen: '2026-05-01T00:00:00Z', principal: 'root',
  secret_sha256: 'a', secret_kind: 'plaintext',
  target_count: 2, attempt_count: 5, deckies: ['d1', 'd2'], services: ['ssh'],
  ...over,
} as CredentialReuseRow);

const baseArgs: UseCredentialsArgs = {
  tab: 'creds', page: 1, query: '', serviceFilter: '', refreshTick: 0,
};

describe('useCredentials', () => {
  it('loads creds on the creds tab and builds the reuse map alongside', async () => {
    server.use(
      http.get(apiUrl('/credentials'), () =>
        HttpResponse.json({ data: [cred()], total: 1 }),
      ),
      http.get(apiUrl('/credential-reuse'), () =>
        HttpResponse.json({ data: [reuse()], total: 1 }),
      ),
    );
    const { result } = renderHook(() => useCredentials(baseArgs));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.creds).toHaveLength(1);
    expect(result.current.credsTotal).toBe(1);
    await waitFor(() => expect(result.current.reuseMap.size).toBe(1));
    expect(result.current.reuseMap.get('a|plaintext|root')?.target_count).toBe(2);
  });

  it('loads reuse rows on the reuse tab', async () => {
    server.use(
      http.get(apiUrl('/credential-reuse'), ({ request }) => {
        const u = new URL(request.url);
        const limit = u.searchParams.get('limit');
        return HttpResponse.json({
          data: [reuse({ id: limit === '25' ? 'page-row' : 'map-row' })],
          total: 1,
        });
      }),
    );
    const { result } = renderHook(() => useCredentials({ ...baseArgs, tab: 'reuse' }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.reuseRows.some((r) => r.id === 'page-row')).toBe(true);
  });

  it('passes search/service/page to /credentials in the query string', async () => {
    let captured: URL | null = null;
    server.use(
      http.get(apiUrl('/credentials'), ({ request }) => {
        captured = new URL(request.url);
        return HttpResponse.json({ data: [], total: 0 });
      }),
      http.get(apiUrl('/credential-reuse'), () =>
        HttpResponse.json({ data: [], total: 0 }),
      ),
    );
    const { result } = renderHook(() =>
      useCredentials({ ...baseArgs, page: 3, query: 'admin', serviceFilter: 'ssh' }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    const url = captured as URL | null;
    expect(url?.searchParams.get('search')).toBe('admin');
    expect(url?.searchParams.get('service')).toBe('ssh');
    expect(url?.searchParams.get('offset')).toBe('100'); // (3 - 1) * 50
  });

  it('fetchReuseDetail returns the row on success', async () => {
    server.use(
      http.get(apiUrl('/credentials'), () => HttpResponse.json({ data: [], total: 0 })),
      http.get(apiUrl('/credential-reuse'), () => HttpResponse.json({ data: [], total: 0 })),
      http.get(apiUrl('/credential-reuse/r-9'), () => HttpResponse.json(reuse({ id: 'r-9' }))),
    );
    const { result } = renderHook(() => useCredentials(baseArgs));
    await waitFor(() => expect(result.current.loading).toBe(false));

    let row: CredentialReuseRow | null | undefined;
    await act(async () => { row = await result.current.fetchReuseDetail('r-9'); });
    expect(row?.id).toBe('r-9');
  });
});
