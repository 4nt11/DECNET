// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { makeCanaryToken, makeCanaryBlob } from '../../test/fixtures';

import { useCanaryTokens } from './useCanaryTokens';

const stockHandlers = () => [
  http.get(apiUrl('/canary/tokens'), () =>
    HttpResponse.json({ tokens: [makeCanaryToken({ uuid: 't-1' })] }),
  ),
  http.get(apiUrl('/canary/blobs'), () =>
    HttpResponse.json({ blobs: [makeCanaryBlob({ uuid: 'b-1' })] }),
  ),
  http.get(apiUrl('/deckies'), () => HttpResponse.json([{ name: 'd1' }])),
  http.get(apiUrl('/topologies/'), () =>
    HttpResponse.json({ data: [{ id: 't-x', name: 'corp', status: 'active' }] }),
  ),
];

describe('useCanaryTokens', () => {
  it('loads tokens + blobs + deckies + topologies on mount', async () => {
    server.use(...stockHandlers());

    const { result } = renderHook(() => useCanaryTokens());
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.tokens).toHaveLength(1);
    expect(result.current.blobs).toHaveLength(1);
    expect(result.current.deckies).toEqual([{ name: 'd1' }]);
    expect(result.current.topologies[0]?.id).toBe('t-x');
  });

  it('silently treats viewer 403 on /canary/blobs as an empty list', async () => {
    server.use(
      ...stockHandlers().filter((h) =>
        typeof h.info.path === 'string' && h.info.path !== apiUrl('/canary/blobs'),
      ),
      http.get(apiUrl('/canary/blobs'), () =>
        HttpResponse.json({ detail: 'forbidden' }, { status: 403 }),
      ),
    );

    const { result } = renderHook(() => useCanaryTokens());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.blobs).toEqual([]);
    expect(result.current.error).toBeNull();
  });

  it('deleteBlob returns ok and removes the blob from state', async () => {
    server.use(
      ...stockHandlers(),
      http.delete(apiUrl('/canary/blobs/b-1'), () => HttpResponse.json({})),
    );

    const { result } = renderHook(() => useCanaryTokens());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.deleteBlob>> | undefined;
    await act(async () => {
      r = await result.current.deleteBlob('b-1');
    });
    expect(r).toEqual({ ok: true });
    expect(result.current.blobs).toEqual([]);
  });

  it('deleteBlob surfaces server-side detail when refused', async () => {
    server.use(
      ...stockHandlers(),
      http.delete(apiUrl('/canary/blobs/b-1'), () =>
        HttpResponse.json({ detail: 'still referenced by 3 tokens' }, { status: 409 }),
      ),
    );

    const { result } = renderHook(() => useCanaryTokens());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.deleteBlob>> | undefined;
    await act(async () => {
      r = await result.current.deleteBlob('b-1');
    });
    expect(r).toEqual({ ok: false, reason: 'still referenced by 3 tokens' });
    expect(result.current.blobs).toHaveLength(1);
  });

  it('markTokenRevoked flips the state to revoked', async () => {
    server.use(...stockHandlers());

    const { result } = renderHook(() => useCanaryTokens());
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => result.current.markTokenRevoked('t-1'));
    expect(result.current.tokens[0].state).toBe('revoked');
  });
});
