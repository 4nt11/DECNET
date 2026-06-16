// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../test/server';
import { useLifecyclePolling, type LifecycleRow } from './useLifecyclePolling';

const row = (over: Partial<LifecycleRow>): LifecycleRow => ({
  id: 'lid-1',
  decky_name: 'decky-01',
  host_uuid: null,
  operation: 'deploy',
  status: 'pending',
  error: null,
  started_at: '2026-05-22T00:00:00Z',
  updated_at: '2026-05-22T00:00:00Z',
  completed_at: null,
  ...over,
});

describe('useLifecyclePolling', () => {
  it('returns no rows and done=false for empty ids', () => {
    const { result } = renderHook(() => useLifecyclePolling([]));
    expect(result.current.rows).toEqual([]);
    expect(result.current.done).toBe(false);
  });

  it('fetches once and marks done when all rows are terminal', async () => {
    server.use(
      http.get(apiUrl('/deckies/lifecycle'), () =>
        HttpResponse.json({
          rows: [row({ id: 'lid-1', status: 'succeeded', completed_at: 'ts' })],
        }),
      ),
    );
    const { result } = renderHook(() => useLifecyclePolling(['lid-1'], 20));
    await waitFor(() => expect(result.current.done).toBe(true));
    expect(result.current.rows).toHaveLength(1);
    expect(result.current.rows[0].status).toBe('succeeded');
    expect(result.current.error).toBeNull();
  });

  it('keeps polling while at least one row is non-terminal', async () => {
    let hits = 0;
    server.use(
      http.get(apiUrl('/deckies/lifecycle'), () => {
        hits++;
        return HttpResponse.json({
          rows: hits < 2
            ? [row({ id: 'lid-1', status: 'running' })]
            : [row({ id: 'lid-1', status: 'succeeded', completed_at: 'ts' })],
        });
      }),
    );
    const { result } = renderHook(() => useLifecyclePolling(['lid-1'], 20));
    await waitFor(() => expect(result.current.done).toBe(true));
    expect(hits).toBeGreaterThanOrEqual(2);
  });

  it('surfaces error and keeps retrying on HTTP failure', async () => {
    server.use(
      http.get(apiUrl('/deckies/lifecycle'), () =>
        HttpResponse.json({ detail: 'server error' }, { status: 500 }),
      ),
    );
    const { result } = renderHook(() => useLifecyclePolling(['lid-1'], 20));
    await waitFor(() => expect(result.current.error).not.toBeNull());
    expect(result.current.done).toBe(false);
  });
});
