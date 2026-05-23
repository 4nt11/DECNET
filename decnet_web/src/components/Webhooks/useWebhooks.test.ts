// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { useWebhooks } from './useWebhooks';
import type { WebhookRow, WebhookSavePayload } from './types';

const row = (over: Partial<WebhookRow> = {}): WebhookRow => ({
  uuid: 'wh-1',
  name: 'shuffle',
  url: 'https://shuffle.example.com/h/x',
  topic_patterns: ['attacker.>'],
  enabled: true,
  consecutive_failures: 0,
  last_success_at: null,
  last_failure_at: null,
  last_error: null,
  auto_disabled_at: null,
  created_at: '2026-05-01T00:00:00Z',
  updated_at: '2026-05-01T00:00:00Z',
  warnings: [],
  ...over,
});

const payload: WebhookSavePayload = {
  name: 'x', url: 'https://y/z', simple_events: ['SystemStatus'],
  topic_patterns: [], enabled: true,
};

describe('useWebhooks', () => {
  it('loads /webhooks/ on mount', async () => {
    server.use(
      http.get(apiUrl('/webhooks/'), () => HttpResponse.json([row()])),
    );
    const { result } = renderHook(() => useWebhooks());
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.webhooks).toHaveLength(1);
    expect(result.current.error).toBeNull();
  });

  it('surfaces error on load failure', async () => {
    server.use(
      http.get(apiUrl('/webhooks/'), () =>
        HttpResponse.json({ detail: 'forbidden' }, { status: 403 }),
      ),
    );
    const { result } = renderHook(() => useWebhooks());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('forbidden');
  });

  it('createWebhook returns secret on success and reloads', async () => {
    let calls = 0;
    server.use(
      http.get(apiUrl('/webhooks/'), () => { calls += 1; return HttpResponse.json([]); }),
      http.post(apiUrl('/webhooks/'), () =>
        HttpResponse.json({ name: 'x', secret: 'plaintext-secret-once' }),
      ),
    );
    const { result } = renderHook(() => useWebhooks());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(calls).toBe(1);

    let r: Awaited<ReturnType<typeof result.current.createWebhook>> | undefined;
    await act(async () => { r = await result.current.createWebhook(payload); });
    expect(r?.ok).toBe(true);
    expect(r?.data?.secret).toBe('plaintext-secret-once');
    expect(calls).toBeGreaterThan(1);
  });

  it('updateWebhook surfaces server detail on failure', async () => {
    server.use(
      http.get(apiUrl('/webhooks/'), () => HttpResponse.json([row()])),
      http.patch(apiUrl('/webhooks/wh-1'), () =>
        HttpResponse.json({ detail: 'too long' }, { status: 400 }),
      ),
    );
    const { result } = renderHook(() => useWebhooks());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.updateWebhook>> | undefined;
    await act(async () => { r = await result.current.updateWebhook('wh-1', payload); });
    expect(r).toEqual({ ok: false, reason: 'too long' });
  });

  it('removeWebhook reports ok on 204', async () => {
    server.use(
      http.get(apiUrl('/webhooks/'), () => HttpResponse.json([row()])),
      http.delete(apiUrl('/webhooks/wh-1'), () => new HttpResponse(null, { status: 204 })),
    );
    const { result } = renderHook(() => useWebhooks());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.removeWebhook>> | undefined;
    await act(async () => { r = await result.current.removeWebhook('wh-1'); });
    expect(r).toEqual({ ok: true });
  });

  it('testWebhook surfaces delivery result', async () => {
    server.use(
      http.get(apiUrl('/webhooks/'), () => HttpResponse.json([row()])),
      http.post(apiUrl('/webhooks/wh-1/test'), () =>
        HttpResponse.json({ delivered: true, status_code: 200 }),
      ),
    );
    const { result } = renderHook(() => useWebhooks());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.testWebhook>> | undefined;
    await act(async () => { r = await result.current.testWebhook('wh-1'); });
    expect(r?.ok).toBe(true);
    expect(r?.data?.delivered).toBe(true);
    expect(r?.data?.status_code).toBe(200);
  });
});
