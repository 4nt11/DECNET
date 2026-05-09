/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { makeAttacker } from '../../test/fixtures';

// Stub the SSE hooks — they would otherwise open EventSource connections
// jsdom can't serve. The hook under test only cares that the callbacks
// it passes are wired up, not what they receive in isolation.
vi.mock('../useAttackerStream', () => ({
  useAttackerStream: vi.fn(),
}));
vi.mock('../useIdentityStream', () => ({
  useIdentityStream: vi.fn(),
}));

// Suppress the alert() the hook fires on a 422 command-filter response.
beforeEach(() => {
  vi.stubGlobal('alert', vi.fn());
});

import { useAttackerDetail } from './useAttackerDetail';

const ID = '11111111-1111-1111-1111-111111111111';

const attackerHandler = (body: unknown, status = 200) =>
  http.get(apiUrl(`/attackers/${ID}`), () =>
    HttpResponse.json(body, { status }),
  );

const stockHandlers = () => [
  attackerHandler(makeAttacker()),
  http.get(apiUrl(`/attackers/${ID}/attribution`), () =>
    HttpResponse.json({ primitives: [] }),
  ),
  http.get(apiUrl(`/attackers/${ID}/commands`), ({ request }) => {
    const url = new URL(request.url);
    const offset = Number(url.searchParams.get('offset') ?? 0);
    return HttpResponse.json({
      data: [{
        service: 'ssh',
        decky: 'decoy-01',
        command: `cmd-offset-${offset}`,
        timestamp: '2026-05-09T11:00:00Z',
      }],
      total: 137,
    });
  }),
  http.get(apiUrl(`/attackers/${ID}/artifacts`), () =>
    HttpResponse.json({ data: [] }),
  ),
  http.get(apiUrl(`/attackers/${ID}/smtp-targets`), () =>
    HttpResponse.json({ data: [] }),
  ),
  http.get(apiUrl(`/attackers/${ID}/mail`), () =>
    HttpResponse.json({ data: [] }),
  ),
  http.get(apiUrl(`/attackers/${ID}/transcripts`), () =>
    HttpResponse.json({ data: [] }),
  ),
];

describe('useAttackerDetail', () => {
  it('loads attacker data and clears loading on success', async () => {
    server.use(...stockHandlers());

    const { result } = renderHook(() => useAttackerDetail(ID));

    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.error).toBeNull();
    expect(result.current.attacker?.uuid).toBe(ID);
    expect(result.current.cmdTotal).toBe(137);
    expect(result.current.commands[0]?.command).toBe('cmd-offset-0');
  });

  it('reports ATTACKER NOT FOUND on 404', async () => {
    server.use(
      attackerHandler({ detail: 'not found' }, 404),
      // remaining handlers degrade gracefully
      http.get(apiUrl(`/attackers/${ID}/attribution`), () =>
        HttpResponse.json({ primitives: [] }),
      ),
      http.get(apiUrl(`/attackers/${ID}/commands`), () =>
        HttpResponse.json({ data: [], total: 0 }),
      ),
      http.get(apiUrl(`/attackers/${ID}/artifacts`), () =>
        HttpResponse.json({ data: [] }),
      ),
      http.get(apiUrl(`/attackers/${ID}/smtp-targets`), () =>
        HttpResponse.json({ data: [] }),
      ),
      http.get(apiUrl(`/attackers/${ID}/mail`), () =>
        HttpResponse.json({ data: [] }),
      ),
      http.get(apiUrl(`/attackers/${ID}/transcripts`), () =>
        HttpResponse.json({ data: [] }),
      ),
    );

    const { result } = renderHook(() => useAttackerDetail(ID));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('ATTACKER NOT FOUND');
    expect(result.current.attacker).toBeNull();
  });

  it('refetches commands on cmdPage change with paged offset', async () => {
    server.use(...stockHandlers());

    const { result } = renderHook(() => useAttackerDetail(ID));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.commands[0]?.command).toBe('cmd-offset-0');

    act(() => result.current.setCmdPage(3));

    await waitFor(() =>
      expect(result.current.commands[0]?.command).toBe('cmd-offset-100'),
    );
    expect(result.current.cmdPage).toBe(3);
  });

  it('resets cmdPage to 1 when serviceFilter changes', async () => {
    server.use(...stockHandlers());

    const { result } = renderHook(() => useAttackerDetail(ID));
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => result.current.setCmdPage(4));
    await waitFor(() => expect(result.current.cmdPage).toBe(4));

    act(() => result.current.setServiceFilter('ssh'));
    await waitFor(() => expect(result.current.cmdPage).toBe(1));
    expect(result.current.serviceFilter).toBe('ssh');
  });

  it('flags mailForbidden on 403', async () => {
    server.use(
      ...stockHandlers().filter(
        (h) => !h.info.path.endsWith('/mail'),
      ),
      http.get(apiUrl(`/attackers/${ID}/mail`), () =>
        HttpResponse.json({ detail: 'forbidden' }, { status: 403 }),
      ),
    );

    const { result } = renderHook(() => useAttackerDetail(ID));

    await waitFor(() => expect(result.current.mailForbidden).toBe(true));
    expect(result.current.mail).toEqual([]);
  });
});
