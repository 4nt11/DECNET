// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { useSwarmHosts } from './useSwarmHosts';
import type { SwarmHost } from './types';

const host = (over: Partial<SwarmHost> = {}): SwarmHost => ({
  uuid: 'h-1',
  name: 'agent-1',
  address: '10.0.0.10',
  agent_port: 8443,
  status: 'active',
  last_heartbeat: '2026-05-01T00:00:00Z',
  client_cert_fingerprint: 'a'.repeat(64),
  updater_cert_fingerprint: null,
  enrolled_at: '2026-05-01T00:00:00Z',
  notes: null,
  ...over,
});

describe('useSwarmHosts', () => {
  it('loads /swarm/hosts on mount', async () => {
    server.use(
      http.get(apiUrl('/swarm/hosts'), () => HttpResponse.json([host()])),
    );
    const { result } = renderHook(() => useSwarmHosts());
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.hosts).toHaveLength(1);
  });

  it('surfaces error on load failure', async () => {
    server.use(
      http.get(apiUrl('/swarm/hosts'), () =>
        HttpResponse.json({ detail: 'forbidden' }, { status: 403 }),
      ),
    );
    const { result } = renderHook(() => useSwarmHosts());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('forbidden');
  });

  it('teardownHost reports ok and reloads', async () => {
    let calls = 0;
    server.use(
      http.get(apiUrl('/swarm/hosts'), () => { calls += 1; return HttpResponse.json([host()]); }),
      http.post(apiUrl('/swarm/hosts/h-1/teardown'), () =>
        new HttpResponse(null, { status: 202 }),
      ),
    );
    const { result } = renderHook(() => useSwarmHosts());
    await waitFor(() => expect(result.current.loading).toBe(false));
    const before = calls;

    let r: Awaited<ReturnType<typeof result.current.teardownHost>> | undefined;
    await act(async () => { r = await result.current.teardownHost('h-1'); });
    expect(r).toEqual({ ok: true });
    expect(calls).toBeGreaterThan(before);
  });

  it('decommissionHost surfaces server reason on failure', async () => {
    server.use(
      http.get(apiUrl('/swarm/hosts'), () => HttpResponse.json([host()])),
      http.delete(apiUrl('/swarm/hosts/h-1'), () =>
        HttpResponse.json({ detail: 'cannot remove last host' }, { status: 400 }),
      ),
    );
    const { result } = renderHook(() => useSwarmHosts());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.decommissionHost>> | undefined;
    await act(async () => { r = await result.current.decommissionHost('h-1'); });
    expect(r).toEqual({ ok: false, reason: 'cannot remove last host' });
  });

  it('generateBundle returns the bundle on success', async () => {
    server.use(
      http.get(apiUrl('/swarm/hosts'), () => HttpResponse.json([])),
      http.post(apiUrl('/swarm/enroll-bundle'), () =>
        HttpResponse.json({
          token: 'abc', host_uuid: 'h-9',
          command: 'curl … | bash', expires_at: '2026-05-09T08:05:00Z',
        }),
      ),
    );
    const { result } = renderHook(() => useSwarmHosts());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.generateBundle>> | undefined;
    await act(async () => {
      r = await result.current.generateBundle({
        master_host: 'master.local',
        agent_name: 'a-1',
        with_updater: true,
        use_ipvlan: false,
        services_ini: null,
      });
    });
    expect(r?.ok).toBe(true);
    expect(r?.ok && r.data?.host_uuid).toBe('h-9');
  });

  it('polls /swarm/hosts every 10s', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let calls = 0;
      server.use(
        http.get(apiUrl('/swarm/hosts'), () => { calls += 1; return HttpResponse.json([]); }),
      );
      const { result } = renderHook(() => useSwarmHosts());
      await waitFor(() => expect(result.current.loading).toBe(false));
      const initial = calls;

      await act(async () => { vi.advanceTimersByTime(10_500); });
      await waitFor(() => expect(calls).toBeGreaterThan(initial));
    } finally {
      vi.useRealTimers();
    }
  });
});
