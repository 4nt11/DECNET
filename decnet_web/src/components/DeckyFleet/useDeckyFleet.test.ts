// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { makeDecky } from '../../test/fixtures';

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.useRealTimers();
});

import { useDeckyFleet } from './useDeckyFleet';

const stockHandlers = (mode: 'unihost' | 'swarm' = 'unihost') => [
  http.get(apiUrl('/system/deployment-mode'), () =>
    HttpResponse.json({ mode, swarm_host_count: mode === 'swarm' ? 2 : 0 }),
  ),
  http.get(apiUrl('/config'), () => HttpResponse.json({ role: 'admin' })),
  http.get(apiUrl('/topologies/archetypes'), () =>
    HttpResponse.json({
      archetypes: [
        { slug: 'web-server', display_name: 'Web Server', services: ['http'] },
      ],
    }),
  ),
  http.get(apiUrl('/deckies'), () => HttpResponse.json([makeDecky({ name: 'd1' })])),
  http.get(apiUrl('/swarm/deckies'), () => HttpResponse.json([])),
];

describe('useDeckyFleet', () => {
  it('loads deckies + role + deploy-mode + archetypes on mount', async () => {
    server.use(...stockHandlers());

    const { result } = renderHook(() => useDeckyFleet());

    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.isAdmin).toBe(true);
    expect(result.current.deckies).toHaveLength(1);
    expect(result.current.deckies[0].name).toBe('d1');
    expect(result.current.deployMode?.mode).toBe('unihost');
    expect(result.current.isSwarm).toBe(false);
    expect(result.current.archetypes[0]?.slug).toBe('web-server');
  });

  it('switches to /swarm/deckies + normalizes the swarm shape when mode=swarm', async () => {
    server.use(
      ...stockHandlers('swarm').filter(
        (h) => typeof h.info.path !== 'string' || h.info.path !== apiUrl('/swarm/deckies'),
      ),
      http.get(apiUrl('/swarm/deckies'), () =>
        HttpResponse.json([
          {
            decky_name: 'sd1',
            decky_ip: '10.1.1.1',
            host_uuid: 'h-1',
            host_name: 'edge-1',
            host_address: 'edge-1.example',
            host_status: 'ok',
            services: ['ssh'],
            state: 'running',
            last_error: null,
            last_seen: null,
            hostname: 'sd1.local',
            distro: 'debian-12',
            archetype: 'workstation',
            service_config: {},
            mutate_interval: null,
            last_mutated: 0,
          },
        ]),
      ),
    );

    const { result } = renderHook(() => useDeckyFleet());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isSwarm).toBe(true);
    expect(result.current.deckies).toHaveLength(1);
    expect(result.current.deckies[0].name).toBe('sd1');
    expect(result.current.deckies[0].swarm?.host_uuid).toBe('h-1');
  });

  it('mutate(name) resolves ok and triggers a refetch', async () => {
    let listCalls = 0;
    server.use(
      ...stockHandlers().filter(
        (h) => typeof h.info.path !== 'string' || h.info.path !== apiUrl('/deckies'),
      ),
      http.get(apiUrl('/deckies'), () => {
        listCalls += 1;
        return HttpResponse.json([makeDecky({ name: 'd1' })]);
      }),
      http.post(apiUrl('/deckies/d1/mutate'), () => HttpResponse.json({})),
    );

    const { result } = renderHook(() => useDeckyFleet());
    await waitFor(() => expect(result.current.loading).toBe(false));
    const initialListCalls = listCalls;

    let mutateResult: Awaited<ReturnType<typeof result.current.mutate>> | undefined;
    await act(async () => {
      mutateResult = await result.current.mutate('d1');
    });
    expect(mutateResult).toEqual({ ok: true });
    // mutate triggers a refetch; list endpoint should have hit again
    expect(listCalls).toBeGreaterThan(initialListCalls);
  });

  it('mutate returns { ok:false, reason:"error" } on a 500', async () => {
    server.use(
      ...stockHandlers(),
      http.post(apiUrl('/deckies/d1/mutate'), () =>
        HttpResponse.json({ detail: 'boom' }, { status: 500 }),
      ),
    );

    const { result } = renderHook(() => useDeckyFleet());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let mutateResult: Awaited<ReturnType<typeof result.current.mutate>> | undefined;
    await act(async () => {
      mutateResult = await result.current.mutate('d1');
    });
    expect(mutateResult).toEqual({ ok: false, reason: 'error' });
  });

  it('teardown returns { ok:true } on success and refetches', async () => {
    server.use(
      ...stockHandlers('swarm'),
      http.get(apiUrl('/swarm/deckies'), () => HttpResponse.json([])),
      http.post(apiUrl('/swarm/hosts/h-1/teardown'), () => HttpResponse.json({})),
    );

    const { result } = renderHook(() => useDeckyFleet());
    await waitFor(() => expect(result.current.loading).toBe(false));

    const swarmDecky = makeDecky({
      name: 'd-td',
      swarm: {
        host_uuid: 'h-1',
        host_name: 'edge-1',
        host_address: 'edge-1.example',
        host_status: 'ok',
        state: 'running',
        last_error: null,
        last_seen: null,
      },
    });
    let tdResult: Awaited<ReturnType<typeof result.current.teardown>> | undefined;
    await act(async () => {
      tdResult = await result.current.teardown(swarmDecky);
    });
    expect(tdResult).toEqual({ ok: true });
  });

  it('applyServicesChange optimistically rewrites the matching row', async () => {
    server.use(...stockHandlers());

    const { result } = renderHook(() => useDeckyFleet());
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => result.current.applyServicesChange('d1', ['ssh', 'http']));
    expect(result.current.deckies[0].services).toEqual(['ssh', 'http']);
  });
});
