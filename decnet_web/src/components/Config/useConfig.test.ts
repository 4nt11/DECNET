/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';

import { useConfig } from './useConfig';

const adminConfigHandlers = () => [
  http.get(apiUrl('/config'), () =>
    HttpResponse.json({
      role: 'admin',
      deployment_limit: 50,
      global_mutation_interval: '30m',
      users: [
        { uuid: 'u-1', username: 'alice', role: 'admin', must_change_password: false },
      ],
      developer_mode: true,
    }),
  ),
];

describe('useConfig', () => {
  it('loads /config on mount and surfaces isAdmin from the role', async () => {
    server.use(...adminConfigHandlers());
    const { result } = renderHook(() => useConfig());
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isAdmin).toBe(true);
    expect(result.current.config?.deployment_limit).toBe(50);
  });

  it('setDeploymentLimit returns ok on 200 and reloads', async () => {
    server.use(
      ...adminConfigHandlers(),
      http.put(apiUrl('/config/deployment-limit'), () => HttpResponse.json({})),
    );
    const { result } = renderHook(() => useConfig());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.setDeploymentLimit>> | undefined;
    await act(async () => { r = await result.current.setDeploymentLimit(120); });
    expect(r).toEqual({ ok: true });
  });

  it('setDeploymentLimit surfaces server detail on error', async () => {
    server.use(
      ...adminConfigHandlers(),
      http.put(apiUrl('/config/deployment-limit'), () =>
        HttpResponse.json({ detail: 'too high' }, { status: 400 }),
      ),
    );
    const { result } = renderHook(() => useConfig());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.setDeploymentLimit>> | undefined;
    await act(async () => { r = await result.current.setDeploymentLimit(999); });
    expect(r).toEqual({ ok: false, reason: 'too high' });
  });

  it('addUser returns ok and reloads', async () => {
    server.use(
      ...adminConfigHandlers(),
      http.post(apiUrl('/config/users'), () => HttpResponse.json({})),
    );
    const { result } = renderHook(() => useConfig());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.addUser>> | undefined;
    await act(async () => {
      r = await result.current.addUser({
        username: 'bob', password: 'hunter22ish', role: 'viewer',
      });
    });
    expect(r).toEqual({ ok: true });
  });

  it('deleteUser surfaces error detail', async () => {
    server.use(
      ...adminConfigHandlers(),
      http.delete(apiUrl('/config/users/u-1'), () =>
        HttpResponse.json({ detail: 'cannot delete last admin' }, { status: 409 }),
      ),
    );
    const { result } = renderHook(() => useConfig());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.deleteUser>> | undefined;
    await act(async () => { r = await result.current.deleteUser('u-1'); });
    expect(r).toEqual({ ok: false, reason: 'cannot delete last admin' });
  });

  it('reinit returns deleted totals on success', async () => {
    server.use(
      ...adminConfigHandlers(),
      http.delete(apiUrl('/config/reinit'), () =>
        HttpResponse.json({ deleted: { logs: 1234, bounties: 7, attackers: 42 } }),
      ),
    );
    const { result } = renderHook(() => useConfig());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.reinit>> | undefined;
    await act(async () => { r = await result.current.reinit(); });
    expect(r).toEqual({ ok: true, deleted: { logs: 1234, bounties: 7, attackers: 42 } });
  });
});
