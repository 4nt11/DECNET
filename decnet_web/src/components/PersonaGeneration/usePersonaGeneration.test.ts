// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse, server, apiUrl } from '../../test/server';
import { usePersonaGeneration } from './usePersonaGeneration';
import { BLANK } from './helpers';
import type { EmailPersona } from './types';

const persona = (over: Partial<EmailPersona> = {}): EmailPersona => ({
  ...BLANK, name: 'Jane', email: 'jane@example.com', role: 'admin', ...over,
});

describe('usePersonaGeneration', () => {
  it('loads global personas from /realism/personas on mount', async () => {
    server.use(
      http.get(apiUrl('/realism/personas'), () =>
        HttpResponse.json({
          path: '/etc/decnet/email_personas.json',
          language_default: 'en',
          personas: [persona({ name: 'Alice', email: 'a@x.com' })],
        }),
      ),
    );
    const { result } = renderHook(() => usePersonaGeneration());
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.personas).toHaveLength(1);
    expect(result.current.path).toBe('/etc/decnet/email_personas.json');
    expect(result.current.languageDefault).toBe('en');
    expect(result.current.error).toBeNull();
  });

  it('loads topology-bound personas from the topology endpoint', async () => {
    server.use(
      http.get(apiUrl('/topologies/topo-1/personas'), () =>
        HttpResponse.json({
          topology_name: 'corp',
          language_default: 'pt',
          personas: [],
        }),
      ),
    );
    const { result } = renderHook(() => usePersonaGeneration('topo-1'));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.topoName).toBe('corp');
    expect(result.current.languageDefault).toBe('pt');
  });

  it('surfaces error when load fails', async () => {
    server.use(
      http.get(apiUrl('/realism/personas'), () =>
        HttpResponse.json({ detail: 'forbidden' }, { status: 403 }),
      ),
    );
    const { result } = renderHook(() => usePersonaGeneration());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('forbidden');
  });

  it('persistPersonas adopts server response on 200', async () => {
    server.use(
      http.get(apiUrl('/realism/personas'), () =>
        HttpResponse.json({ personas: [] }),
      ),
      http.put(apiUrl('/realism/personas'), () =>
        HttpResponse.json({
          path: '/p.json',
          language_default: 'en',
          personas: [persona({ name: 'Bob', email: 'b@x.com' })],
        }),
      ),
    );
    const { result } = renderHook(() => usePersonaGeneration());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.persistPersonas>> | undefined;
    await act(async () => {
      r = await result.current.persistPersonas([persona({ email: 'b@x.com' })]);
    });
    expect(r).toEqual({ ok: true });
    expect(result.current.personas[0]?.name).toBe('Bob');
    expect(result.current.path).toBe('/p.json');
  });

  it('persistPersonas returns reason on server error', async () => {
    server.use(
      http.get(apiUrl('/realism/personas'), () =>
        HttpResponse.json({ personas: [] }),
      ),
      http.put(apiUrl('/realism/personas'), () =>
        HttpResponse.json({ detail: 'boom' }, { status: 400 }),
      ),
    );
    const { result } = renderHook(() => usePersonaGeneration());
    await waitFor(() => expect(result.current.loading).toBe(false));

    let r: Awaited<ReturnType<typeof result.current.persistPersonas>> | undefined;
    await act(async () => { r = await result.current.persistPersonas([]); });
    expect(r).toEqual({ ok: false, reason: 'boom' });
    expect(result.current.error).toBe('boom');
  });

  it('reload re-fetches the endpoint', async () => {
    let calls = 0;
    server.use(
      http.get(apiUrl('/realism/personas'), () => {
        calls += 1;
        return HttpResponse.json({ personas: [] });
      }),
    );
    const { result } = renderHook(() => usePersonaGeneration());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(calls).toBe(1);
    await act(async () => { await result.current.reload(); });
    expect(calls).toBe(2);
  });
});
