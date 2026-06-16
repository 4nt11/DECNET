// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';

// useTopologyStream opens an EventSource — stub it to a no-op.
vi.mock('./useTopologyStream', () => ({
  useTopologyStream: vi.fn(),
}));

import { useTopologyData } from './useTopologyData';
import type { MazeApi } from './useMazeApi';

const TOPO_ID = 'topo-1';

const stubHydrated = (overrides: Partial<{ status: string; version: number }> = {}) => ({
  topology: {
    id: TOPO_ID,
    name: 'corp-net',
    mode: 'unihost',
    target_host_uuid: null,
    status: overrides.status ?? 'pending',
    version: overrides.version ?? 1,
  },
  nets: [],
  nodes: [],
  edges: [],
});

const buildApi = (overrides: Partial<MazeApi> = {}): MazeApi => ({
  listTopologies: vi.fn().mockResolvedValue([]),
  createBlankTopology: vi.fn(),
  getTopology: vi.fn().mockResolvedValue(stubHydrated()),
  getServices: vi.fn().mockResolvedValue([]),
  getArchetypes: vi.fn().mockResolvedValue([]),
  getNextIp: vi.fn(),
  getNextSubnet: vi.fn(),
  createLan: vi.fn(),
  updateLan: vi.fn(),
  deleteLan: vi.fn(),
  createDecky: vi.fn(),
  updateDecky: vi.fn(),
  deleteDecky: vi.fn(),
  createEdge: vi.fn(),
  deleteEdge: vi.fn(),
  applyMutation: vi.fn(),
  deployTopology: vi.fn().mockResolvedValue(undefined),
  ...overrides,
} as unknown as MazeApi);

describe('useTopologyData', () => {
  it('hydrates topology metadata from getTopology on mount', async () => {
    const api = buildApi();
    const { result } = renderHook(() => useTopologyData(api, TOPO_ID));
    await waitFor(() => expect(result.current.topoMeta.name).toBe('corp-net'));
    expect(result.current.topoMeta.status).toBe('pending');
    expect(api.getTopology).toHaveBeenCalledWith(TOPO_ID);
  });

  it('surfaces loadErr when getTopology rejects', async () => {
    const api = buildApi({
      getTopology: vi.fn().mockRejectedValue(new Error('not found')),
    });
    const { result } = renderHook(() => useTopologyData(api, TOPO_ID));
    await waitFor(() => expect(result.current.loadErr).toBe('not found'));
  });

  it('streamEnabled flips on for active/degraded topologies', async () => {
    const api = buildApi({
      getTopology: vi.fn().mockResolvedValue(stubHydrated({ status: 'active' })),
    });
    const { result } = renderHook(() => useTopologyData(api, TOPO_ID));
    await waitFor(() => expect(result.current.topoMeta.status).toBe('active'));
    expect(result.current.streamEnabled).toBe(true);
  });

  it('onDeploy fires deployTopology and refetches on success', async () => {
    const deploy = vi.fn().mockResolvedValue(undefined);
    const get = vi.fn().mockResolvedValue(stubHydrated());
    const api = buildApi({ deployTopology: deploy, getTopology: get });
    const { result } = renderHook(() => useTopologyData(api, TOPO_ID));
    await waitFor(() => expect(result.current.topoMeta.name).toBe('corp-net'));
    const initialGetCalls = get.mock.calls.length;

    await act(async () => { await result.current.onDeploy(); });
    expect(deploy).toHaveBeenCalledWith(TOPO_ID);
    expect(get.mock.calls.length).toBeGreaterThan(initialGetCalls);
  });

  it('onDeploy surfaces actionErr when deploy throws', async () => {
    const deploy = vi.fn().mockRejectedValue({ response: { data: { detail: 'boom' } } });
    const api = buildApi({ deployTopology: deploy });
    const { result } = renderHook(() => useTopologyData(api, TOPO_ID));
    await waitFor(() => expect(result.current.topoMeta.name).toBe('corp-net'));

    await act(async () => { await result.current.onDeploy(); });
    expect(result.current.actionErr).toBe('boom');
  });

  it('flashErr writes actionErr and auto-clears after 4s', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const api = buildApi();
      const { result } = renderHook(() => useTopologyData(api, TOPO_ID));
      await waitFor(() => expect(result.current.topoMeta.name).toBe('corp-net'));

      act(() => result.current.flashErr(new Error('oops'), 'fallback'));
      expect(result.current.actionErr).toBe('oops');

      act(() => { vi.advanceTimersByTime(4500); });
      expect(result.current.actionErr).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
