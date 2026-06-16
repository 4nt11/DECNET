// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';

import { useTopologyEditor } from './useTopologyEditor';
import type { MazeApi } from './useMazeApi';

const buildApi = (overrides: Partial<MazeApi> = {}): MazeApi => ({
  enqueueMutation: vi.fn().mockResolvedValue({ mutation_id: 'm', state: 'pending' }),
  ...overrides,
} as unknown as MazeApi);

const editorFor = (api: MazeApi, topoVersion = 5) =>
  renderHook(() =>
    useTopologyEditor({ api, topoStatus: 'active', topoVersion }),
  );

describe('useTopologyEditor live staging', () => {
  it('stages live edits without sending; commit enqueues them in order with a version cursor', async () => {
    const enqueue = vi.fn().mockResolvedValue({ mutation_id: 'm', state: 'pending' });
    const api = buildApi({ enqueueMutation: enqueue });
    const { result } = editorFor(api, 5);

    await act(async () => {
      await result.current.createLan('t', { name: 'a', is_dmz: false, x: 0, y: 0 });
      await result.current.deleteLan('t', 'lid', 'b');
    });

    // Staged, not sent.
    expect(result.current.pendingCount).toBe(2);
    expect(enqueue).not.toHaveBeenCalled();

    await act(async () => {
      await result.current.commitStaged();
    });

    // Enqueued (not waited-on): no apply polling.
    expect(enqueue).toHaveBeenCalledTimes(2);
    expect(enqueue.mock.calls[0][3]).toBe(5); // first uses server version
    expect(enqueue.mock.calls[1][3]).toBe(6); // second advanced by the cursor
    expect(result.current.pendingCount).toBe(0);
  });

  it('keeps the un-enqueued remainder staged when an enqueue POST fails', async () => {
    const enqueue = vi
      .fn()
      .mockResolvedValueOnce({ mutation_id: 'm', state: 'pending' })
      .mockRejectedValueOnce(new Error('409 version conflict'))
      .mockResolvedValue({ mutation_id: 'm', state: 'pending' });
    const api = buildApi({ enqueueMutation: enqueue });
    const { result } = editorFor(api, 1);

    await act(async () => {
      await result.current.createLan('t', { name: 'a', is_dmz: false, x: 0, y: 0 });
      await result.current.deleteLan('t', 'lid', 'b');
    });
    expect(result.current.pendingCount).toBe(2);

    await act(async () => {
      await expect(result.current.commitStaged()).rejects.toThrow('409');
    });
    // First op enqueued, second threw → one remains staged for retry.
    expect(result.current.pendingCount).toBe(1);

    await act(async () => {
      await result.current.commitStaged();
    });
    expect(result.current.pendingCount).toBe(0);
  });

  it('discardStaged drops the batch without sending', async () => {
    const enqueue = vi.fn().mockResolvedValue({ mutation_id: 'm', state: 'pending' });
    const api = buildApi({ enqueueMutation: enqueue });
    const { result } = editorFor(api, 1);

    await act(async () => {
      await result.current.createLan('t', { name: 'a', is_dmz: false, x: 0, y: 0 });
    });
    expect(result.current.pendingCount).toBe(1);

    act(() => result.current.discardStaged());
    expect(result.current.pendingCount).toBe(0);
    expect(enqueue).not.toHaveBeenCalled();
  });
});
