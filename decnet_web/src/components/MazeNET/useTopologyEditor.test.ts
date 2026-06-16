// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';

import { useTopologyEditor, MutationFailedError } from './useTopologyEditor';
import type { MazeApi } from './useMazeApi';

const buildApi = (overrides: Partial<MazeApi> = {}): MazeApi => ({
  enqueueMutation: vi.fn().mockResolvedValue({ mutation_id: 'm', state: 'pending' }),
  waitForMutation: vi.fn().mockResolvedValue({ state: 'applied', reason: null }),
  ...overrides,
} as unknown as MazeApi);

const editorFor = (api: MazeApi, topoVersion = 5) =>
  renderHook(() =>
    useTopologyEditor({ api, topoStatus: 'active', topoVersion }),
  );

describe('useTopologyEditor live mutation queue', () => {
  it('serialises concurrent submits and advances expected_version per enqueue', async () => {
    const enqueue = vi.fn().mockResolvedValue({ mutation_id: 'm', state: 'pending' });
    const api = buildApi({ enqueueMutation: enqueue });
    const { result } = editorFor(api, 5);

    // Fire two structural ops in the SAME tick — the pre-fix bug was both
    // sending expected_version=5 and the loser 409ing.
    await act(async () => {
      await Promise.all([
        result.current.createLan('t', { name: 'a', is_dmz: false, x: 0, y: 0 }),
        result.current.deleteLan('t', 'lid', 'b'),
      ]);
    });

    expect(enqueue).toHaveBeenCalledTimes(2);
    expect(enqueue.mock.calls[0][3]).toBe(5); // first uses server version
    expect(enqueue.mock.calls[1][3]).toBe(6); // second advanced by the cursor
  });

  it('throws MutationFailedError on a failed mutation but keeps the queue alive', async () => {
    const wait = vi
      .fn()
      .mockResolvedValueOnce({ state: 'failed', reason: 'post-apply validation failed: IP_COLLISION' })
      .mockResolvedValue({ state: 'applied', reason: null });
    const api = buildApi({ waitForMutation: wait });
    const { result } = editorFor(api, 1);

    await act(async () => {
      await expect(
        result.current.createLan('t', { name: 'a', is_dmz: false, x: 0, y: 0 }),
      ).rejects.toBeInstanceOf(MutationFailedError);
    });

    // A failed op must not wedge the chain — the next submit still resolves.
    await act(async () => {
      await expect(
        result.current.deleteLan('t', 'lid', 'b'),
      ).resolves.toEqual({ kind: 'enqueued', mutationId: 'm' });
    });
  });
});
