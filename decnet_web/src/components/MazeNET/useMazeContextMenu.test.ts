// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useMazeContextMenu } from './useMazeContextMenu';
import type { Net, MazeNode } from './types';
import type { UseTopologyEditor } from './useTopologyEditor';

const stubEditor = (): UseTopologyEditor => ({
  inFlight: 0,
  addLan: vi.fn(),
  updateLanRow: vi.fn(),
  deleteLan: vi.fn(),
  addDeckyToLan: vi.fn(),
  updateDecky: vi.fn(),
  deleteDecky: vi.fn(),
  attachEdge: vi.fn(),
  detachEdge: vi.fn(),
} as unknown as UseTopologyEditor);

const fakeMouse = (overrides: Partial<MouseEvent> = {}): React.MouseEvent => ({
  clientX: 100,
  clientY: 200,
  preventDefault: vi.fn(),
  stopPropagation: vi.fn(),
  ...overrides,
} as unknown as React.MouseEvent);

const subnet: Net = {
  id: 'lan-1', name: 'lan-corp', label: 'CORP',
  cidr: '10.0.0.0/24', kind: 'subnet', x: 0, y: 0, w: 300, h: 240,
};
const internet: Net = {
  id: 'lan-www', name: 'internet', label: 'INTERNET',
  cidr: '0.0.0.0/0', kind: 'internet', x: 0, y: 0, w: 300, h: 240,
};
const decky: MazeNode = {
  kind: 'decky', id: 'd1', name: 'decoy-01', netId: 'lan-1',
  archetype: 'workstation', services: ['ssh'], status: 'idle', x: 0, y: 0,
};
const observed: MazeNode = {
  kind: 'observed', id: 'obs-1', netId: 'lan-www', name: '1.2.3.4',
  archetype: 'attacker-pool', services: ['*'], status: 'idle',
  x: 0, y: 0,
};

const baseArgs = () => ({
  nets: [subnet, internet],
  nodes: [decky, observed],
  services: [
    {
      slug: 'http', name: 'HTTP', proto: 'tcp' as const, port: 80,
      icon: 'globe', risk: 'med' as const, group: 'Web' as const,
    },
  ],
  archetypes: [
    { slug: 'workstation', name: 'Workstation', services: ['ssh'], icon: 'monitor' },
  ],
  topologyId: 'topo-1',
  setSelection: vi.fn(),
  setNodes: vi.fn(),
  canvasRef: { current: null as HTMLDivElement | null } as React.RefObject<HTMLDivElement | null>,
  pan: { x: 0, y: 0 },
  editor: stubEditor(),
  flashErr: vi.fn(),
  onPaletteDrop: vi.fn(),
  removeNet: vi.fn(),
  removeNode: vi.fn(),
  removeEdge: vi.fn(),
  duplicateNode: vi.fn(),
  addServiceToNode: vi.fn(),
});

describe('useMazeContextMenu', () => {
  it('starts with no menu open and clears on closeMenu', () => {
    const { result } = renderHook(() => useMazeContextMenu(baseArgs()));
    expect(result.current.ctxMenu).toBeNull();

    act(() => result.current.onNodeContextMenu('d1')(fakeMouse()));
    expect(result.current.ctxMenu).not.toBeNull();
    expect(result.current.ctxMenu?.x).toBe(100);
    expect(result.current.ctxMenu?.items.length).toBeGreaterThan(0);

    act(() => result.current.closeMenu());
    expect(result.current.ctxMenu).toBeNull();
  });

  it('node context menu offers add-service / mutate / duplicate / delete', () => {
    const { result } = renderHook(() => useMazeContextMenu(baseArgs()));
    act(() => result.current.onNodeContextMenu('d1')(fakeMouse()));
    const labels = result.current.ctxMenu?.items.map((i) => i.label);
    expect(labels).toContain('Add service…');
    expect(labels).toContain('Force mutate');
    expect(labels).toContain('Duplicate decky');
    expect(labels).toContain('Delete decky');
  });

  it('observed entities lock duplicate + delete', () => {
    const { result } = renderHook(() => useMazeContextMenu(baseArgs()));
    act(() => result.current.onNodeContextMenu('obs-1')(fakeMouse()));
    const dup = result.current.ctxMenu?.items.find((i) => i.label === 'Duplicate decky');
    const del = result.current.ctxMenu?.items.find((i) => i.label === 'Delete decky');
    expect(dup?.disabled).toBe(true);
    expect(del?.disabled).toBe(true);
  });

  it('internet network cannot be deleted', () => {
    const { result } = renderHook(() => useMazeContextMenu(baseArgs()));
    act(() => result.current.onNetContextMenu('lan-www')(fakeMouse()));
    const del = result.current.ctxMenu?.items.find((i) =>
      typeof i.label === 'string' && i.label.startsWith('Delete'),
    );
    expect(del?.disabled).toBe(true);
  });

  it('canvas context menu provides Add subnet / Add DMZ', () => {
    const { result } = renderHook(() => useMazeContextMenu(baseArgs()));
    act(() => result.current.onCanvasContextMenu(fakeMouse()));
    const labels = result.current.ctxMenu?.items.map((i) => i.label);
    expect(labels).toEqual(['Add subnet here', 'Add DMZ here']);
  });

  it('edge context menu invokes removeEdge on click', () => {
    const args = baseArgs();
    const { result } = renderHook(() => useMazeContextMenu(args));
    act(() => result.current.onEdgeContextMenu('e1')(fakeMouse()));
    const rm = result.current.ctxMenu?.items[0];
    expect(rm?.label).toBe('Remove edge');
    rm?.onClick?.();
    expect(args.removeEdge).toHaveBeenCalledWith('e1');
  });
});
