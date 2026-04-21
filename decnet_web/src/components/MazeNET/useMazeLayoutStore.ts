import { useCallback, useEffect, useRef } from 'react';
import type { Net, MazeNode } from './types';

/** Per-topology canvas layout persisted to localStorage. Keyed by
 *  topology id so two topologies don't share positions. Stored keys
 *  for missing LAN/decky ids are pruned on save (self-heal). */

interface NetLayout { x: number; y: number; w: number; h: number }
interface NodeLayout { x: number; y: number }

export interface LayoutSnapshot {
  nets: Record<string, NetLayout>;
  nodes: Record<string, NodeLayout>;
}

const EMPTY: LayoutSnapshot = { nets: {}, nodes: {} };
const SAVE_DEBOUNCE_MS = 300;

function storageKey(topologyId: string): string {
  return `mazenet.layout.${topologyId}`;
}

export function loadLayout(topologyId: string | null): LayoutSnapshot {
  if (!topologyId) return EMPTY;
  try {
    const raw = window.localStorage.getItem(storageKey(topologyId));
    if (!raw) return EMPTY;
    const parsed = JSON.parse(raw) as Partial<LayoutSnapshot>;
    return {
      nets: parsed.nets ?? {},
      nodes: parsed.nodes ?? {},
    };
  } catch {
    return EMPTY;
  }
}

function saveLayout(topologyId: string, snap: LayoutSnapshot): void {
  try {
    window.localStorage.setItem(storageKey(topologyId), JSON.stringify(snap));
  } catch {
    /* quota exhausted or private mode — layout reverts to grid. */
  }
}

/** Apply stored positions on top of grid-laid-out entities. Entities
 *  without a stored entry keep their grid position. */
export function applyLayout(
  nets: Net[],
  nodes: MazeNode[],
  layout: LayoutSnapshot,
): { nets: Net[]; nodes: MazeNode[] } {
  const adjustedNets = nets.map((n) => {
    const saved = layout.nets[n.id];
    return saved ? { ...n, x: saved.x, y: saved.y, w: saved.w, h: saved.h } : n;
  });
  const adjustedNodes = nodes.map((n) => {
    const saved = layout.nodes[n.id];
    return saved ? { ...n, x: saved.x, y: saved.y } : n;
  });
  return { nets: adjustedNets, nodes: adjustedNodes };
}

/** Debounced writer — every nets/nodes change is captured and flushed
 *  to localStorage after a short idle window. Also prunes entries for
 *  LANs / deckies that no longer exist in the current topology. */
export function useLayoutPersistor(
  topologyId: string | null,
  nets: Net[],
  nodes: MazeNode[],
): void {
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!topologyId) return;
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => {
      const snap: LayoutSnapshot = { nets: {}, nodes: {} };
      for (const n of nets) {
        if (n.kind === 'internet') continue;
        snap.nets[n.id] = { x: n.x, y: n.y, w: n.w, h: n.h };
      }
      for (const n of nodes) {
        snap.nodes[n.id] = { x: n.x, y: n.y };
      }
      saveLayout(topologyId, snap);
      timerRef.current = null;
    }, SAVE_DEBOUNCE_MS);
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [topologyId, nets, nodes]);
}

/** Clear the stored layout for a topology — call after delete so stale
 *  entries don't linger forever. */
export function clearLayout(topologyId: string): void {
  try {
    window.localStorage.removeItem(storageKey(topologyId));
  } catch {
    /* ignore */
  }
}

/** Hook form for consumers that prefer a stable callback. */
export function useClearLayout(): (topologyId: string) => void {
  return useCallback((id: string) => clearLayout(id), []);
}
