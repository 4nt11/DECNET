import { useCallback, useEffect, useRef, useState } from 'react';
import type { Net, MazeNode, PendingChange } from './types';

export type ResizeHandle = 'e' | 'w' | 'n' | 's' | 'ne' | 'nw' | 'se' | 'sw';

type Drag =
  | null
  | { type: 'pan';    startX: number; startY: number; panX: number; panY: number }
  | { type: 'node';   id: string; offX: number; offY: number }
  | { type: 'net';    id: string; offX: number; offY: number }
  | { type: 'resize'; id: string; handle: ResizeHandle; startX: number; startY: number; start: Net };

interface Args {
  nets: Net[];
  nodes: MazeNode[];
  setNets: React.Dispatch<React.SetStateAction<Net[]>>;
  setNodes: React.Dispatch<React.SetStateAction<MazeNode[]>>;
  applyChange: (pc: PendingChange) => void;
  canvasRef: React.RefObject<HTMLDivElement | null>;
}

export function useMazeInteraction({ nets, nodes, setNets, setNodes, applyChange, canvasRef }: Args) {
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [drag, setDrag] = useState<Drag>(null);
  const [dropTargetId, setDropTargetId] = useState<string | null>(null);

  /* Refs to avoid re-binding global listeners on every state change. */
  const netsRef = useRef(nets);
  const nodesRef = useRef(nodes);
  const panRef = useRef(pan);
  const dragRef = useRef(drag);
  useEffect(() => { netsRef.current = nets; }, [nets]);
  useEffect(() => { nodesRef.current = nodes; }, [nodes]);
  useEffect(() => { panRef.current = pan; }, [pan]);
  useEffect(() => { dragRef.current = drag; }, [drag]);

  const canvasOriginRef = useRef(() => {
    const r = canvasRef.current?.getBoundingClientRect();
    return { x: r?.left ?? 0, y: r?.top ?? 0 };
  });

  /* World-space coords from a client event (applies pan inverse). */
  const toWorld = useCallback((clientX: number, clientY: number) => {
    const o = canvasOriginRef.current();
    const p = panRef.current;
    return { x: clientX - o.x - p.x, y: clientY - o.y - p.y };
  }, []);

  /* ── Mousedown dispatchers ────────────────────────────── */

  const onCanvasMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    if (e.target !== e.currentTarget) return;
    setDrag({ type: 'pan', startX: e.clientX, startY: e.clientY, panX: panRef.current.x, panY: panRef.current.y });
  }, []);

  const onNodeMouseDown = useCallback((id: string) => (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    e.stopPropagation();
    const node = nodesRef.current.find((n) => n.id === id);
    if (!node) return;
    const net = netsRef.current.find((nn) => nn.id === node.netId);
    if (!net) return;
    const w = toWorld(e.clientX, e.clientY);
    setDrag({ type: 'node', id, offX: w.x - (net.x + node.x), offY: w.y - (net.y + node.y) });
  }, [toWorld]);

  const onNetMouseDown = useCallback((id: string) => (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    e.stopPropagation();
    const net = netsRef.current.find((n) => n.id === id);
    if (!net) return;
    const w = toWorld(e.clientX, e.clientY);
    setDrag({ type: 'net', id, offX: w.x - net.x, offY: w.y - net.y });
  }, [toWorld]);

  const onNetResizeMouseDown = useCallback((id: string, handle: ResizeHandle) => (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    e.stopPropagation();
    const net = netsRef.current.find((n) => n.id === id);
    if (!net) return;
    setDrag({ type: 'resize', id, handle, startX: e.clientX, startY: e.clientY, start: { ...net } });
  }, []);

  /* ── Global mousemove / mouseup ───────────────────────── */

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const d = dragRef.current;
      if (!d) return;

      if (d.type === 'pan') {
        setPan({ x: d.panX + (e.clientX - d.startX), y: d.panY + (e.clientY - d.startY) });
        return;
      }

      const w = (() => {
        const o = canvasOriginRef.current();
        const p = panRef.current;
        return { x: e.clientX - o.x - p.x, y: e.clientY - o.y - p.y };
      })();

      if (d.type === 'net') {
        setNets((prev) => prev.map((n) => n.id === d.id ? { ...n, x: Math.round(w.x - d.offX), y: Math.round(w.y - d.offY) } : n));
        return;
      }

      if (d.type === 'node') {
        const node = nodesRef.current.find((n) => n.id === d.id);
        if (!node) return;
        const isObserved = node.kind === 'observed';
        const targetNet = !isObserved ? netsRef.current.find((net) => {
          if (net.id === node.netId) return false;
          return w.x >= net.x && w.x <= net.x + net.w && w.y >= net.y && w.y <= net.y + net.h;
        }) : undefined;
        setDropTargetId(targetNet?.id ?? null);

        const parent = netsRef.current.find((n) => n.id === node.netId);
        if (!parent) return;
        const nx = Math.max(8, Math.round(w.x - d.offX - parent.x));
        const ny = Math.max(28, Math.round(w.y - d.offY - parent.y));
        setNodes((prev) => prev.map((n) => n.id === d.id ? { ...n, x: nx, y: ny } : n));
        return;
      }

      if (d.type === 'resize') {
        const dx = e.clientX - d.startX;
        const dy = e.clientY - d.startY;
        setNets((prev) => prev.map((n) => {
          if (n.id !== d.id) return n;
          let { x, y, w: width, h: height } = d.start;
          const MIN_W = 220, MIN_H = 140;
          if (d.handle.includes('e')) width  = Math.max(MIN_W, d.start.w + dx);
          if (d.handle.includes('s')) height = Math.max(MIN_H, d.start.h + dy);
          if (d.handle.includes('w')) {
            width  = Math.max(MIN_W, d.start.w - dx);
            x = d.start.x + (d.start.w - width);
          }
          if (d.handle.includes('n')) {
            height = Math.max(MIN_H, d.start.h - dy);
            y = d.start.y + (d.start.h - height);
          }
          return { ...n, x, y, w: width, h: height };
        }));
        return;
      }
    };

    const onUp = () => {
      const d = dragRef.current;
      if (!d) return;

      if (d.type === 'node') {
        const node = nodesRef.current.find((n) => n.id === d.id);
        const target = dropTargetId;
        if (node && node.kind === 'decky' && target && target !== node.netId) {
          const parentOld = netsRef.current.find((nn) => nn.id === node.netId);
          const parentNew = netsRef.current.find((nn) => nn.id === target);
          if (parentOld && parentNew) {
            const absX = parentOld.x + node.x;
            const absY = parentOld.y + node.y;
            const relX = Math.max(8,  absX - parentNew.x);
            const relY = Math.max(28, absY - parentNew.y);
            setNodes((prev) => prev.map((n) => n.id === d.id ? { ...n, netId: target, x: relX, y: relY } : n));
            applyChange({ op: 'detach_decky', payload: { nodeId: d.id, netId: node.netId } });
            applyChange({ op: 'attach_decky', payload: {
              nodeId: d.id, netId: target, archetype: node.archetype, name: node.name,
              x: relX, y: relY, services: node.services,
            }});
          }
        } else if (node && node.kind === 'decky') {
          applyChange({ op: 'update_decky', payload: { nodeId: node.id, patch: { x: node.x, y: node.y } } });
        }
      } else if (d.type === 'net') {
        const net = netsRef.current.find((n) => n.id === d.id);
        if (net) applyChange({ op: 'update_lan', payload: { id: net.id, patch: { x: net.x, y: net.y } } });
      } else if (d.type === 'resize') {
        const net = netsRef.current.find((n) => n.id === d.id);
        if (net) applyChange({ op: 'update_lan', payload: { id: net.id, patch: { x: net.x, y: net.y, w: net.w, h: net.h } } });
      }

      setDropTargetId(null);
      setDrag(null);
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [applyChange, setNets, setNodes, dropTargetId]);

  const resetPan = useCallback(() => setPan({ x: 0, y: 0 }), []);

  return {
    pan,
    dropTargetId,
    dragging: drag !== null,
    onCanvasMouseDown,
    onNodeMouseDown,
    onNetMouseDown,
    onNetResizeMouseDown,
    resetPan,
  };
}
