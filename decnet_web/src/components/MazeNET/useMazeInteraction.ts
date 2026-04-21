import { useCallback, useEffect, useRef, useState } from 'react';
import type { Net, MazeNode } from './types';

export type ResizeHandle = 'e' | 'w' | 'n' | 's' | 'ne' | 'nw' | 'se' | 'sw';

export type PaletteDragKind = 'network-subnet' | 'network-dmz' | 'archetype' | 'service';
export interface PaletteDrag {
  kind: PaletteDragKind;
  slug: string;
  label: string;
  services?: string[];
  clientX: number;
  clientY: number;
}

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
  canvasRef: React.RefObject<HTMLDivElement | null>;
  onPaletteDrop?: (drag: PaletteDrag, world: { x: number; y: number }, overNetId: string | null, overNodeId: string | null) => void;
  /** Structural callbacks — only these hit the backend. */
  onReparent?: (nodeId: string, fromNetId: string, toNetId: string) => void;
  onAddEdge?:  (fromNodeId: string, toNodeId: string) => void;
}

interface EdgeDraw {
  fromId: string;
  fromX: number; fromY: number;
  toX: number;   toY: number;
  hoverTarget: string | null;
}

export function useMazeInteraction({ nets, nodes, setNets, setNodes, canvasRef, onPaletteDrop, onReparent, onAddEdge }: Args) {
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [drag, setDrag] = useState<Drag>(null);
  const [dropTargetId, setDropTargetId] = useState<string | null>(null);
  const [edgeDraw, setEdgeDraw] = useState<EdgeDraw | null>(null);
  const [paletteDrag, setPaletteDrag] = useState<PaletteDrag | null>(null);
  const edgeDrawRef = useRef<EdgeDraw | null>(null);
  const paletteDragRef = useRef<PaletteDrag | null>(null);
  useEffect(() => { edgeDrawRef.current = edgeDraw; }, [edgeDraw]);
  useEffect(() => { paletteDragRef.current = paletteDrag; }, [paletteDrag]);

  const startPaletteDrag = useCallback((d: Omit<PaletteDrag, 'clientX' | 'clientY'>, e: React.MouseEvent) => {
    setPaletteDrag({ ...d, clientX: e.clientX, clientY: e.clientY });
  }, []);

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

  const onPortMouseDown = useCallback((id: string) => (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    e.stopPropagation();
    const node = nodesRef.current.find((n) => n.id === id);
    if (!node) return;
    const parent = netsRef.current.find((n) => n.id === node.netId);
    if (!parent) return;
    const fx = parent.x + node.x + 140;
    const fy = parent.y + node.y + 22;
    const w = toWorld(e.clientX, e.clientY);
    setEdgeDraw({ fromId: id, fromX: fx, fromY: fy, toX: w.x, toY: w.y, hoverTarget: null });
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
      const pd = paletteDragRef.current;
      if (pd) {
        setPaletteDrag({ ...pd, clientX: e.clientX, clientY: e.clientY });
        return;
      }
      const ed = edgeDrawRef.current;
      if (ed) {
        const o = canvasOriginRef.current();
        const p = panRef.current;
        const wx = e.clientX - o.x - p.x;
        const wy = e.clientY - o.y - p.y;
        const hover = nodesRef.current.find((n) => {
          if (n.id === ed.fromId) return false;
          const parent = netsRef.current.find((nn) => nn.id === n.netId);
          if (!parent) return false;
          const ax = parent.x + n.x;
          const ay = parent.y + n.y;
          return wx >= ax - 12 && wx <= ax + 140 && wy >= ay && wy <= ay + 80;
        });
        setEdgeDraw({ ...ed, toX: wx, toY: wy, hoverTarget: hover?.id ?? null });
        return;
      }

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
        const isPinned = node.kind === 'decky' && !!node.decky_config?.forwards_l3;
        const targetNet = !isObserved && !isPinned ? netsRef.current.find((net) => {
          if (net.id === node.netId) return false;
          return w.x >= net.x && w.x <= net.x + net.w && w.y >= net.y && w.y <= net.y + net.h;
        }) : undefined;
        setDropTargetId(targetNet?.id ?? null);

        const parent = netsRef.current.find((n) => n.id === node.netId);
        if (!parent) return;
        const maxX = Math.max(8, parent.w - 148);
        const maxY = Math.max(28, parent.h - 88);
        const nx = Math.min(maxX, Math.max(8,  Math.round(w.x - d.offX - parent.x)));
        const ny = Math.min(maxY, Math.max(28, Math.round(w.y - d.offY - parent.y)));
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

    const onUp = (e: MouseEvent) => {
      const pd = paletteDragRef.current;
      if (pd) {
        setPaletteDrag(null);
        const o = canvasOriginRef.current();
        const p = panRef.current;
        const wx = e.clientX - o.x - p.x;
        const wy = e.clientY - o.y - p.y;
        const rect = canvasRef.current?.getBoundingClientRect();
        const inside = rect
          ? e.clientX >= rect.left && e.clientX <= rect.right
            && e.clientY >= rect.top && e.clientY <= rect.bottom
          : false;
        if (!inside) return;
        const overNet = netsRef.current.find(
          (n) => wx >= n.x && wx <= n.x + n.w && wy >= n.y && wy <= n.y + n.h,
        );
        const overNode = nodesRef.current.find((n) => {
          const parent = netsRef.current.find((nn) => nn.id === n.netId);
          if (!parent) return false;
          const ax = parent.x + n.x;
          const ay = parent.y + n.y;
          return wx >= ax && wx <= ax + 140 && wy >= ay && wy <= ay + 80;
        });
        onPaletteDrop?.(pd, { x: wx, y: wy }, overNet?.id ?? null, overNode?.id ?? null);
        return;
      }
      const ed = edgeDrawRef.current;
      if (ed) {
        if (ed.hoverTarget && ed.hoverTarget !== ed.fromId) {
          const target = nodesRef.current.find((n) => n.id === ed.hoverTarget);
          if (target && target.kind !== 'observed') {
            onAddEdge?.(ed.fromId, ed.hoverTarget);
          }
        }
        setEdgeDraw(null);
        return;
      }

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
            const fromNetId = node.netId;
            setNodes((prev) => prev.map((n) => n.id === d.id ? { ...n, netId: target, x: relX, y: relY } : n));
            onReparent?.(d.id, fromNetId, target);
          }
        }
        /* Intra-net moves and net/resize drags are cosmetic — never persisted. */
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
  }, [setNets, setNodes, dropTargetId, onPaletteDrop, onReparent, onAddEdge, canvasRef]);

  const resetPan = useCallback(() => setPan({ x: 0, y: 0 }), []);

  return {
    pan,
    dropTargetId,
    dragging: drag !== null,
    edgeDraw,
    paletteDrag,
    startPaletteDrag,
    onCanvasMouseDown,
    onNodeMouseDown,
    onNetMouseDown,
    onNetResizeMouseDown,
    onPortMouseDown,
    resetPan,
  };
}
