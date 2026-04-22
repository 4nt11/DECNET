import React, { forwardRef, useMemo } from 'react';
import { RotateCcw, LayoutGrid } from 'lucide-react';
import NetBox from './NetBox';
import NodeCard from './NodeCard';
import type { Net, MazeNode, Edge } from './types';
import type { Selection } from './Inspector';
import type { ResizeHandle } from './useMazeInteraction';

interface Props {
  nets: Net[];
  nodes: MazeNode[];
  edges: Edge[];
  deployed: boolean;
  selection: Selection;
  setSelection: (s: Selection) => void;
  pan: { x: number; y: number };
  dropTargetId: string | null;
  dragging: boolean;
  edgeDraw: { fromX: number; fromY: number; toX: number; toY: number; hoverTarget: string | null } | null;
  onCanvasMouseDown: (e: React.MouseEvent) => void;
  onNodeMouseDown: (id: string) => (e: React.MouseEvent) => void;
  onNetMouseDown: (id: string) => (e: React.MouseEvent) => void;
  onNetResizeMouseDown: (id: string, handle: ResizeHandle) => (e: React.MouseEvent) => void;
  onPortMouseDown: (id: string) => (e: React.MouseEvent) => void;
  onNodeContextMenu?: (id: string) => (e: React.MouseEvent) => void;
  onNetContextMenu?: (id: string) => (e: React.MouseEvent) => void;
  onEdgeContextMenu?: (id: string) => (e: React.MouseEvent) => void;
  onCanvasContextMenu?: (e: React.MouseEvent) => void;
  onResetView?: () => void;
  onAutoLayout?: () => void;
  sseConnected?: boolean;
  lastEventAt?: Date | null;
}

const fmtTime = (d: Date) =>
  `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;

const NODE_W = 140;
const NODE_HEAD_H = 22;

const Canvas = forwardRef<HTMLDivElement, Props>(function Canvas(
  { nets, nodes, edges, deployed, selection, setSelection, pan, dropTargetId, dragging, edgeDraw,
    onCanvasMouseDown, onNodeMouseDown, onNetMouseDown, onNetResizeMouseDown, onPortMouseDown,
    onNodeContextMenu, onNetContextMenu, onEdgeContextMenu, onCanvasContextMenu,
    onResetView, onAutoLayout, sseConnected, lastEventAt },
  ref,
) {
  const netById = useMemo(() => new Map(nets.map((n) => [n.id, n])), [nets]);

  const absPos = (node: MazeNode) => {
    const net = netById.get(node.netId);
    return { x: (net?.x ?? 0) + node.x, y: (net?.y ?? 0) + node.y };
  };

  const activeNetIds = useMemo(() => {
    const nodeNet = new Map(nodes.map((n) => [n.id, n.netId]));
    const ids = new Set<string>();
    for (const e of edges) {
      const a = nodeNet.get(e.from); const b = nodeNet.get(e.to);
      if (a) ids.add(a); if (b) ids.add(b);
    }
    return ids;
  }, [nodes, edges]);

  const selNetId  = selection?.type === 'net'  ? selection.id : null;
  const selNodeId = selection?.type === 'node' ? selection.id : null;
  const selEdgeId = selection?.type === 'edge' ? selection.id : null;

  return (
    <div
      ref={ref}
      className="maze-canvas-wrap"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) setSelection(null);
        onCanvasMouseDown(e);
      }}
      onContextMenu={(e) => {
        if (e.target === e.currentTarget && onCanvasContextMenu) onCanvasContextMenu(e);
      }}
      style={{ cursor: dragging ? 'grabbing' : 'grab' }}
    >
      <div className="maze-grid-bg">
        <svg xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="maze-grid-pat" x={pan.x} y={pan.y} width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="var(--grid-line)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#maze-grid-pat)" />
        </svg>
      </div>

      <div className="maze-pan-layer" style={{ transform: `translate(${pan.x}px, ${pan.y}px)` }}>
        <svg className="maze-svg">
          <defs>
            <marker id="arrow-matrix" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#00ff41" />
            </marker>
            <marker id="arrow-violet" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#ee82ee" />
            </marker>
            <marker id="arrow-alert" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#ff4141" />
            </marker>
          </defs>
          {edges.map((e) => {
            const from = nodes.find((n) => n.id === e.from);
            const to   = nodes.find((n) => n.id === e.to);
            if (!from || !to) return null;
            const a = absPos(from); const b = absPos(to);
            const x1 = a.x + NODE_W, y1 = a.y + NODE_HEAD_H;
            const x2 = b.x,           y2 = b.y + NODE_HEAD_H;
            const cx = (x1 + x2) / 2;
            const d  = `M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}`;
            const klass  = e.traffic === 'hot' ? 'hot' : e.traffic === 'active' ? 'active' : '';
            const marker = e.traffic === 'hot' ? 'arrow-alert' : e.traffic === 'active' ? 'arrow-violet' : 'arrow-matrix';
            const isSel  = e.id === selEdgeId;
            return (
              <g key={e.id} style={{ pointerEvents: 'auto' }}
                 onClick={(ev) => { ev.stopPropagation(); setSelection({ type: 'edge', id: e.id }); }}
                 onContextMenu={onEdgeContextMenu?.(e.id)}>
                <path d={d} className={`maze-edge ${klass} maze-edge-dash`} markerEnd={`url(#${marker})`}
                      style={{ strokeWidth: isSel ? 2.5 : 1.5 }} />
                <path d={d} stroke="transparent" strokeWidth="12" fill="none" style={{ cursor: 'pointer' }} />
                {e.label && (
                  <text x={cx} y={(y1 + y2) / 2 - 6} textAnchor="middle"
                        fill={e.traffic === 'hot' ? '#ff4141' : '#ee82ee'}
                        fontSize="9" fontFamily="var(--font-mono)" letterSpacing="1">
                    {e.label}
                  </text>
                )}
              </g>
            );
          })}
          {edgeDraw && (() => {
            const cx = (edgeDraw.fromX + edgeDraw.toX) / 2;
            const d = `M${edgeDraw.fromX},${edgeDraw.fromY} C${cx},${edgeDraw.fromY} ${cx},${edgeDraw.toY} ${edgeDraw.toX},${edgeDraw.toY}`;
            return <path d={d} className={`ghost-edge ${edgeDraw.hoverTarget ? 'snap' : ''}`} />;
          })()}
        </svg>

        <div className="maze-nodes">
          {nets.map((net) => {
            const inactive = net.kind !== 'internet' && !activeNetIds.has(net.id);
            return (
              <NetBox
                key={net.id}
                net={net}
                selected={net.id === selNetId}
                dropTarget={dropTargetId === net.id}
                inactive={inactive}
                deployed={deployed}
                onSelect={(id) => setSelection({ type: 'net', id })}
                onHeaderMouseDown={onNetMouseDown}
                onResizeMouseDown={onNetResizeMouseDown}
                onContextMenu={onNetContextMenu?.(net.id)}
              />
            );
          })}
          {nodes.map((n) => {
            const p = absPos(n);
            return (
              <NodeCard
                key={n.id}
                node={n}
                absX={p.x}
                absY={p.y}
                selected={n.id === selNodeId}
                deployed={deployed}
                dragging={dragging && n.id === selNodeId}
                onSelect={(id) => setSelection({ type: 'node', id })}
                onMouseDown={onNodeMouseDown}
                onPortMouseDown={onPortMouseDown}
                onContextMenu={onNodeContextMenu}
              />
            );
          })}
        </div>
      </div>

      {(onResetView || onAutoLayout) && (
        <div className="maze-toolbar">
          {onResetView && (
            <button type="button" className="maze-btn ghost small" onClick={onResetView} title="Reset pan to origin">
              <RotateCcw size={11} /> RESET VIEW
            </button>
          )}
          {onAutoLayout && (
            <button type="button" className="maze-btn ghost small" onClick={onAutoLayout} title="Auto-layout nodes">
              <LayoutGrid size={11} /> AUTO-LAYOUT
            </button>
          )}
        </div>
      )}

      <div className="maze-status">
        <span className={`status-seg ${sseConnected ? 'live' : 'dim'}`}>
          <span className={`status-dot ${sseConnected ? 'active' : 'idle'}`} />
          GRAPH {sseConnected ? 'LIVE' : 'IDLE'}
        </span>
        <span className="status-seg">PAN: {Math.round(pan.x)},{Math.round(pan.y)}</span>
        <span className="status-seg">AS-OF {lastEventAt ? fmtTime(lastEventAt) : '--:--:--'}</span>
      </div>

      <div className="maze-legend">
        <div className="lg-row"><span className="lg-swatch alert" /> ACTIVE ATTACK</div>
        <div className="lg-row"><span className="lg-swatch violet" /> OBSERVED FLOW</div>
        <div className="lg-row"><span className="lg-swatch matrix" /> CONFIGURED</div>
        <div className="lg-row"><span className="lg-swatch inactive" /> INACTIVE NET</div>
      </div>
    </div>
  );
});

export default Canvas;
