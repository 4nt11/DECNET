import React from 'react';
import { Trash2 } from 'lucide-react';
import type { Net, MazeNode, Edge, PendingChange } from './types';

export type Selection =
  | { type: 'net'; id: string }
  | { type: 'node'; id: string }
  | { type: 'edge'; id: string }
  | null;

interface Props {
  selection: Selection;
  nets: Net[];
  nodes: MazeNode[];
  edges: Edge[];
  pending: PendingChange[];
  onClose?: () => void;
  onDeleteNet?: (id: string) => void;
  onDeleteNode?: (id: string) => void;
  onDeleteEdge?: (id: string) => void;
}

const Inspector: React.FC<Props> = ({ selection, nets, nodes, edges, pending, onClose, onDeleteNet, onDeleteNode, onDeleteEdge }) => {
  const net  = selection?.type === 'net'  ? nets.find((n) => n.id === selection.id)  : undefined;
  const node = selection?.type === 'node' ? nodes.find((n) => n.id === selection.id) : undefined;
  const edge = selection?.type === 'edge' ? edges.find((e) => e.id === selection.id) : undefined;

  return (
    <aside className="maze-inspector">
      <div className="maze-inspector-title">
        <span>INSPECTOR</span>
        {onClose && (
          <button
            type="button"
            className="maze-btn ghost"
            style={{ marginLeft: 'auto', padding: '2px 8px', fontSize: '0.6rem' }}
            onClick={onClose}
          >
            CLOSE
          </button>
        )}
      </div>
      <div className="maze-inspector-body">
        {!selection && <div className="inspector-empty">SELECT AN ELEMENT</div>}

        {net && (
          <>
            <div className="kvs">
              <div className="k">KIND</div>     <div className="v">{net.kind.toUpperCase()}</div>
              <div className="k">LABEL</div>    <div className="v">{net.label}</div>
              <div className="k">CIDR</div>     <div className="v">{net.cidr}</div>
              <div className="k">MEMBERS</div>  <div className="v">
                {nodes.filter((n) => n.netId === net.id).map((n) => n.name).join(', ') || '—'}
              </div>
            </div>
            {net.kind !== 'internet' && onDeleteNet && (
              <button type="button" className="maze-btn ghost" onClick={() => onDeleteNet(net.id)}>
                <Trash2 size={12} /> DELETE NET
              </button>
            )}
          </>
        )}

        {node && (
          <>
            <div className="kvs">
              <div className="k">KIND</div>      <div className="v">{node.kind === 'observed' ? 'OBSERVED' : 'DECKY'}</div>
              <div className="k">NAME</div>      <div className="v">{node.name}</div>
              <div className="k">ARCHETYPE</div> <div className="v">{node.archetype}</div>
              <div className="k">NET</div>       <div className="v">{nets.find((nn) => nn.id === node.netId)?.label ?? node.netId}</div>
              <div className="k">SERVICES</div>  <div className="v">{node.services.join(', ') || '—'}</div>
              <div className="k">STATUS</div>    <div className="v">{node.status.toUpperCase()}</div>
            </div>
            {onDeleteNode && (
              <button
                type="button"
                className="maze-btn ghost"
                disabled={node.kind === 'observed'}
                title={node.kind === 'observed' ? 'observed entity — not a deployed decky' : 'delete decky'}
                onClick={() => node.kind === 'decky' && onDeleteNode(node.id)}
              >
                <Trash2 size={12} /> DELETE NODE
              </button>
            )}
          </>
        )}

        {edge && (
          <>
            <div className="kvs">
              <div className="k">FROM</div>    <div className="v">{nodes.find((n) => n.id === edge.from)?.name ?? edge.from}</div>
              <div className="k">TO</div>      <div className="v">{nodes.find((n) => n.id === edge.to)?.name ?? edge.to}</div>
              <div className="k">TRAFFIC</div> <div className="v">{edge.traffic.toUpperCase()}</div>
              {edge.label && (<>
                <div className="k">LABEL</div> <div className="v">{edge.label}</div>
              </>)}
            </div>
            {onDeleteEdge && (
              <button type="button" className="maze-btn ghost" onClick={() => onDeleteEdge(edge.id)}>
                <Trash2 size={12} /> REMOVE EDGE
              </button>
            )}
          </>
        )}

        <div>
          <div className="k" style={{ fontSize: '0.62rem', letterSpacing: '1.5px', opacity: 0.5, marginBottom: 6 }}>
            PENDING DIFF ({pending.length})
          </div>
          <pre className="maze-diff">
            {pending.length === 0
              ? <span className="ctx">no pending changes</span>
              : pending.map((p, i) => <div key={i} className="add">+ {p.op} {JSON.stringify(p.payload)}</div>)}
          </pre>
        </div>
      </div>
    </aside>
  );
};

export default Inspector;
