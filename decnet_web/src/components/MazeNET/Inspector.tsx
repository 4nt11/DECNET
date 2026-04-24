import React, { useMemo } from 'react';
import {
  ArrowLeft, ArrowRight, Crosshair, Globe, GitMerge, MousePointer2, Plus,
  Server, Trash2, X, Shield,
} from '../../icons';
import type { Net, MazeNode, Edge } from './types';
import { DEFAULT_SERVICES } from './data';

export type Selection =
  | { type: 'net'; id: string }
  | { type: 'node'; id: string }
  | { type: 'edge'; id: string }
  | { type: 'service'; id: string; nodeId: string }
  | null;

interface Props {
  selection: Selection;
  nets: Net[];
  nodes: MazeNode[];
  edges: Edge[];
  topologyStatus?: string;
  onClose?: () => void;
  onDeleteNet?: (id: string) => void;
  onDeleteNode?: (id: string) => void;
  onDeleteEdge?: (id: string) => void;
  onRemoveService?: (nodeId: string, slug: string) => void;
  onAddDecky?: (netId: string) => void;
  setSelection?: (sel: Selection) => void;
  pendingChanges?: number;
  className?: string;
}

const Inspector: React.FC<Props> = ({
  selection, nets, nodes, edges, topologyStatus, onClose,
  onDeleteNet, onDeleteNode, onDeleteEdge, onRemoveService, onAddDecky, setSelection,
  pendingChanges = 0,
  className = '',
}) => {
  const net  = selection?.type === 'net'  ? nets.find((n) => n.id === selection.id)  : undefined;
  const node = selection?.type === 'node' ? nodes.find((n) => n.id === selection.id) : undefined;
  const edge = selection?.type === 'edge' ? edges.find((e) => e.id === selection.id) : undefined;
  const serviceSel = selection?.type === 'service' ? selection : undefined;
  const serviceMeta = serviceSel ? DEFAULT_SERVICES.find((s) => s.slug === serviceSel.id) : undefined;
  const serviceParent = serviceSel ? nodes.find((n) => n.id === serviceSel.nodeId) : undefined;
  const serviceParentNet = serviceParent ? nets.find((n) => n.id === serviceParent.netId) : undefined;

  const activeNetIds = useMemo(() => {
    const s = new Set<string>();
    edges.forEach((e) => {
      const f = nodes.find((n) => n.id === e.from);
      const t = nodes.find((n) => n.id === e.to);
      if (f) s.add(f.netId);
      if (t) s.add(t.netId);
    });
    return s;
  }, [edges, nodes]);

  const typeLabel = selection ? selection.type.toUpperCase() : 'IDLE';
  const isGateway = node?.kind === 'decky' && !!node.decky_config?.forwards_l3;
  const isObserved = node?.kind === 'observed';

  return (
    <aside className={`maze-inspector ${className}`}>
      <div className="maze-inspector-title">
        <Crosshair size={12} className="violet-accent" />
        <span>INSPECTOR</span>
        <span className="dim inspector-type-label">{typeLabel}</span>
        {onClose && (
          <button
            type="button"
            className="inspector-close-btn"
            onClick={onClose}
            title="Hide inspector"
          >
            <X size={12} />
          </button>
        )}
      </div>

      <div className="maze-inspector-body">
        {!selection && (
          <div className="inspector-empty">
            <MousePointer2 size={22} style={{ opacity: 0.4, marginBottom: 10 }} />
            <div>SELECT A NODE, NETWORK, OR EDGE</div>
            <div style={{ marginTop: 10, fontSize: '0.6rem', opacity: 0.5 }}>
              Right-click for actions
            </div>
          </div>
        )}

        {node && (
          <>
            <div className="inspector-head">
              <span className={`status-dot ${node.status}`} />
              <span className="inspector-head-title">{node.name}</span>
              <span className="chip violet inspector-head-chip">{node.archetype}</span>
            </div>
            <div className="kvs">
              <div className="k">NETWORK</div>
              <div className="v violet-accent">
                {nets.find((nn) => nn.id === node.netId)?.label ?? node.netId}
              </div>
              <div className="k">STATUS</div>
              <div className="v">{node.status.toUpperCase()}</div>
              <div className="k">SERVICES</div>
              <div className="v">
                <div className="inspector-service-row">
                  {node.services.length === 0 && <span className="dim">—</span>}
                  {node.services.map((s) => (
                    <span key={s} className="service-tag">{s}</span>
                  ))}
                </div>
              </div>
            </div>
            <div>
              <div className="type-label inspector-section-label">CONNECTIONS</div>
              {edges.filter((e) => e.from === node.id || e.to === node.id).map((e) => {
                const otherId = e.from === node.id ? e.to : e.from;
                const other = nodes.find((n) => n.id === otherId);
                const Arrow = e.from === node.id ? ArrowRight : ArrowLeft;
                return (
                  <div key={e.id} className="inspector-conn-row">
                    <Arrow size={10} className={e.traffic === 'hot' ? 'alert-text' : 'dim'} />
                    <span>{other?.name ?? '—'}</span>
                    <span className="chip dim-chip inspector-conn-chip">{e.traffic}</span>
                  </div>
                );
              })}
              {edges.filter((e) => e.from === node.id || e.to === node.id).length === 0 && (
                <div className="dim inspector-empty-line">NO EDGES</div>
              )}
            </div>
            {onDeleteNode && (
              <button
                type="button"
                className="maze-btn alert small"
                disabled={isObserved || isGateway}
                title={
                  isObserved ? 'observed entity — not a deployed decky'
                  : isGateway ? 'DMZ gateway — pinned to its DMZ network'
                  : undefined
                }
                onClick={() => !isObserved && !isGateway && onDeleteNode(node.id)}
              >
                <Trash2 size={12} /> REMOVE FROM GRAPH
              </button>
            )}
          </>
        )}

        {net && (
          <>
            <div className="inspector-head">
              {net.kind === 'internet'
                ? <Globe size={14} className="violet-accent" />
                : <GitMerge size={14} className="violet-accent" />}
              <span className="inspector-head-title">{net.label}</span>
              {net.kind !== 'internet' && !activeNetIds.has(net.id) && (
                <span className="chip-mini inspector-head-chip">INACTIVE</span>
              )}
            </div>
            <div className="kvs">
              <div className="k">KIND</div><div className="v">{net.kind.toUpperCase()}</div>
              <div className="k">CIDR</div><div className="v">{net.cidr}</div>
              <div className="k">DECKIES</div>
              <div className="v" style={{ fontWeight: 700 }}>
                {nodes.filter((n) => n.netId === net.id).length}
              </div>
            </div>
            <div>
              <div className="type-label inspector-section-label">MEMBERS</div>
              {nodes.filter((n) => n.netId === net.id).map((n) => (
                <div
                  key={n.id}
                  className="inspector-member-row"
                  onClick={() => setSelection?.({ type: 'node', id: n.id })}
                >
                  <span className={`status-dot ${n.status}`} />
                  <span>{n.name}</span>
                  <span className="dim inspector-member-arch">{n.archetype}</span>
                </div>
              ))}
              {nodes.filter((n) => n.netId === net.id).length === 0 && (
                <div className="dim inspector-empty-line">NO MEMBERS</div>
              )}
            </div>
            {net.kind !== 'internet' && onAddDecky && (
              <button type="button" className="maze-btn small" onClick={() => onAddDecky(net.id)}>
                <Plus size={10} /> ADD DECKY
              </button>
            )}
            {net.kind !== 'internet' && onDeleteNet && (
              <button
                type="button"
                className="maze-btn alert small"
                onClick={() => onDeleteNet(net.id)}
              >
                <Trash2 size={10} /> REMOVE NETWORK
              </button>
            )}
          </>
        )}

        {edge && (
          <>
            <div className="inspector-head">
              <Server size={14} className="violet-accent" />
              <span className="inspector-head-title">EDGE · {edge.id.slice(0, 8)}</span>
            </div>
            <div className="kvs">
              <div className="k">FROM</div>
              <div className="v">{nodes.find((n) => n.id === edge.from)?.name ?? edge.from}</div>
              <div className="k">TO</div>
              <div className="v">{nodes.find((n) => n.id === edge.to)?.name ?? edge.to}</div>
              <div className="k">TRAFFIC</div>
              <div className="v">{edge.traffic.toUpperCase()}</div>
              {edge.label && (
                <>
                  <div className="k">LABEL</div>
                  <div className="v">{edge.label}</div>
                </>
              )}
            </div>
            {onDeleteEdge && (
              <button
                type="button"
                className="maze-btn alert small"
                onClick={() => onDeleteEdge(edge.id)}
              >
                <Trash2 size={10} /> CUT EDGE
              </button>
            )}
          </>
        )}

        {serviceSel && (
          <>
            <div className="inspector-head">
              <Shield
                size={14}
                className={serviceMeta?.risk === 'high' ? 'alert-text' : 'violet-accent'}
              />
              <span className="inspector-head-title">
                {serviceMeta?.name ?? serviceSel.id.toUpperCase()}
              </span>
              {serviceMeta && (
                <span className={`chip inspector-head-chip ${
                  serviceMeta.risk === 'high' ? 'alert'
                  : serviceMeta.risk === 'med' ? 'violet'
                  : 'dim-chip'
                }`}>
                  {serviceMeta.risk.toUpperCase()}
                </span>
              )}
            </div>
            <div className="kvs">
              <div className="k">EXPOSED ON</div>
              <div className="v violet-accent">{serviceParent?.name ?? '—'}</div>
              <div className="k">PROTOCOL</div>
              <div className="v">{(serviceMeta?.proto ?? '—').toUpperCase()}</div>
              <div className="k">PORT</div>
              <div className="v" style={{ fontWeight: 700 }}>{serviceMeta?.port ?? '—'}</div>
              <div className="k">SUBNET</div>
              <div className="v">{serviceParentNet?.label ?? '—'}</div>
            </div>
            {onRemoveService && serviceParent && serviceParent.kind !== 'observed' && (
              <button
                type="button"
                className="maze-btn alert small"
                disabled={topologyStatus === 'degraded'}
                title={topologyStatus === 'degraded' ? 'topology degraded — mutations blocked' : undefined}
                onClick={() => onRemoveService(serviceSel.nodeId, serviceSel.id)}
              >
                <Trash2 size={10} /> REMOVE SERVICE
              </button>
            )}
          </>
        )}

        {pendingChanges > 0 && (
          <div className="inspector-diff-block">
            <div className="type-label inspector-section-label">PENDING DIFF</div>
            <div className="maze-diff">
              <span className="ctx">  +{pendingChanges} graph mutation(s)</span>{'\n'}
              <span className="ctx">  networks: {nets.length}</span>{'\n'}
              <span className="ctx">  deckies:  {nodes.length}</span>{'\n'}
              <span className="ctx">  paths:    {edges.length}</span>
            </div>
          </div>
        )}

        {topologyStatus && !selection && (
          <div className="kvs inspector-status-block">
            <div className="k">TOPOLOGY</div>
            <div className="v">{topologyStatus.toUpperCase()}</div>
          </div>
        )}
      </div>
    </aside>
  );
};

export default Inspector;
