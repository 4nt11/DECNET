import React, { useEffect, useRef, useState } from 'react';
import {
  ArrowLeft, ArrowRight, Plus, Shield, Trash2, X,
} from '../../../icons';
import type { ApiError } from '../../../utils/api';
import type { DeckyNode, Edge, MazeNode, Net } from '../types';

export interface NodeInspectorProps {
  node: MazeNode;
  nodes: MazeNode[];
  nets: Net[];
  edges: Edge[];
  topologyStatus?: string;
  /** Per-decky-eligible service slugs, fetched via useServiceRegistry. */
  availableServices?: string[];
  onDeleteNode?: (id: string) => void;
  /** Trigger the schema-driven add-service flow. Synchronous: opens
   *  the AddServiceConfigModal at the page level (or auto-confirms if
   *  the service has no schema fields). Errors surface inside the modal. */
  onLiveAddService?: (nodeName: string, slug: string) => void;
  onLiveRemoveService?: (nodeName: string, slug: string) => Promise<void>;
  onToggleGateway?: (nodeId: string, nextValue: boolean) => Promise<void>;
  onLiveTarpitEnable?: (nodeName: string, ports: number[], delayMs: number) => Promise<void>;
  onLiveTarpitDisable?: (nodeName: string) => Promise<void>;
  /** Selection key used to reset local form state when the user
   *  picks a different node. */
  selectionKey: string | undefined;
}

const NodeInspector: React.FC<NodeInspectorProps> = ({
  node, nodes, nets, edges, topologyStatus, availableServices = [],
  onDeleteNode, onLiveAddService, onLiveRemoveService, onToggleGateway,
  onLiveTarpitEnable, onLiveTarpitDisable, selectionKey,
}) => {
  const liveOpsEnabled =
    !!onLiveAddService &&
    !!onLiveRemoveService &&
    (topologyStatus === 'active' || topologyStatus === 'degraded');

  const [addOpen, setAddOpen] = useState(false);
  const [addSlug, setAddSlug] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [opError, setOpError] = useState<string | null>(null);
  const [tarpitOpen, setTarpitOpen] = useState(false);
  const [tarpitPorts, setTarpitPorts] = useState('22');
  const [tarpitDelay, setTarpitDelay] = useState(30000);
  const tarpitEnabled = liveOpsEnabled && !!onLiveTarpitEnable && !!onLiveTarpitDisable;

  // Close tarpit form when selection changes
  const prevKey = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (selectionKey !== prevKey.current) {
      prevKey.current = selectionKey;
      setTarpitOpen(false);
    }
  }, [selectionKey]);

  const isObserved = node.kind === 'observed';
  const isGateway = node.kind === 'decky'
    && !!(node as DeckyNode).decky_config?.forwards_l3;

  const conns = edges.filter((e) => e.from === node.id || e.to === node.id);

  return (
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
              <span key={s} className="service-tag" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <span>{s}</span>
                {liveOpsEnabled && !isObserved && (
                  <button
                    type="button"
                    title={`Remove ${s} (live)`}
                    disabled={busy === s}
                    onClick={async () => {
                      setOpError(null);
                      setBusy(s);
                      try {
                        await onLiveRemoveService!(node.name, s);
                      } catch (err) {
                        const msg = (err as ApiError)?.response?.data?.detail
                          ?? 'Remove failed.';
                        setOpError(msg);
                      } finally {
                        setBusy(null);
                      }
                    }}
                    style={{
                      background: 'transparent', border: 'none', padding: 0,
                      color: 'inherit', cursor: busy === s ? 'wait' : 'pointer',
                      opacity: busy === s ? 0.4 : 0.7, lineHeight: 1,
                    }}
                  >
                    <X size={9} />
                  </button>
                )}
              </span>
            ))}
            {liveOpsEnabled && !isObserved && !addOpen && (
              <button
                type="button"
                className="service-tag"
                onClick={() => { setAddOpen(true); setAddSlug(''); }}
                style={{ cursor: 'pointer', borderStyle: 'dashed' }}
                title="Add service (live)"
              >
                <Plus size={10} /> ADD
              </button>
            )}
          </div>
          {liveOpsEnabled && addOpen && (
            <div style={{ display: 'flex', gap: 6, marginTop: 6, alignItems: 'center' }}>
              <select
                value={addSlug}
                onChange={(e) => setAddSlug(e.target.value)}
                style={{
                  flex: 1, fontSize: '0.75rem', padding: '4px 6px',
                  background: 'var(--matrix-tint-10)',
                  border: '1px solid var(--border-color, #30363d)',
                  color: 'var(--text-color)',
                }}
              >
                <option value="">— pick a service —</option>
                {availableServices
                  .filter((s) => !(node.services as readonly string[]).includes(s))
                  .map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
              </select>
              <button
                type="button"
                disabled={!addSlug || busy === addSlug}
                onClick={() => {
                  if (!addSlug) return;
                  setOpError(null);
                  // Fire-and-forget: opens the schema-driven config
                  // modal at the page level (or auto-confirms for
                  // schema-less services). Errors surface in the modal.
                  onLiveAddService!(node.name, addSlug);
                  setAddOpen(false);
                  setAddSlug('');
                }}
                style={{
                  padding: '4px 10px', fontSize: '0.7rem',
                  border: '1px solid var(--accent-color, #00ff88)',
                  background: 'var(--accent-color, #00ff88)',
                  color: 'var(--bg-color, #0d1117)',
                  cursor: busy === addSlug ? 'wait' : 'pointer',
                  opacity: !addSlug || busy === addSlug ? 0.5 : 1,
                  textTransform: 'uppercase',
                }}
              >
                ADD
              </button>
              <button
                type="button"
                onClick={() => { setAddOpen(false); setAddSlug(''); }}
                style={{
                  padding: '4px 10px', fontSize: '0.7rem',
                  border: '1px solid var(--dim-color)',
                  background: 'transparent', color: 'var(--dim-color)',
                  cursor: 'pointer', textTransform: 'uppercase',
                }}
              >
                CANCEL
              </button>
            </div>
          )}
          {opError && (
            <div style={{ color: '#ff5555', fontSize: '0.7rem', marginTop: 6 }}>{opError}</div>
          )}
        </div>
      </div>
      <div>
        <div className="type-label inspector-section-label">CONNECTIONS</div>
        {conns.map((e) => {
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
        {conns.length === 0 && (
          <div className="dim inspector-empty-line">NO EDGES</div>
        )}
      </div>
      {onToggleGateway && !isObserved && (
        <button
          type="button"
          className={`maze-btn small ${isGateway ? 'alert' : ''}`}
          disabled={busy === '__gateway__'}
          title={
            isGateway
              ? 'Demote this decky from gateway (forwards_l3=false)'
              : 'Promote this decky to gateway (forwards_l3=true)'
          }
          onClick={async () => {
            const next = !isGateway;
            // forwards_l3 flip on a deployed topology recreates
            // the base container — destructive. Confirm before
            // hitting the API; the caller (MazeNET.tsx) submits
            // with force: true on active topologies.
            const live = topologyStatus === 'active' || topologyStatus === 'degraded';
            if (live) {
              const ok = window.confirm(
                `${next ? 'Promote' : 'Demote'} ${node.name} ${next ? 'to' : 'from'} gateway?\n\n` +
                'This recreates the base container to apply the new port-publishing config. ' +
                'In-container state is lost; active sessions to it drop.',
              );
              if (!ok) return;
            }
            setOpError(null);
            setBusy('__gateway__');
            try {
              await onToggleGateway(node.id, next);
            } catch (err) {
              const msg = (err as ApiError)?.response?.data?.detail
                ?? 'Gateway toggle failed.';
              setOpError(msg);
            } finally {
              setBusy(null);
            }
          }}
        >
          <Shield size={12} />
          {busy === '__gateway__'
            ? (isGateway ? 'DEMOTING…' : 'PROMOTING…')
            : (isGateway ? 'DEMOTE GATEWAY' : 'PROMOTE TO GATEWAY')}
        </button>
      )}
      {tarpitEnabled && !isObserved && (
        <div className="inspector-tarpit-wrap">
          <div className="inspector-tarpit-row">
            <button
              type="button"
              className={`maze-btn small ${tarpitOpen ? 'active' : ''}`}
              disabled={busy === '__tarpit__'}
              onClick={() => setTarpitOpen((o) => !o)}
              title="Configure tc netem tarpit on this decky"
            >
              <Shield size={12} />
              {tarpitOpen ? 'CANCEL' : 'TARPIT'}
            </button>
            <button
              type="button"
              className="maze-btn alert small"
              disabled={busy === '__tarpit__'}
              title="Remove active tarpit rule"
              onClick={async () => {
                setOpError(null);
                setBusy('__tarpit__');
                try {
                  await onLiveTarpitDisable!(node.name);
                } catch (err) {
                  const msg = (err as ApiError)
                    ?.response?.data?.detail ?? 'Tarpit disable failed.';
                  setOpError(msg);
                } finally {
                  setBusy(null);
                }
              }}
            >
              {busy === '__tarpit__' ? '…' : 'DISABLE'}
            </button>
          </div>
          {tarpitOpen && (
            <div className="inspector-tarpit-form">
              <div className="inspector-tarpit-field">
                <label className="type-label">PORTS</label>
                <input
                  className="maze-input"
                  value={tarpitPorts}
                  placeholder="22,80,443"
                  onChange={(e) => setTarpitPorts(e.target.value)}
                />
              </div>
              <div className="inspector-tarpit-field">
                <label className="type-label">
                  DELAY · {tarpitDelay >= 1000
                    ? `${(tarpitDelay / 1000).toFixed(0)}s`
                    : `${tarpitDelay}ms`}
                </label>
                <input
                  type="range"
                  min={100}
                  max={60000}
                  step={100}
                  value={tarpitDelay}
                  onChange={(e) => setTarpitDelay(parseInt(e.target.value, 10))}
                  style={{ width: '100%' }}
                />
              </div>
              <button
                type="button"
                className="maze-btn alert small"
                disabled={busy === '__tarpit__' || !tarpitPorts.trim()}
                onClick={async () => {
                  const ports = tarpitPorts
                    .split(',')
                    .map((p) => parseInt(p.trim(), 10))
                    .filter((p) => !isNaN(p) && p > 0 && p <= 65535);
                  if (!ports.length) return;
                  setOpError(null);
                  setBusy('__tarpit__');
                  try {
                    await onLiveTarpitEnable!(node.name, ports, tarpitDelay);
                    setTarpitOpen(false);
                  } catch (err) {
                    const msg = (err as ApiError)
                      ?.response?.data?.detail ?? 'Tarpit enable failed.';
                    setOpError(msg);
                  } finally {
                    setBusy(null);
                  }
                }}
              >
                {busy === '__tarpit__' ? 'APPLYING…' : 'APPLY TARPIT'}
              </button>
            </div>
          )}
        </div>
      )}
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
  );
};

export default NodeInspector;
