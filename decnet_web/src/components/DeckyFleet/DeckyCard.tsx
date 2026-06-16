// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Network, Plus, PowerOff, RefreshCw, X } from '../../icons';
import api, { type ApiError } from '../../utils/api';
import AddServiceConfigModal from '../AddServiceConfigModal';
import ServiceConfigForm from '../ServiceConfigForm';
import { dotFor, hitsFor, stateColor } from './helpers';
import type { Decky } from './types';

interface Props {
  decky: Decky;
  mutating: boolean;
  isAdmin: boolean;
  armed: string | null;
  tdBusy: boolean;
  onForce: (name: string) => void;
  onTeardown: (d: Decky) => void;
  onIntervalChange: (name: string, current: number | null) => void;
  onInspect: (d: Decky) => void;
  innerRef?: React.Ref<HTMLDivElement>;
  /** Per-decky-eligible service slugs from useServiceRegistry. */
  availableServices: string[];
  /** Called after a successful live add/remove so the parent can
   *  optimistically apply the response's services list. */
  onServicesChanged: (deckyName: string, services: string[]) => void;
  /** Called after a tarpit enable/disable with success or error text. */
  onTarpitResult: (deckyName: string, ok: boolean, message: string) => void;
}

/** Single decky tile rendered inside the fleet grid. Owns its own
 *  add-service / tarpit / per-service-config local UI state; all
 *  data + lifecycle decisions come in via props from the parent. */
export const DeckyCard: React.FC<Props> = ({
  decky, mutating, isAdmin, armed, tdBusy, onForce, onTeardown, onIntervalChange, onInspect,
  innerRef, availableServices, onServicesChanged, onTarpitResult,
}) => {
  const dot = dotFor(decky);
  const hits = hitsFor(decky);
  const hot = dot === 'hot';
  const dotClass = mutating ? 'mutating' : dot;
  const tdKey = `td:${decky.swarm?.host_uuid ?? 'local'}:${decky.name}`;

  // Live service mutation is local-only (admin, non-swarm). Swarm
  // deckies live on a remote agent — the W3 path runs docker compose
  // locally and won't reach the agent's containers (same gap as the
  // canary planter has for agent-pinned topologies; out of scope here).
  const liveServicesEnabled = isAdmin && !decky.swarm;
  const [addOpen, setAddOpen] = useState(false);
  const [addSlug, setAddSlug] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [opError, setOpError] = useState<string | null>(null);
  const [openCfgSvc, setOpenCfgSvc] = useState<string | null>(null);
  // Pending add — when non-null, AddServiceConfigModal is mounted and
  // will either auto-fire onConfirm (no schema fields) or show the form.
  const [pendingAdd, setPendingAdd] = useState<{ deckyName: string; slug: string } | null>(null);

  // Tarpit controls — admin + non-swarm only (same gate as liveServicesEnabled)
  const [tarpitMenuOpen, setTarpitMenuOpen] = useState(false);
  const [tarpitFormOpen, setTarpitFormOpen] = useState(false);
  const [tarpitBusy, setTarpitBusy] = useState(false);
  const [tarpitPorts, setTarpitPorts] = useState('22');
  const [tarpitDelayMs, setTarpitDelayMs] = useState(30000);
  const tarpitMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!tarpitMenuOpen) return;
    const handler = (e: MouseEvent) => {
      if (tarpitMenuRef.current && !tarpitMenuRef.current.contains(e.target as Node)) {
        setTarpitMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [tarpitMenuOpen]);

  const enableTarpit = useCallback(async () => {
    const ports = tarpitPorts
      .split(',')
      .map((p) => parseInt(p.trim(), 10))
      .filter((p) => !isNaN(p) && p > 0 && p <= 65535);
    if (ports.length === 0) return;
    setTarpitBusy(true);
    try {
      await api.post(`/deckies/${encodeURIComponent(decky.name)}/tarpit`, {
        ports,
        delay_ms: tarpitDelayMs,
      });
      setTarpitFormOpen(false);
      setTarpitMenuOpen(false);
      onTarpitResult(decky.name, true, `TARPIT ON · ${decky.name.toUpperCase()} · ${ports.join(',')} / ${tarpitDelayMs}ms`);
    } catch (err) {
      const msg = (err as ApiError)?.response?.data?.detail ?? 'Tarpit enable failed';
      onTarpitResult(decky.name, false, msg);
    } finally {
      setTarpitBusy(false);
    }
  }, [decky.name, tarpitPorts, tarpitDelayMs, onTarpitResult]);

  const disableTarpit = useCallback(async () => {
    setTarpitBusy(true);
    setTarpitMenuOpen(false);
    try {
      await api.delete(`/deckies/${encodeURIComponent(decky.name)}/tarpit`);
      onTarpitResult(decky.name, true, `TARPIT OFF · ${decky.name.toUpperCase()}`);
    } catch (err) {
      const msg = (err as ApiError)?.response?.data?.detail ?? 'Tarpit disable failed';
      onTarpitResult(decky.name, false, msg);
    } finally {
      setTarpitBusy(false);
    }
  }, [decky.name, onTarpitResult]);

  const removeService = async (slug: string) => {
    setOpError(null);
    setBusy(slug);
    try {
      const { data } = await api.delete<{ services: string[] }>(
        `/deckies/${encodeURIComponent(decky.name)}/services/${encodeURIComponent(slug)}`,
      );
      onServicesChanged(decky.name, data.services);
    } catch (err) {
      const msg = (err as ApiError)?.response?.data?.detail
        ?? 'Remove failed.';
      setOpError(msg);
    } finally {
      setBusy(null);
    }
  };

  const beginAdd = () => {
    if (!addSlug) return;
    setOpError(null);
    setPendingAdd({ deckyName: decky.name, slug: addSlug });
  };

  const confirmAdd = async (deckyName: string, slug: string, cfg: Record<string, unknown>) => {
    setBusy(slug);
    try {
      const { data } = await api.post<{ services: string[] }>(
        `/deckies/${encodeURIComponent(deckyName)}/services`,
        { name: slug, config: cfg },
      );
      onServicesChanged(deckyName, data.services);
      setPendingAdd(null);
      setAddOpen(false);
      setAddSlug('');
    } catch (err) {
      // Re-raise so the modal can surface the error in its own status row.
      // Also mirror onto opError for the inline picker case.
      const msg = (err as ApiError)?.response?.data?.detail
        ?? 'Add failed.';
      setOpError(msg);
      throw err;
    } finally {
      setBusy(null);
    }
  };

  return (
    <div
      ref={innerRef}
      className={`decky-card ${hot ? 'hot' : ''}`}
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a, input')) return;
        onInspect(decky);
      }}
      style={{ cursor: 'pointer' }}
    >
      <div className="decky-head">
        <div className="decky-name">
          <span className={`status-dot ${dotClass}`} />
          {decky.name}
        </div>
        <span className="decky-ip">{decky.ip}</span>
      </div>

      {decky.swarm && (
        <div className="decky-swarm-row">
          <span className="decky-swarm-chip">
            <Network size={10} className="dim" />
            <span className="dim">{decky.swarm.host_name}</span>
            <span style={{ opacity: 0.5 }}>@ {decky.swarm.host_address || '—'}</span>
          </span>
          <span
            className="decky-swarm-state"
            style={{
              borderColor: stateColor(decky.swarm.state),
              color: stateColor(decky.swarm.state),
            }}
          >
            {decky.swarm.state.toUpperCase()}
          </span>
          {decky.swarm.last_error && (
            <span className="alert-text" title={decky.swarm.last_error} style={{ fontSize: '0.65rem' }}>
              ⚠ {decky.swarm.last_error.slice(0, 48)}
              {decky.swarm.last_error.length > 48 ? '…' : ''}
            </span>
          )}
        </div>
      )}

      <div className="decky-meta">
        <div className="row"><span className="label">HOST</span><span>{decky.hostname}</span></div>
        <div className="row"><span className="label">DISTRO</span><span className="dim">{decky.distro}</span></div>
        <div className="row">
          <span className="label">ARCHETYPE</span>
          <span className="violet-accent">{decky.archetype || '—'}</span>
        </div>
        <div className="row">
          <span className="label">MUTATE</span>
          {!decky.swarm && isAdmin ? (
            <span
              className={decky.mutate_interval ? 'violet-accent' : 'dim'}
              style={{ cursor: 'pointer', textDecoration: 'underline' }}
              onClick={() => onIntervalChange(decky.name, decky.mutate_interval)}
            >
              {decky.mutate_interval ? `EVERY ${decky.mutate_interval}m` : 'DISABLED'}
            </span>
          ) : (
            <span className={decky.mutate_interval ? 'violet-accent' : 'dim'}>
              {decky.mutate_interval ? `EVERY ${decky.mutate_interval}m` : 'DISABLED'}
            </span>
          )}
        </div>
      </div>

      <div>
        <div className="type-label" style={{ marginBottom: 6 }}>EXPOSED</div>
        <div className="decky-services">
          {decky.services.map((s) => (
            <span key={s} className="service-tag" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              {liveServicesEnabled ? (
                <button
                  type="button"
                  className="svc-cfg-toggle-btn"
                  title={`Configure ${s}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setOpenCfgSvc((cur) => (cur === s ? null : s));
                  }}
                >
                  {s}
                </button>
              ) : (
                <span>{s}</span>
              )}
              {liveServicesEnabled && (
                <button
                  type="button"
                  title={`Remove ${s}`}
                  disabled={busy === s}
                  onClick={(e) => { e.stopPropagation(); removeService(s); }}
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
          {liveServicesEnabled && !addOpen && (
            <button
              type="button"
              className="service-tag"
              onClick={(e) => { e.stopPropagation(); setAddOpen(true); setAddSlug(''); }}
              style={{ cursor: 'pointer', borderStyle: 'dashed' }}
              title="Add service (live)"
            >
              <Plus size={10} /> ADD
            </button>
          )}
        </div>
        {liveServicesEnabled && addOpen && (
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ display: 'flex', gap: 6, marginTop: 6, alignItems: 'center' }}
          >
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
                .filter((s) => !decky.services.includes(s))
                .map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <button
              type="button"
              disabled={!addSlug || busy === addSlug}
              onClick={beginAdd}
              className="btn violet small"
            >
              {busy === addSlug ? 'ADDING' : 'ADD'}
            </button>
            <button
              type="button"
              onClick={() => { setAddOpen(false); setAddSlug(''); }}
              className="btn small"
            >
              CANCEL
            </button>
          </div>
        )}
        {opError && (
          <div className="alert-text" style={{ fontSize: '0.7rem', marginTop: 6 }}>{opError}</div>
        )}
        {liveServicesEnabled && openCfgSvc && decky.services.includes(openCfgSvc) && (
          <div onClick={(e) => e.stopPropagation()}>
            <ServiceConfigForm
              key={`${decky.name}:${openCfgSvc}`}
              deckyName={decky.name}
              serviceSlug={openCfgSvc}
              currentConfig={decky.service_config?.[openCfgSvc] ?? {}}
            />
          </div>
        )}
      </div>

      <div className="decky-footer">
        <span className="decky-hits">
          <span className="dim">HITS 24h: </span>
          <span
            className={hot ? 'alert-text' : 'matrix-text'}
            style={{ fontWeight: 700 }}
          >
            {hits}
          </span>
        </span>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {!decky.swarm && isAdmin && (
            <button
              className="btn violet small"
              disabled={mutating}
              onClick={() => onForce(decky.name)}
              title="Force a mutation now"
            >
              <RefreshCw size={10} className={mutating ? 'fx-spin' : ''} />
              {mutating ? 'MUTATING' : 'FORCE MUTATE'}
            </button>
          )}
          {isAdmin && (
            <button
              className="btn alert small"
              disabled={tdBusy}
              onClick={() => onTeardown(decky)}
              title={decky.swarm ? 'Stop this decky on its host' : 'Tear down this decky'}
            >
              <PowerOff size={10} />
              {tdBusy
                ? 'TEARING DOWN…'
                : armed === tdKey ? 'CONFIRM' : 'TEARDOWN'}
            </button>
          )}
          {liveServicesEnabled && (
            <div className="tarpit-menu-wrap" ref={tarpitMenuRef}>
              <button
                type="button"
                className="btn small tarpit-menu-btn"
                title="Tarpit controls"
                disabled={tarpitBusy}
                onClick={() => {
                  setTarpitMenuOpen((o) => !o);
                  setTarpitFormOpen(false);
                }}
              >
                {tarpitBusy ? '…' : '⋮'}
              </button>
              {tarpitMenuOpen && (
                <div className="tarpit-dropdown">
                  <button
                    type="button"
                    className="tarpit-dropdown-item"
                    onClick={() => {
                      setTarpitMenuOpen(false);
                      setTarpitFormOpen(true);
                    }}
                  >
                    ENABLE TARPIT
                  </button>
                  <button
                    type="button"
                    className="tarpit-dropdown-item alert"
                    onClick={() => void disableTarpit()}
                  >
                    DISABLE TARPIT
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {liveServicesEnabled && tarpitFormOpen && (
        <div
          className="tarpit-form"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="tarpit-form-row">
            <label className="type-label" style={{ minWidth: 70 }}>PORTS</label>
            <input
              className="input"
              value={tarpitPorts}
              placeholder="22,80,443"
              onChange={(e) => setTarpitPorts(e.target.value)}
              style={{ flex: 1 }}
            />
          </div>
          <div className="tarpit-form-row">
            <label className="type-label" style={{ minWidth: 70 }}>DELAY</label>
            <input
              type="range"
              min={100}
              max={60000}
              step={100}
              value={tarpitDelayMs}
              onChange={(e) => setTarpitDelayMs(parseInt(e.target.value, 10))}
              style={{ flex: 1 }}
            />
            <span className="dim" style={{ fontSize: '0.7rem', minWidth: 52, textAlign: 'right' }}>
              {tarpitDelayMs >= 1000 ? `${(tarpitDelayMs / 1000).toFixed(1)}s` : `${tarpitDelayMs}ms`}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', marginTop: 4 }}>
            <button
              type="button"
              className="btn small"
              onClick={() => setTarpitFormOpen(false)}
            >
              CANCEL
            </button>
            <button
              type="button"
              className="btn alert small"
              disabled={tarpitBusy || !tarpitPorts.trim()}
              onClick={() => void enableTarpit()}
            >
              {tarpitBusy ? 'APPLYING…' : 'APPLY'}
            </button>
          </div>
        </div>
      )}
      <AddServiceConfigModal
        pending={pendingAdd}
        onCancel={() => setPendingAdd(null)}
        onConfirm={confirmAdd}
      />
    </div>
  );
};
