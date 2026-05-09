import React, { useEffect, useRef, useState } from 'react';
import { X } from '../../icons';
import api from '../../utils/api';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import type { CanaryTokenRow } from '../CanaryTokenDrawer';
import {
  KNOWN_GENERATORS, KIND_OPTIONS,
  type BlobRow, type DeckyOption, type TopologyOption, type Scope, type GeneratorName,
} from './types';
import { extractError, fmtBytes } from './helpers';
import { INPUT_STYLE, BTN_PRIMARY, BTN_GHOST, Field } from './ui';

interface Props {
  blobs: BlobRow[];
  deckies: DeckyOption[];
  topologies: TopologyOption[];
  onClose: () => void;
  onCreated: (token: CanaryTokenRow) => void;
}

/** Modal for planting a new canary token. Lets the operator pick
 *  fleet vs. topology scope, target decky, callback kind, placement
 *  path, and either a built-in template generator or a previously
 *  uploaded blob as the artifact source. */
export const CreateTokenModal: React.FC<Props> = ({ blobs, deckies, topologies, onClose, onCreated }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);

  const [scope, setScope] = useState<Scope>('fleet');
  const [topologyId, setTopologyId] = useState<string>(topologies[0]?.id ?? '');
  const [topoDeckies, setTopoDeckies] = useState<DeckyOption[]>([]);
  const [topoLoading, setTopoLoading] = useState(false);

  // When scope flips to topology (or topology selection changes) we
  // hydrate the chosen topology's decky list — different shape than the
  // /deckies endpoint, so the picker must repopulate.
  useEffect(() => {
    if (scope !== 'topology' || !topologyId) {
      setTopoDeckies([]);
      return;
    }
    let cancelled = false;
    setTopoLoading(true);
    api.get(`/topologies/${encodeURIComponent(topologyId)}`)
      .then((res) => {
        if (cancelled) return;
        const list: DeckyOption[] = (res.data?.deckies ?? []).map(
          (d: { name: string; ip?: string }) => ({ name: d.name, ip: d.ip }),
        );
        setTopoDeckies(list);
      })
      .catch(() => { if (!cancelled) setTopoDeckies([]); })
      .finally(() => { if (!cancelled) setTopoLoading(false); });
    return () => { cancelled = true; };
  }, [scope, topologyId]);

  const activeDeckies = scope === 'topology' ? topoDeckies : deckies;
  const [decky, setDecky] = useState(deckies[0]?.name ?? '');

  // Reset the decky selection when the active list changes — otherwise
  // a fleet decky name lingers as a stale value when the user flips to
  // a topology that doesn't have that decky.
  useEffect(() => {
    if (activeDeckies.length === 0) {
      setDecky('');
    } else if (!activeDeckies.some((d) => d.name === decky)) {
      setDecky(activeDeckies[0].name);
    }
  }, [activeDeckies]); // eslint-disable-line react-hooks/exhaustive-deps

  const [kind, setKind] = useState<'http' | 'dns' | 'aws_passive'>('http');
  const [path, setPath] = useState('/home/admin/.aws/credentials');
  const [source, setSource] = useState<'generator' | 'blob'>('generator');
  const [generator, setGenerator] = useState<GeneratorName>('aws_creds');
  const [blobUuid, setBlobUuid] = useState<string>('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setError(null);
    if (scope === 'topology' && !topologyId) return setError('Pick a topology.');
    if (!decky.trim()) return setError('Pick a decky.');
    if (!path.trim().startsWith('/')) return setError('placement_path must be absolute.');
    if (source === 'blob' && !blobUuid) return setError('Pick a blob or switch to Generator.');
    setSubmitting(true);
    try {
      const body: Record<string, unknown> = {
        decky_name: decky.trim(),
        kind,
        placement_path: path.trim(),
      };
      if (scope === 'topology') body.topology_id = topologyId;
      if (source === 'generator') body.generator = generator;
      else body.blob_uuid = blobUuid;
      const res = await api.post('/canary/tokens', body);
      onCreated(res.data);
    } catch (err) {
      setError(extractError(err, 'Create failed.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: 'fixed', inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        zIndex: 1000,
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        style={{
          width: 'min(560px, 100%)', maxHeight: '90vh', overflowY: 'auto',
          backgroundColor: 'var(--bg-color, #0d1117)',
          border: '1px solid var(--border-color, #30363d)',
          padding: '24px', color: 'var(--text-color)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ fontSize: '1rem', fontWeight: 'bold' }}>NEW CANARY TOKEN</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-color)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
          {(['fleet', 'topology'] as const).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setScope(s)}
              style={{
                flex: 1,
                padding: '8px',
                background: scope === s ? 'var(--accent-color, #00ff88)' : 'transparent',
                color: scope === s ? 'var(--bg-color, #0d1117)' : 'var(--text-color)',
                border: '1px solid var(--border-color, #30363d)',
                cursor: 'pointer', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em',
              }}
            >
              {s === 'fleet' ? 'Fleet' : 'MazeNET topology'}
            </button>
          ))}
        </div>

        {scope === 'topology' && (
          <Field label="Topology">
            {topologies.length === 0 ? (
              <div style={{ fontSize: '0.8rem', opacity: 0.6, padding: '8px 0' }}>
                No active topologies. Deploy one from MazeNET first.
              </div>
            ) : (
              <select
                value={topologyId}
                onChange={(e) => setTopologyId(e.target.value)}
                style={INPUT_STYLE}
              >
                {topologies.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.status})
                  </option>
                ))}
              </select>
            )}
          </Field>
        )}

        <Field label="Decky">
          {topoLoading ? (
            <div style={{ fontSize: '0.8rem', opacity: 0.6, padding: '8px 0' }}>
              loading topology deckies…
            </div>
          ) : activeDeckies.length === 0 ? (
            <div style={{ fontSize: '0.8rem', opacity: 0.6, padding: '8px 0' }}>
              {scope === 'topology'
                ? 'This topology has no deckies.'
                : 'No fleet deckies running. Deploy a fleet first.'}
            </div>
          ) : (
            <select
              value={decky}
              onChange={(e) => setDecky(e.target.value)}
              autoFocus
              style={INPUT_STYLE}
            >
              {activeDeckies.map((d) => (
                <option key={d.name} value={d.name}>
                  {d.name}{d.ip ? ` (${d.ip})` : ''}
                </option>
              ))}
            </select>
          )}
        </Field>

        <Field label="Kind">
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as typeof kind)}
            style={INPUT_STYLE}
          >
            {KIND_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </Field>

        <Field label="Placement path (inside the container)">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/home/admin/.aws/credentials"
            style={{ ...INPUT_STYLE, fontFamily: 'monospace' }}
          />
        </Field>

        <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
          {(['generator', 'blob'] as const).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSource(s)}
              style={{
                flex: 1,
                padding: '8px',
                background: source === s ? 'var(--accent-color, #00ff88)' : 'transparent',
                color: source === s ? 'var(--bg-color, #0d1117)' : 'var(--text-color)',
                border: '1px solid var(--border-color, #30363d)',
                cursor: 'pointer', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em',
              }}
            >
              {s === 'generator' ? 'Built-in template' : 'Operator upload'}
            </button>
          ))}
        </div>

        {source === 'generator' && (
          <Field label="Generator">
            <select
              value={generator}
              onChange={(e) => setGenerator(e.target.value as GeneratorName)}
              style={INPUT_STYLE}
            >
              {KNOWN_GENERATORS.map((g) => (
                <option key={g} value={g}>{g}</option>
              ))}
            </select>
          </Field>
        )}

        {source === 'blob' && (
          <Field label="Uploaded artifact">
            {blobs.length === 0 ? (
              <div style={{ fontSize: '0.8rem', opacity: 0.6, padding: '8px 0' }}>
                No blobs uploaded yet. Use "Upload artifact" on the main page first.
              </div>
            ) : (
              <select
                value={blobUuid}
                onChange={(e) => setBlobUuid(e.target.value)}
                style={INPUT_STYLE}
              >
                <option value="">— select —</option>
                {blobs.map((b) => (
                  <option key={b.uuid} value={b.uuid}>
                    {b.filename} ({b.content_type}, {fmtBytes(b.size_bytes)})
                  </option>
                ))}
              </select>
            )}
          </Field>
        )}

        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '12px' }}>{error}</div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '20px' }}>
          <button onClick={onClose} style={BTN_GHOST}>CANCEL</button>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            style={{ ...BTN_PRIMARY, opacity: submitting ? 0.5 : 1, cursor: submitting ? 'wait' : 'pointer' }}
          >
            {submitting ? 'PLANTING…' : 'PLANT TOKEN'}
          </button>
        </div>
      </div>
    </div>
  );
};
