import React, { useEffect, useRef, useState } from 'react';
import { Upload, X, AlertTriangle } from '../../icons';
import api from '../../utils/api';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import type { DeckyOption, TopologyOption, Scope } from './types';
import { extractError, fmtBytes } from './helpers';
import { INPUT_STYLE, BTN_PRIMARY, BTN_GHOST, Field } from './ui';

// File drops aren't persisted server-side (W2 backend is fire-and-forget),
// so we keep a local log per admin uuid. This is informational only —
// the server has no record of what an admin dropped, by design (the
// endpoint exists to let operators stage payloads, not as an audit trail).
export const FILEDROP_LS_KEY = 'decnet:canary:filedrops';

export interface FileDropEntry {
  id: string;          // local-only uuid
  decky_name: string;
  topology_id: string | null;
  path: string;
  size_bytes: number;
  filename: string;
  mode: number;
  mtime_offset: number;
  dropped_at: string;  // ISO
}

export function loadFileDrops(): FileDropEntry[] {
  try {
    const raw = localStorage.getItem(FILEDROP_LS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveFileDrops(rows: FileDropEntry[]): void {
  try {
    localStorage.setItem(FILEDROP_LS_KEY, JSON.stringify(rows.slice(0, 200)));
  } catch {
    // localStorage may be full or disabled; the list is best-effort.
  }
}

interface Props {
  deckies: DeckyOption[];
  topologies: TopologyOption[];
  onClose: () => void;
  onDropped: (entry: FileDropEntry) => void;
}

/** Modal that POSTs raw bytes to /deckies/files. The browser reads
 *  the picked File via FileReader and ships it as base64. The list
 *  view that follows is local-only — the backend doesn't keep an
 *  audit trail of file drops by design. */
export const FileDropModal: React.FC<Props> = ({ deckies, topologies, onClose, onDropped }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);

  const [scope, setScope] = useState<Scope>('fleet');
  const [topologyId, setTopologyId] = useState<string>(topologies[0]?.id ?? '');
  const [topoDeckies, setTopoDeckies] = useState<DeckyOption[]>([]);
  const [topoLoading, setTopoLoading] = useState(false);

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
        setTopoDeckies(
          (res.data?.deckies ?? []).map((d: { name: string; ip?: string }) => ({
            name: d.name, ip: d.ip,
          })),
        );
      })
      .catch(() => { if (!cancelled) setTopoDeckies([]); })
      .finally(() => { if (!cancelled) setTopoLoading(false); });
    return () => { cancelled = true; };
  }, [scope, topologyId]);

  const activeDeckies = scope === 'topology' ? topoDeckies : deckies;
  const [decky, setDecky] = useState(deckies[0]?.name ?? '');

  useEffect(() => {
    if (activeDeckies.length === 0) setDecky('');
    else if (!activeDeckies.some((d) => d.name === decky)) setDecky(activeDeckies[0].name);
  }, [activeDeckies]); // eslint-disable-line react-hooks/exhaustive-deps

  const [path, setPath] = useState('/root/payload.bin');
  const [mode, setMode] = useState('644');
  const [mtimeOffset, setMtimeOffset] = useState('0');
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validatePath = (p: string): string | null => {
    if (!p.startsWith('/')) return 'path must be absolute (start with /)';
    if (p.split('/').includes('..')) return 'path must not contain .. segments';
    return null;
  };

  const handleSubmit = async () => {
    setError(null);
    if (scope === 'topology' && !topologyId) return setError('Pick a topology.');
    if (!decky.trim()) return setError('Pick a decky.');
    if (!file) return setError('Pick a file.');
    const pathErr = validatePath(path.trim());
    if (pathErr) return setError(pathErr);
    const modeNum = parseInt(mode, 8);
    if (Number.isNaN(modeNum) || modeNum < 0 || modeNum > 0o7777) {
      return setError('mode must be a 3- or 4-digit octal (e.g. 644, 0755).');
    }
    const offsetNum = parseInt(mtimeOffset, 10);
    if (Number.isNaN(offsetNum)) return setError('mtime offset must be an integer (seconds).');

    setSubmitting(true);
    try {
      // FileReader → base64. We strip the data: prefix from the
      // result; the backend wants raw base64 only.
      const reader = new FileReader();
      const b64: string = await new Promise((resolve, reject) => {
        reader.onerror = () => reject(reader.error);
        reader.onload = () => {
          const r = reader.result;
          if (typeof r !== 'string') return reject(new Error('FileReader did not return a string'));
          const comma = r.indexOf(',');
          resolve(comma >= 0 ? r.slice(comma + 1) : r);
        };
        reader.readAsDataURL(file);
      });

      const body: Record<string, unknown> = {
        decky_name: decky.trim(),
        path: path.trim(),
        content_b64: b64,
        mode: modeNum,
        mtime_offset: offsetNum,
      };
      if (scope === 'topology') body.topology_id = topologyId;
      await api.post('/deckies/files', body);

      const entry: FileDropEntry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        decky_name: decky.trim(),
        topology_id: scope === 'topology' ? topologyId : null,
        path: path.trim(),
        size_bytes: file.size,
        filename: file.name,
        mode: modeNum,
        mtime_offset: offsetNum,
        dropped_at: new Date().toISOString(),
      };
      onDropped(entry);
    } catch (err) {
      setError(extractError(err, 'File drop failed.'));
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
          <div style={{ fontSize: '1rem', fontWeight: 'bold' }}>DROP FILE ON DECKY</div>
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
                No active topologies.
              </div>
            ) : (
              <select
                value={topologyId}
                onChange={(e) => setTopologyId(e.target.value)}
                style={INPUT_STYLE}
              >
                {topologies.map((t) => (
                  <option key={t.id} value={t.id}>{t.name} ({t.status})</option>
                ))}
              </select>
            )}
          </Field>
        )}

        <Field label="Decky">
          {topoLoading ? (
            <div style={{ fontSize: '0.8rem', opacity: 0.6, padding: '8px 0' }}>loading…</div>
          ) : activeDeckies.length === 0 ? (
            <div style={{ fontSize: '0.8rem', opacity: 0.6, padding: '8px 0' }}>
              {scope === 'topology' ? 'This topology has no deckies.' : 'No fleet deckies running.'}
            </div>
          ) : (
            <select
              value={decky}
              onChange={(e) => setDecky(e.target.value)}
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

        <Field label="Destination path (inside the container)">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/root/payload.bin"
            style={{ ...INPUT_STYLE, fontFamily: 'monospace' }}
          />
        </Field>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <Field label="Mode (octal)">
            <input
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              placeholder="644"
              style={{ ...INPUT_STYLE, fontFamily: 'monospace' }}
            />
          </Field>
          <Field label="Mtime offset (seconds)">
            <div style={{ display: 'flex', gap: '6px', alignItems: 'flex-start' }}>
              <input
                value={mtimeOffset}
                onChange={(e) => setMtimeOffset(e.target.value)}
                placeholder="0"
                style={{ ...INPUT_STYLE, fontFamily: 'monospace', flex: 1 }}
              />
              <button
                type="button"
                onClick={() => setMtimeOffset(String(-7 * 24 * 3600))}
                title="Backdate to one week ago"
                style={{
                  padding: '8px 10px',
                  border: '1px solid var(--border-color, #30363d)',
                  background: 'transparent', color: 'var(--text-color)',
                  fontSize: '0.7rem', cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                -1w
              </button>
            </div>
          </Field>
        </div>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files?.[0];
            if (f) setFile(f);
          }}
          onClick={() => document.getElementById('canary-filedrop-input')?.click()}
          style={{
            border: `2px dashed ${dragOver ? 'var(--accent-color, #00ff88)' : 'var(--border-color, #30363d)'}`,
            padding: '20px',
            textAlign: 'center',
            marginBottom: '16px',
            cursor: 'pointer',
            background: dragOver ? 'rgba(0, 255, 136, 0.05)' : 'transparent',
          }}
        >
          <Upload size={24} style={{ opacity: 0.5, marginBottom: '6px' }} />
          <div style={{ fontSize: '0.85rem' }}>
            {file ? `${file.name} (${fmtBytes(file.size)})` : 'Drop a file here or click to browse'}
          </div>
          <input
            id="canary-filedrop-input"
            type="file"
            style={{ display: 'none' }}
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '8px 12px', marginBottom: '16px',
          border: '1px solid var(--warn)',
          backgroundColor: 'var(--warn-tint-10)',
          fontSize: '0.7rem', color: 'var(--warn)',
        }}>
          <AlertTriangle size={14} />
          File drops bypass canary instrumentation — bytes land verbatim. The list below is local only.
        </div>

        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '12px' }}>{error}</div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={BTN_GHOST}>CANCEL</button>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            style={{ ...BTN_PRIMARY, opacity: submitting ? 0.5 : 1, cursor: submitting ? 'wait' : 'pointer' }}
          >
            {submitting ? 'DROPPING…' : 'DROP FILE'}
          </button>
        </div>
      </div>
    </div>
  );
};
