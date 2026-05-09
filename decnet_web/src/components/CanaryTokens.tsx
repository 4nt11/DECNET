import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Plus, Upload, X, AlertTriangle, Search, Target,
} from '../icons';
import api from '../utils/api';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';
import CanaryTokenDrawer from './CanaryTokenDrawer';
import type { CanaryTokenRow } from './CanaryTokenDrawer';
import {
  STATE_COLOR,
  type BlobRow, type DeckyOption, type TopologyOption, type Scope,
} from './CanaryTokens/types';
import { extractError, fmt, fmtBytes } from './CanaryTokens/helpers';
import { INPUT_STYLE, BTN_PRIMARY, BTN_GHOST, Field, Stat } from './CanaryTokens/ui';
import { CreateTokenModal } from './CanaryTokens/CreateTokenModal';

// ─── BLOB UPLOAD MODAL ─────────────────────────────────────────────────────

interface UploadModalProps {
  onClose: () => void;
  onUploaded: (blob: BlobRow) => void;
}

const UploadModal: React.FC<UploadModalProps> = ({ onClose, onUploaded }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);

  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const handleSubmit = async () => {
    if (!file) return setError('Pick a file first.');
    setUploading(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await api.post('/canary/blobs', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      onUploaded(res.data);
    } catch (err) {
      setError(extractError(err, 'Upload failed.'));
    } finally {
      setUploading(false);
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
          width: 'min(520px, 100%)',
          backgroundColor: 'var(--bg-color, #0d1117)',
          border: '1px solid var(--border-color, #30363d)',
          padding: '24px', color: 'var(--text-color)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ fontSize: '1rem', fontWeight: 'bold' }}>UPLOAD CANARY ARTIFACT</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-color)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
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
          style={{
            border: `2px dashed ${dragOver ? 'var(--accent-color, #00ff88)' : 'var(--border-color, #30363d)'}`,
            padding: '32px',
            textAlign: 'center',
            marginBottom: '16px',
            cursor: 'pointer',
            background: dragOver ? 'rgba(0, 255, 136, 0.05)' : 'transparent',
          }}
          onClick={() => document.getElementById('canary-blob-input')?.click()}
        >
          <Upload size={32} style={{ opacity: 0.5, marginBottom: '8px' }} />
          <div style={{ fontSize: '0.85rem' }}>
            {file ? `${file.name} (${fmtBytes(file.size)})` : 'Drop a file here or click to browse'}
          </div>
          {!file && (
            <div style={{ fontSize: '0.7rem', opacity: 0.6, marginTop: '6px' }}>
              DOCX · XLSX · PDF · HTML · PNG/JPEG · plain configs
            </div>
          )}
          <input
            id="canary-blob-input"
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
          fontSize: '0.75rem', color: 'var(--warn)',
        }}>
          <AlertTriangle size={14} />
          DECNET injects the callback server-side; the original bytes stay on the master.
        </div>

        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '12px' }}>{error}</div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={BTN_GHOST}>CANCEL</button>
          <button
            onClick={handleSubmit}
            disabled={!file || uploading}
            style={{ ...BTN_PRIMARY, opacity: (!file || uploading) ? 0.5 : 1, cursor: uploading ? 'wait' : 'pointer' }}
          >
            {uploading ? 'UPLOADING…' : 'UPLOAD'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── FILE DROP MODAL ───────────────────────────────────────────────────────

// File drops aren't persisted server-side (W2 backend is fire-and-forget),
// so we keep a local log per admin uuid.  This is informational only —
// the server has no record of what an admin dropped, by design (the
// endpoint exists to let operators stage payloads, not as an audit trail).
const FILEDROP_LS_KEY = 'decnet:canary:filedrops';

interface FileDropEntry {
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

function loadFileDrops(): FileDropEntry[] {
  try {
    const raw = localStorage.getItem(FILEDROP_LS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveFileDrops(rows: FileDropEntry[]): void {
  try {
    localStorage.setItem(FILEDROP_LS_KEY, JSON.stringify(rows.slice(0, 200)));
  } catch {
    // localStorage may be full or disabled; the list is best-effort.
  }
}

interface FileDropModalProps {
  deckies: DeckyOption[];
  topologies: TopologyOption[];
  onClose: () => void;
  onDropped: (entry: FileDropEntry) => void;
}

const FileDropModal: React.FC<FileDropModalProps> = ({ deckies, topologies, onClose, onDropped }) => {
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
      // FileReader → base64.  We strip the data: prefix from the
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

// ─── MAIN PAGE ─────────────────────────────────────────────────────────────

const CanaryTokens: React.FC = () => {
  const [tokens, setTokens] = useState<CanaryTokenRow[]>([]);
  const [blobs, setBlobs] = useState<BlobRow[]>([]);
  const [deckies, setDeckies] = useState<DeckyOption[]>([]);
  const [topologies, setTopologies] = useState<TopologyOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'tokens' | 'blobs' | 'filedrops'>('tokens');
  const [fileDrops, setFileDrops] = useState<FileDropEntry[]>(() => loadFileDrops());
  const [showFileDrop, setShowFileDrop] = useState(false);
  const [filter, setFilter] = useState('');
  const [stateFilter, setStateFilter] = useState<'all' | 'planted' | 'revoked' | 'failed'>('all');
  const [scopeFilter, setScopeFilter] = useState<'all' | 'fleet' | 'topology'>('all');

  const [showCreate, setShowCreate] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [drawerToken, setDrawerToken] = useState<CanaryTokenRow | null>(null);

  const loadAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const [t, b, d, topos] = await Promise.all([
        api.get('/canary/tokens'),
        api.get('/canary/blobs').catch(() => ({ data: { blobs: [] } })), // viewers can't list blobs
        api.get<DeckyOption[]>('/deckies').catch(() => ({ data: [] })),
        // Active topologies only — planting on a torn-down or pending
        // topology would 422/404 anyway.  Endpoint shape: { data: [...] }
        // Trailing slash matters: FastAPI's slash-redirect issues a 307
        // and the browser re-fires without the Authorization header,
        // landing as 401 on the redirected URL.  Hit the canonical
        // path (/topologies/) directly.
        api.get('/topologies/?status=active').catch(() => ({ data: { data: [] } })),
      ]);
      setTokens(t.data.tokens || []);
      setBlobs(b.data.blobs || []);
      setDeckies(Array.isArray(d.data) ? d.data : []);
      const topoRows: Array<{ id: string; name: string; status: string }> =
        topos.data?.data ?? [];
      setTopologies(topoRows.map((r) => ({ id: r.id, name: r.name, status: r.status })));
    } catch (err) {
      setError(extractError(err, 'Failed to load canary tokens.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAll(); }, []);

  // Alt+C / Alt+D — open create-token / drop-file modals (per
  // feedback_linux_meta_key — never Meta/⌘ on Linux).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const anyModalOpen = showCreate || showUpload || showFileDrop || drawerToken;
      if (anyModalOpen) return;
      if (e.altKey && e.key.toLowerCase() === 'c') {
        e.preventDefault();
        setShowCreate(true);
      } else if (e.altKey && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        setShowFileDrop(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [showCreate, showUpload, showFileDrop, drawerToken]);

  const visibleTokens = useMemo(() => {
    return tokens.filter((t) => {
      if (stateFilter !== 'all' && t.state !== stateFilter) return false;
      if (scopeFilter === 'fleet' && t.topology_id) return false;
      if (scopeFilter === 'topology' && !t.topology_id) return false;
      if (!filter) return true;
      const f = filter.toLowerCase();
      return (
        t.decky_name.toLowerCase().includes(f) ||
        t.placement_path.toLowerCase().includes(f) ||
        t.callback_token.toLowerCase().includes(f) ||
        (t.generator || '').toLowerCase().includes(f) ||
        (t.instrumenter || '').toLowerCase().includes(f) ||
        (t.topology_id || '').toLowerCase().includes(f)
      );
    });
  }, [tokens, filter, stateFilter, scopeFilter]);

  const counts = useMemo(() => {
    const c = { planted: 0, revoked: 0, failed: 0, hits: 0 };
    for (const t of tokens) {
      c[t.state] += 1;
      c.hits += t.trigger_count;
    }
    return c;
  }, [tokens]);

  const handleDeleteBlob = async (uuid: string) => {
    if (!window.confirm('Delete this blob? Refused if any token still references it.')) return;
    try {
      await api.delete(`/canary/blobs/${encodeURIComponent(uuid)}`);
      setBlobs((prev) => prev.filter((b) => b.uuid !== uuid));
    } catch (err) {
      alert(extractError(err, 'Delete failed.'));
    }
  };

  return (
    <div className="fleet-root canary-tokens-root" style={{ padding: '24px', color: 'var(--text-color)' }}>
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Target size={22} className="violet-accent" />
            <h1>CANARY TOKENS</h1>
          </div>
          <span className="page-sub">
            {tokens.length} TOKEN{tokens.length === 1 ? '' : 'S'} · {counts.planted} PLANTED · {counts.hits} TOTAL HIT{counts.hits === 1 ? '' : 'S'} · {blobs.length} UPLOADED BLOB{blobs.length === 1 ? '' : 'S'}
          </span>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setShowUpload(true)}>
            <Upload size={12} /> UPLOAD ARTIFACT
          </button>
          <button className="btn" onClick={() => setShowFileDrop(true)} title="Alt+D">
            <Upload size={12} /> DROP FILE
          </button>
          <button className="btn violet" onClick={() => setShowCreate(true)} title="Alt+C">
            <Plus size={12} /> NEW TOKEN
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px', flexWrap: 'wrap' }}>
        <Stat label="PLANTED" value={counts.planted} color={STATE_COLOR.planted} />
        <Stat label="REVOKED" value={counts.revoked} color={STATE_COLOR.revoked} />
        <Stat label="FAILED" value={counts.failed} color={STATE_COLOR.failed} />
        <Stat label="TOTAL HITS" value={counts.hits} color="#00ff88" />
        <Stat label="UPLOADED BLOBS" value={blobs.length} color="var(--text-color)" />
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', borderBottom: '1px solid var(--border-color, #30363d)' }}>
        {(['tokens', 'blobs', 'filedrops'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              background: 'transparent', border: 'none',
              color: tab === t ? 'var(--text-color)' : 'var(--dim-color)',
              padding: '8px 16px', cursor: 'pointer',
              borderBottom: tab === t ? '2px solid var(--accent-color, #00ff88)' : '2px solid transparent',
              fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em',
            }}
          >
            {t === 'tokens'
              ? `Tokens (${tokens.length})`
              : t === 'blobs'
                ? `Blobs (${blobs.length})`
                : `File drops (${fileDrops.length})`}
          </button>
        ))}
      </div>

      {tab === 'tokens' && (
        <>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: '1 1 300px' }}>
              <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', opacity: 0.5 }} />
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter by decky / path / slug / generator…"
                style={{ ...INPUT_STYLE, paddingLeft: '32px', marginBottom: 0 }}
              />
            </div>
            <select
              value={stateFilter}
              onChange={(e) => setStateFilter(e.target.value as typeof stateFilter)}
              style={{ ...INPUT_STYLE, marginBottom: 0, width: 'auto' }}
            >
              <option value="all">all states</option>
              <option value="planted">planted</option>
              <option value="revoked">revoked</option>
              <option value="failed">failed</option>
            </select>
            <select
              value={scopeFilter}
              onChange={(e) => setScopeFilter(e.target.value as typeof scopeFilter)}
              style={{ ...INPUT_STYLE, marginBottom: 0, width: 'auto' }}
            >
              <option value="all">all scopes</option>
              <option value="fleet">fleet only</option>
              <option value="topology">topology only</option>
            </select>
          </div>

          {loading && <div style={{ opacity: 0.6 }}>loading…</div>}
          {error && <div style={{ color: '#ff5555', marginBottom: '16px' }}>{error}</div>}
          {!loading && visibleTokens.length === 0 && (
            <div style={{ textAlign: 'center', padding: '40px', opacity: 0.6, fontSize: '0.85rem' }}>
              {tokens.length === 0
                ? 'No canary tokens yet. Click NEW TOKEN to plant one, or UPLOAD ARTIFACT to start with an operator-supplied document.'
                : 'No tokens match the current filter.'}
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {visibleTokens.map((t) => (
              <button
                key={t.uuid}
                onClick={() => setDrawerToken(t)}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '110px 80px 140px 1fr 100px 110px 80px',
                  alignItems: 'center', gap: '12px',
                  padding: '10px 14px',
                  border: '1px solid var(--border-color, #30363d)',
                  background: 'var(--matrix-tint-5)',
                  color: 'var(--text-color)',
                  cursor: 'pointer',
                  textAlign: 'left',
                  fontSize: '0.8rem',
                }}
              >
                <span style={{
                  color: STATE_COLOR[t.state], fontFamily: 'monospace',
                  fontSize: '0.7rem', letterSpacing: '0.05em',
                }}>
                  ● {t.state.toUpperCase()}
                </span>
                <span
                  title={t.topology_id ? `topology ${t.topology_id}` : 'fleet'}
                  style={{
                    fontSize: '0.65rem', letterSpacing: '0.05em',
                    padding: '2px 6px',
                    border: `1px solid ${t.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)'}`,
                    color: t.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)',
                    textAlign: 'center',
                    textTransform: 'uppercase',
                  }}
                >
                  {t.topology_id ? 'topology' : 'fleet'}
                </span>
                <span style={{ fontFamily: 'monospace' }}>{t.decky_name}</span>
                <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.placement_path}
                </span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>
                  {t.kind === 'aws_passive' ? 'aws-passive' : t.kind}
                </span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7, fontFamily: 'monospace' }}>
                  {t.generator || t.instrumenter || '?'}
                </span>
                <span style={{ textAlign: 'right', fontFamily: 'monospace', color: t.trigger_count > 0 ? '#00ff88' : 'var(--dim-color)' }}>
                  {t.trigger_count} {t.trigger_count === 1 ? 'hit' : 'hits'}
                </span>
              </button>
            ))}
          </div>
        </>
      )}

      {tab === 'blobs' && (
        <>
          {blobs.length === 0 && (
            <div style={{ textAlign: 'center', padding: '40px', opacity: 0.6, fontSize: '0.85rem' }}>
              No uploaded artifacts. Click UPLOAD ARTIFACT to add one.
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {blobs.map((b) => (
              <div
                key={b.uuid}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 220px 90px 100px 80px',
                  alignItems: 'center', gap: '12px',
                  padding: '10px 14px',
                  border: '1px solid var(--border-color, #30363d)',
                  background: 'var(--matrix-tint-5)',
                  fontSize: '0.8rem',
                }}
              >
                <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {b.filename}
                </span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7, fontFamily: 'monospace' }}>{b.content_type}</span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmtBytes(b.size_bytes)}</span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmt(b.uploaded_at)}</span>
                <button
                  onClick={() => handleDeleteBlob(b.uuid)}
                  disabled={b.token_count > 0}
                  title={b.token_count > 0 ? `${b.token_count} token(s) still reference this blob` : 'Delete'}
                  style={{
                    background: 'transparent', color: b.token_count > 0 ? 'var(--dim-color)' : '#ff5555',
                    border: `1px solid ${b.token_count > 0 ? 'var(--dim-color)' : '#ff5555'}`,
                    padding: '4px 8px', fontSize: '0.7rem',
                    cursor: b.token_count > 0 ? 'not-allowed' : 'pointer',
                    opacity: b.token_count > 0 ? 0.4 : 1,
                  }}
                >
                  {b.token_count > 0 ? `${b.token_count} REFS` : 'DELETE'}
                </button>
              </div>
            ))}
          </div>
        </>
      )}

      {tab === 'filedrops' && (
        <>
          <div style={{
            display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '12px',
            justifyContent: 'space-between',
          }}>
            <div style={{ fontSize: '0.75rem', opacity: 0.6 }}>
              Local log only — the server doesn't persist file drops.
              Cleared when you clear browser storage.
            </div>
            {fileDrops.length > 0 && (
              <button
                onClick={() => {
                  if (window.confirm('Clear local file drop history? This does not delete dropped files.')) {
                    setFileDrops([]);
                    saveFileDrops([]);
                  }
                }}
                style={{
                  padding: '4px 10px',
                  border: '1px solid var(--dim-color)',
                  background: 'transparent', color: 'var(--dim-color)',
                  fontSize: '0.7rem', cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                CLEAR LIST
              </button>
            )}
          </div>
          {fileDrops.length === 0 && (
            <div style={{ textAlign: 'center', padding: '40px', opacity: 0.6, fontSize: '0.85rem' }}>
              No file drops in this browser yet. Click DROP FILE to send bytes to a decky.
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {fileDrops.map((fd) => (
              <div
                key={fd.id}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '80px 140px 1fr 90px 80px 140px',
                  alignItems: 'center', gap: '12px',
                  padding: '10px 14px',
                  border: '1px solid var(--border-color, #30363d)',
                  background: 'var(--matrix-tint-5)',
                  fontSize: '0.8rem',
                }}
              >
                <span
                  title={fd.topology_id ? `topology ${fd.topology_id}` : 'fleet'}
                  style={{
                    fontSize: '0.65rem', letterSpacing: '0.05em',
                    padding: '2px 6px',
                    border: `1px solid ${fd.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)'}`,
                    color: fd.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)',
                    textAlign: 'center',
                    textTransform: 'uppercase',
                  }}
                >
                  {fd.topology_id ? 'topology' : 'fleet'}
                </span>
                <span style={{ fontFamily: 'monospace' }}>{fd.decky_name}</span>
                <span
                  title={`${fd.filename} → ${fd.path}`}
                  style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                >
                  {fd.path}
                </span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmtBytes(fd.size_bytes)}</span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7, fontFamily: 'monospace' }}>{fd.mode.toString(8)}</span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmt(fd.dropped_at)}</span>
              </div>
            ))}
          </div>
        </>
      )}

      {showCreate && (
        <CreateTokenModal
          blobs={blobs}
          deckies={deckies}
          topologies={topologies}
          onClose={() => setShowCreate(false)}
          onCreated={(t) => {
            setTokens((prev) => [t, ...prev]);
            setShowCreate(false);
          }}
        />
      )}
      {showUpload && (
        <UploadModal
          onClose={() => setShowUpload(false)}
          onUploaded={(b) => {
            setBlobs((prev) => prev.some((x) => x.uuid === b.uuid) ? prev : [b, ...prev]);
            setShowUpload(false);
          }}
        />
      )}
      {drawerToken && (
        <CanaryTokenDrawer
          token={drawerToken}
          onClose={() => setDrawerToken(null)}
          onRevoked={(uuid) => {
            setTokens((prev) => prev.map((t) =>
              t.uuid === uuid ? { ...t, state: 'revoked' } : t,
            ));
            setDrawerToken(null);
          }}
        />
      )}
      {showFileDrop && (
        <FileDropModal
          deckies={deckies}
          topologies={topologies}
          onClose={() => setShowFileDrop(false)}
          onDropped={(entry) => {
            setFileDrops((prev) => {
              const next = [entry, ...prev].slice(0, 200);
              saveFileDrops(next);
              return next;
            });
            setShowFileDrop(false);
            setTab('filedrops');
          }}
        />
      )}
    </div>
  );
};

export default CanaryTokens;
