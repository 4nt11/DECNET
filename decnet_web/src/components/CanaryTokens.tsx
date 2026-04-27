import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Plus, Upload, X, AlertTriangle, Search,
} from '../icons';
import api from '../utils/api';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';
import CanaryTokenDrawer from './CanaryTokenDrawer';
import type { CanaryTokenRow } from './CanaryTokenDrawer';

interface BlobRow {
  uuid: string;
  sha256: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: string;
  uploaded_at: string;
  token_count: number;
}

const KNOWN_GENERATORS = [
  'git_config', 'env_file', 'ssh_key', 'aws_creds', 'honeydoc',
] as const;
type GeneratorName = typeof KNOWN_GENERATORS[number];

const KIND_OPTIONS: Array<{ value: 'http' | 'dns' | 'aws_passive'; label: string }> = [
  { value: 'http', label: 'HTTP callback' },
  { value: 'dns', label: 'DNS callback' },
  { value: 'aws_passive', label: 'AWS passive (no callback)' },
];

function extractError(err: unknown, fallback: string): string {
  const e = err as { response?: { status?: number; data?: { detail?: string } } };
  if (e?.response?.data?.detail) return e.response.data.detail;
  if (e?.response?.status === 403) return 'Insufficient permissions (admin only).';
  if (e?.response?.status === 401) return 'Session expired — please log in again.';
  return fallback;
}

function fmt(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

const STATE_COLOR = {
  planted: '#00ff88',
  revoked: 'var(--dim-color)',
  failed: '#ff5555',
};

// ─── CREATE MODAL ──────────────────────────────────────────────────────────

interface DeckyOption {
  name: string;
  ip?: string;
}

interface CreateModalProps {
  blobs: BlobRow[];
  deckies: DeckyOption[];
  onClose: () => void;
  onCreated: (token: CanaryTokenRow) => void;
}

const CreateModal: React.FC<CreateModalProps> = ({ blobs, deckies, onClose, onCreated }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);

  const [decky, setDecky] = useState(deckies[0]?.name ?? '');
  const [kind, setKind] = useState<'http' | 'dns' | 'aws_passive'>('http');
  const [path, setPath] = useState('/home/admin/.aws/credentials');
  const [source, setSource] = useState<'generator' | 'blob'>('generator');
  const [generator, setGenerator] = useState<GeneratorName>('aws_creds');
  const [blobUuid, setBlobUuid] = useState<string>('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setError(null);
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

        <Field label="Decky">
          {deckies.length === 0 ? (
            <div style={{ fontSize: '0.8rem', opacity: 0.6, padding: '8px 0' }}>
              No deckies running. Deploy a fleet first.
            </div>
          ) : (
            <select
              value={decky}
              onChange={(e) => setDecky(e.target.value)}
              autoFocus
              style={INPUT_STYLE}
            >
              {deckies.map((d) => (
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
          border: '1px solid rgba(255, 170, 0, 0.3)',
          backgroundColor: 'rgba(255, 170, 0, 0.05)',
          fontSize: '0.75rem', color: '#ffaa00',
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

// ─── MAIN PAGE ─────────────────────────────────────────────────────────────

const CanaryTokens: React.FC = () => {
  const [tokens, setTokens] = useState<CanaryTokenRow[]>([]);
  const [blobs, setBlobs] = useState<BlobRow[]>([]);
  const [deckies, setDeckies] = useState<DeckyOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'tokens' | 'blobs'>('tokens');
  const [filter, setFilter] = useState('');
  const [stateFilter, setStateFilter] = useState<'all' | 'planted' | 'revoked' | 'failed'>('all');

  const [showCreate, setShowCreate] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [drawerToken, setDrawerToken] = useState<CanaryTokenRow | null>(null);

  const loadAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const [t, b, d] = await Promise.all([
        api.get('/canary/tokens'),
        api.get('/canary/blobs').catch(() => ({ data: { blobs: [] } })), // viewers can't list blobs
        api.get<DeckyOption[]>('/deckies').catch(() => ({ data: [] })),
      ]);
      setTokens(t.data.tokens || []);
      setBlobs(b.data.blobs || []);
      setDeckies(Array.isArray(d.data) ? d.data : []);
    } catch (err) {
      setError(extractError(err, 'Failed to load canary tokens.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAll(); }, []);

  // Alt+C — open the create modal (per feedback_linux_meta_key).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.altKey && e.key.toLowerCase() === 'c' && !showCreate && !showUpload && !drawerToken) {
        e.preventDefault();
        setShowCreate(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [showCreate, showUpload, drawerToken]);

  const visibleTokens = useMemo(() => {
    return tokens.filter((t) => {
      if (stateFilter !== 'all' && t.state !== stateFilter) return false;
      if (!filter) return true;
      const f = filter.toLowerCase();
      return (
        t.decky_name.toLowerCase().includes(f) ||
        t.placement_path.toLowerCase().includes(f) ||
        t.callback_token.toLowerCase().includes(f) ||
        (t.generator || '').toLowerCase().includes(f) ||
        (t.instrumenter || '').toLowerCase().includes(f)
      );
    });
  }, [tokens, filter, stateFilter]);

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
          <h1>CANARY TOKENS</h1>
          <span className="page-sub">
            {tokens.length} TOKEN{tokens.length === 1 ? '' : 'S'} · {counts.planted} PLANTED · {counts.hits} TOTAL HIT{counts.hits === 1 ? '' : 'S'} · {blobs.length} UPLOADED BLOB{blobs.length === 1 ? '' : 'S'}
          </span>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setShowUpload(true)}>
            <Upload size={12} /> UPLOAD ARTIFACT
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
        {(['tokens', 'blobs'] as const).map((t) => (
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
            {t === 'tokens' ? `Tokens (${tokens.length})` : `Blobs (${blobs.length})`}
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
                  gridTemplateColumns: '110px 140px 1fr 100px 110px 80px',
                  alignItems: 'center', gap: '12px',
                  padding: '10px 14px',
                  border: '1px solid var(--border-color, #30363d)',
                  background: 'rgba(255,255,255,0.02)',
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
                  background: 'rgba(255,255,255,0.02)',
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

      {showCreate && (
        <CreateModal
          blobs={blobs}
          deckies={deckies}
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
    </div>
  );
};

// ─── small style helpers ───────────────────────────────────────────────────

const INPUT_STYLE: React.CSSProperties = {
  width: '100%',
  padding: '8px 10px',
  marginBottom: '12px',
  background: 'rgba(255,255,255,0.03)',
  border: '1px solid var(--border-color, #30363d)',
  color: 'var(--text-color)',
  fontSize: '0.85rem',
};

const BTN_PRIMARY: React.CSSProperties = {
  padding: '8px 14px',
  border: '1px solid var(--accent-color, #00ff88)',
  background: 'var(--accent-color, #00ff88)',
  color: 'var(--bg-color, #0d1117)',
  cursor: 'pointer',
  fontSize: '0.8rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  fontWeight: 'bold',
};

const BTN_GHOST: React.CSSProperties = {
  padding: '8px 14px',
  border: '1px solid var(--text-color)',
  background: 'transparent',
  color: 'var(--text-color)',
  cursor: 'pointer',
  fontSize: '0.8rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
};

const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div>
    <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em', marginBottom: '4px' }}>
      {label.toUpperCase()}
    </div>
    {children}
  </div>
);

const Stat: React.FC<{ label: string; value: number | string; color: string }> = ({ label, value, color }) => (
  <div style={{
    flex: '1 1 120px',
    padding: '12px 16px',
    border: '1px solid var(--border-color, #30363d)',
    background: 'rgba(255,255,255,0.02)',
  }}>
    <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em' }}>{label}</div>
    <div style={{ fontSize: '1.4rem', fontWeight: 'bold', color, marginTop: '4px' }}>{value}</div>
  </div>
);

export default CanaryTokens;
