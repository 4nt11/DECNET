import React, { useEffect, useMemo, useRef, useState } from 'react';
import api from '../../utils/api';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import { X, FileText } from '../../icons';
import { contentClassLabel, isCanaryClass } from '../../realism/labels';

// ─── Types ───────────────────────────────────────────────────────────────────

interface SyntheticFileRow {
  uuid: string;
  decky_uuid: string;
  path: string;
  persona: string;
  content_class: string;
  created_at: string;
  last_modified: string;
  edit_count: number;
  content_hash: string;
}

interface SyntheticFileDetail extends SyntheticFileRow {
  last_body: string;
  truncated: boolean;
}

interface PaginatedResponse {
  total: number;
  limit: number;
  offset: number;
  data: SyntheticFileRow[];
}

interface DeckyOption {
  uuid: string;
  name: string;
}

const PAGE_SIZE = 50;

// Fixed list of content_class values mirroring decnet/realism/taxonomy.py.
// A static dropdown beats free-text — the operator sees what's actually
// available without a typo path failing silently.
const CONTENT_CLASSES = [
  'note', 'todo', 'draft', 'script',
  'log_cron', 'log_daemon',
  'cache_tmp', 'config_local',
  'canary_aws_creds', 'canary_env_file', 'canary_git_config',
  'canary_ssh_key', 'canary_honeydoc', 'canary_honeydoc_docx',
  'canary_honeydoc_pdf', 'canary_mysql_dump',
] as const;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmt(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function deckyLabel(uuid: string, deckies: DeckyOption[]): string {
  const d = deckies.find((d) => d.uuid === uuid);
  return d ? d.name : `${uuid.slice(0, 8)}…`;
}

// ─── Drawer ──────────────────────────────────────────────────────────────────

interface DrawerProps {
  uuid: string;
  deckies: DeckyOption[];
  onClose: () => void;
}

const SyntheticFileDrawer: React.FC<DrawerProps> = ({ uuid, deckies, onClose }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  const [row, setRow] = useState<SyntheticFileDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.get<SyntheticFileDetail>(`/realism/synthetic-files/${encodeURIComponent(uuid)}`)
      .then((res) => { if (!cancelled) setRow(res.data); })
      .catch((err: any) => {
        if (cancelled) return;
        setError(err?.response?.status === 404 ? 'File no longer exists.' : 'Load failed.');
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [uuid]);

  return (
    <div
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: 'fixed', inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex', justifyContent: 'flex-end',
        zIndex: 1000,
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        style={{
          width: 'min(720px, 100%)', height: '100%',
          backgroundColor: 'var(--bg-color, #0d1117)',
          borderLeft: '1px solid var(--border-color, #30363d)',
          padding: '24px', overflowY: 'auto',
          color: 'var(--text-color)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em' }}>
              SYNTHETIC FILE {row ? `· ${deckyLabel(row.decky_uuid, deckies)}` : ''}
            </div>
            <div className="mono" style={{ fontSize: '0.95rem', fontWeight: 'bold', marginTop: '4px', wordBreak: 'break-all' }}>
              {row?.path ?? uuid}
            </div>
          </div>
          <button onClick={onClose} aria-label="Close" style={{ background: 'none', border: 'none', color: 'var(--text-color)', cursor: 'pointer' }}>
            <X size={18} />
          </button>
        </div>

        {loading && <div style={{ opacity: 0.6 }}>Loading…</div>}
        {error && <div style={{ color: '#ff5555' }}>{error}</div>}

        {row && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', rowGap: '6px', fontSize: '0.85rem', marginBottom: '16px' }}>
              <div style={{ color: 'var(--dim-color)' }}>PERSONA</div><div>{row.persona}</div>
              <div style={{ color: 'var(--dim-color)' }}>CONTENT CLASS</div>
              <div>
                <span style={{ color: isCanaryClass(row.content_class) ? '#ffaa66' : 'inherit' }}>
                  {contentClassLabel(row.content_class)}
                </span>
                <span className="mono" style={{ marginLeft: 8, fontSize: '0.75rem', color: 'var(--dim-color)' }}>
                  {row.content_class}
                </span>
              </div>
              <div style={{ color: 'var(--dim-color)' }}>EDIT COUNT</div><div>{row.edit_count}</div>
              <div style={{ color: 'var(--dim-color)' }}>CREATED</div><div>{fmt(row.created_at)}</div>
              <div style={{ color: 'var(--dim-color)' }}>LAST MODIFIED</div><div>{fmt(row.last_modified)}</div>
              <div style={{ color: 'var(--dim-color)' }}>CONTENT HASH</div>
              <div className="mono" style={{ wordBreak: 'break-all' }}>{row.content_hash}</div>
            </div>

            <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em' }}>
                  BODY PREVIEW ({(row.last_body?.length ?? 0).toLocaleString()} bytes)
                </span>
                {row.truncated && (
                  <span
                    className="chip dim-chip"
                    title="Body is at the 64KB cap; the decky filesystem holds the canonical bytes."
                  >
                    TRUNCATED
                  </span>
                )}
              </div>
              <pre className="mono" style={{
                whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                backgroundColor: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.05)',
                padding: '12px', fontSize: '0.78rem',
                maxHeight: '60vh', overflowY: 'auto',
              }}>
                {row.last_body || <span style={{ opacity: 0.4 }}>—</span>}
              </pre>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

// ─── Page ────────────────────────────────────────────────────────────────────

const SyntheticFiles: React.FC = () => {
  const [rows, setRows] = useState<SyntheticFileRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [deckies, setDeckies] = useState<DeckyOption[]>([]);
  const [deckyFilter, setDeckyFilter] = useState<string>('');     // '' = all
  const [personaFilter, setPersonaFilter] = useState<string>('');
  const [classFilter, setClassFilter] = useState<string>('');

  const [selectedUuid, setSelectedUuid] = useState<string | null>(null);

  useEffect(() => {
    api.get<DeckyOption[]>('/deckies')
      .then((res) => setDeckies(Array.isArray(res.data) ? res.data : []))
      .catch(() => setDeckies([]));
  }, []);

  const personaOptions = useMemo(() => {
    const set = new Set<string>();
    rows.forEach((r) => set.add(r.persona));
    return Array.from(set).sort();
  }, [rows]);

  const fetchRows = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('limit', String(PAGE_SIZE));
      params.set('offset', String(page * PAGE_SIZE));
      if (deckyFilter) params.set('decky_uuid', deckyFilter);
      if (personaFilter) params.set('persona', personaFilter);
      if (classFilter) params.set('content_class', classFilter);
      const res = await api.get<PaginatedResponse>(
        `/realism/synthetic-files?${params.toString()}`,
      );
      setRows(res.data.data);
      setTotal(res.data.total);
    } catch (err: any) {
      setError(err?.response?.status === 401 ? 'Authentication required.' : 'Load failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchRows(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [
    page, deckyFilter, personaFilter, classFilter,
  ]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div style={{ padding: '24px', color: 'var(--text-color)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
        <FileText size={18} />
        <h2 style={{ margin: 0, fontSize: '1.1rem', letterSpacing: '0.05em' }}>SYNTHETIC FILES</h2>
        <span style={{ marginLeft: 'auto', color: 'var(--dim-color)', fontSize: '0.8rem' }}>
          {total} total
        </span>
      </div>

      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
          <span style={{ color: 'var(--dim-color)' }}>Decky:</span>
          <select
            value={deckyFilter}
            onChange={(e) => { setDeckyFilter(e.target.value); setPage(0); }}
          >
            <option value="">All</option>
            {deckies.map((d) => (
              <option key={d.uuid} value={d.uuid}>{d.name}</option>
            ))}
          </select>
        </label>

        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
          <span style={{ color: 'var(--dim-color)' }}>Persona:</span>
          <select
            value={personaFilter}
            onChange={(e) => { setPersonaFilter(e.target.value); setPage(0); }}
          >
            <option value="">All</option>
            {personaOptions.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>

        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
          <span style={{ color: 'var(--dim-color)' }}>Class:</span>
          <select
            value={classFilter}
            onChange={(e) => { setClassFilter(e.target.value); setPage(0); }}
          >
            <option value="">All</option>
            {CONTENT_CLASSES.map((c) => (
              <option key={c} value={c}>{contentClassLabel(c)}</option>
            ))}
          </select>
        </label>
      </div>

      {error && <div style={{ color: '#ff5555', marginBottom: '12px' }}>{error}</div>}

      <div style={{ overflowX: 'auto', border: '1px solid rgba(255,255,255,0.05)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              <th style={{ padding: '8px 12px', color: 'var(--dim-color)', fontSize: '0.7rem', letterSpacing: '0.1em' }}>DECKY</th>
              <th style={{ padding: '8px 12px', color: 'var(--dim-color)', fontSize: '0.7rem', letterSpacing: '0.1em' }}>PATH</th>
              <th style={{ padding: '8px 12px', color: 'var(--dim-color)', fontSize: '0.7rem', letterSpacing: '0.1em' }}>PERSONA</th>
              <th style={{ padding: '8px 12px', color: 'var(--dim-color)', fontSize: '0.7rem', letterSpacing: '0.1em' }}>CLASS</th>
              <th style={{ padding: '8px 12px', color: 'var(--dim-color)', fontSize: '0.7rem', letterSpacing: '0.1em' }}>LAST MODIFIED</th>
              <th style={{ padding: '8px 12px', color: 'var(--dim-color)', fontSize: '0.7rem', letterSpacing: '0.1em' }}>EDITS</th>
              <th style={{ padding: '8px 12px', color: 'var(--dim-color)', fontSize: '0.7rem', letterSpacing: '0.1em' }}>HASH</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={7} style={{ padding: '20px', textAlign: 'center', opacity: 0.6 }}>Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={7} style={{ padding: '20px', textAlign: 'center', opacity: 0.6 }}>
                No files match the current filters.
              </td></tr>
            )}
            {!loading && rows.map((r) => (
              <tr
                key={r.uuid}
                className="clickable"
                onClick={() => setSelectedUuid(r.uuid)}
                style={{ cursor: 'pointer', borderBottom: '1px solid rgba(255,255,255,0.03)' }}
              >
                <td style={{ padding: '8px 12px' }}>{deckyLabel(r.decky_uuid, deckies)}</td>
                <td className="mono" style={{ padding: '8px 12px', wordBreak: 'break-all' }}>{r.path}</td>
                <td style={{ padding: '8px 12px' }}>{r.persona}</td>
                <td style={{
                  padding: '8px 12px',
                  color: isCanaryClass(r.content_class) ? '#ffaa66' : 'inherit',
                }}>
                  {contentClassLabel(r.content_class)}
                </td>
                <td style={{ padding: '8px 12px' }}>{fmt(r.last_modified)}</td>
                <td style={{ padding: '8px 12px' }}>{r.edit_count}</td>
                <td className="mono" style={{ padding: '8px 12px', opacity: 0.7 }}>{r.content_hash.slice(0, 12)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', gap: '8px', marginTop: '12px', alignItems: 'center' }}>
        <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>
          ← Prev
        </button>
        <span style={{ fontSize: '0.8rem', color: 'var(--dim-color)' }}>
          Page {page + 1} / {totalPages}
        </span>
        <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}>
          Next →
        </button>
      </div>

      {selectedUuid && (
        <SyntheticFileDrawer
          uuid={selectedUuid}
          deckies={deckies}
          onClose={() => setSelectedUuid(null)}
        />
      )}
    </div>
  );
};

export default SyntheticFiles;
