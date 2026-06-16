// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useRef, useState } from 'react';
import api from '../../utils/api';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import { X, FileText } from '../../icons';
import { contentClassLabel, isCanaryClass } from '../../realism/labels';
// Reuse the DeckyFleet shell + the persona-page tweaks so this page reads
// the same as the rest of the realism nav group.
import '../DeckyFleet.css';
import '../PersonaGeneration.css';
import './SyntheticFiles.css';

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
  'log_cron', 'log_daemon', 'cache_tmp',
  'canary_aws_creds', 'canary_env_file', 'canary_git_config',
  'canary_ssh_key', 'canary_honeydoc', 'canary_honeydoc_docx',
  'canary_honeydoc_pdf', 'canary_mysql_dump',
  'canary_fingerprint_html', 'canary_fingerprint_svg',
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

  const canary = row ? isCanaryClass(row.content_class) : false;

  return (
    <div
      className="drawer-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div ref={panelRef} role="dialog" aria-modal="true" className="drawer">
        <div className="drawer-head">
          <div>
            <div className="drawer-eyebrow">
              SYNTHETIC FILE{row ? ` · ${deckyLabel(row.decky_uuid, deckies)}` : ''}
            </div>
            <div className="drawer-title">{row?.path ?? uuid}</div>
          </div>
          <button onClick={onClose} aria-label="Close" className="drawer-close">
            <X size={18} />
          </button>
        </div>

        {loading && <div className="dim">Loading…</div>}
        {error && <div className="alert-text">{error}</div>}

        {row && (
          <>
            <div className="meta-grid">
              <div className="label">Persona</div>
              <div>{row.persona}</div>

              <div className="label">Content Class</div>
              <div>
                <span className={canary ? 'value-canary' : ''}>
                  {contentClassLabel(row.content_class)}
                </span>
                <span className="mono dim" style={{ marginLeft: 8, fontSize: '0.75rem' }}>
                  {row.content_class}
                </span>
              </div>

              <div className="label">Edit Count</div>
              <div className="mono">{row.edit_count}</div>

              <div className="label">Created</div>
              <div className="mono dim">{fmt(row.created_at)}</div>

              <div className="label">Last Modified</div>
              <div className="mono">{fmt(row.last_modified)}</div>

              <div className="label">Content Hash</div>
              <div className="mono dim" style={{ wordBreak: 'break-all' }}>
                {row.content_hash}
              </div>
            </div>

            <div className="body-head">
              <span>BODY PREVIEW · {(row.last_body?.length ?? 0).toLocaleString()} BYTES</span>
              {row.truncated && (
                <span
                  className="truncated-chip"
                  title="Body is at the 64KB cap; the decky filesystem holds the canonical bytes."
                >
                  TRUNCATED
                </span>
              )}
            </div>
            <pre className="body-pre">
              {row.last_body || <span className="dim">—</span>}
            </pre>
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
  const filtersActive = !!(deckyFilter || personaFilter || classFilter);

  return (
    <div className="fleet-root synthetic-files-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <FileText size={22} className="violet-accent" />
            <h1>SYNTHETIC FILES</h1>
          </div>
          <span className="page-sub">
            {total} TOTAL · PAGE {page + 1} / {totalPages}
            {filtersActive ? ' · FILTERED' : ''}
          </span>
        </div>
        <div className="actions filters">
          <div className="filter-group">
            <label>Decky</label>
            <select
              className="filter-input"
              value={deckyFilter}
              onChange={(e) => { setDeckyFilter(e.target.value); setPage(0); }}
            >
              <option value="">All</option>
              {deckies.map((d) => (
                <option key={d.uuid} value={d.uuid}>{d.name}</option>
              ))}
            </select>
          </div>
          <div className="filter-group">
            <label>Persona</label>
            <select
              className="filter-input"
              value={personaFilter}
              onChange={(e) => { setPersonaFilter(e.target.value); setPage(0); }}
            >
              <option value="">All</option>
              {personaOptions.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>
          <div className="filter-group">
            <label>Content Class</label>
            <select
              className="filter-input"
              value={classFilter}
              onChange={(e) => { setClassFilter(e.target.value); setPage(0); }}
            >
              <option value="">All</option>
              {CONTENT_CLASSES.map((c) => (
                <option key={c} value={c}>{contentClassLabel(c)}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="info-banner">
        <div>
          <strong>Scope:</strong> read-only inventory of files the realism
          worker has grown across the fleet. The orchestrator is the sole
          writer; rows persist in the{' '}
          <span className="mono matrix-text">synthetic_files</span> table.
          Click any row for the body preview and lineage detail.
        </div>
        {error && (
          <div className="info-line alert-text" style={{ marginTop: 8 }}>{error}</div>
        )}
      </div>

      <div className="files-table-wrap">
        <table className="files-table">
          <thead>
            <tr>
              <th>Decky</th>
              <th>Path</th>
              <th>Persona</th>
              <th>Class</th>
              <th>Last Modified</th>
              <th>Edits</th>
              <th>Hash</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr className="empty-row"><td colSpan={7}>Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr className="empty-row"><td colSpan={7}>
                No files match the current filters.
              </td></tr>
            )}
            {!loading && rows.map((r) => {
              const canary = isCanaryClass(r.content_class);
              return (
                <tr key={r.uuid} onClick={() => setSelectedUuid(r.uuid)}>
                  <td>{deckyLabel(r.decky_uuid, deckies)}</td>
                  <td className="path">{r.path}</td>
                  <td>{r.persona}</td>
                  <td className={`cls${canary ? ' canary' : ''}`}>
                    {contentClassLabel(r.content_class)}
                  </td>
                  <td className="dim-time">{fmt(r.last_modified)}</td>
                  <td className="mono">{r.edit_count}</td>
                  <td className="hash">{r.content_hash.slice(0, 12)}…</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="pager">
        <button
          className="btn ghost small"
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          disabled={page === 0}
        >
          ← PREV
        </button>
        <span className="page-counter">PAGE {page + 1} / {totalPages}</span>
        <button
          className="btn ghost small"
          onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
          disabled={page >= totalPages - 1}
        >
          NEXT →
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
