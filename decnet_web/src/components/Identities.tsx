import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  ChevronLeft, ChevronRight, ChevronRight as ChevR, Filter, Fingerprint, Search,
} from '../icons';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import { useFocusSearch } from '../hooks/useFocusSearch';
import { useIdentityStream } from './useIdentityStream';
import './Dashboard.css';

interface IdentityEntry {
  uuid: string;
  schema_version: number;
  campaign_id: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  updated_at: string;
  confidence: number | null;
  observation_count: number;
  ja3_hashes: string | null;
  hassh_hashes: string | null;
  payload_simhashes: string | null;
  c2_endpoints: string | null;
  merged_into_uuid: string | null;
}

const safeListLen = (raw: string | null): number => {
  if (!raw) return 0;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.length : 0;
  } catch {
    return 0;
  }
};

const timeAgo = (dateStr: string | null): string => {
  if (!dateStr) return '—';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

const Identities: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = (searchParams.get('q') || '').toLowerCase();
  const page = parseInt(searchParams.get('page') || '1');

  const [identities, setIdentities] = useState<IdentityEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(searchParams.get('q') || '');
  const searchRef = useRef<HTMLInputElement | null>(null);
  useFocusSearch(searchRef);

  const limit = 50;

  const fetchIdentities = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const res = await api.get(`/identities?limit=${limit}&offset=${offset}`);
      setIdentities(res.data.data ?? []);
      setTotal(res.data.total ?? 0);
    } catch (err) {
      console.error('Failed to fetch identities', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchIdentities(); }, [page]);

  // Live updates: refetch on any clusterer event so the list stays
  // current without polling.
  useIdentityStream({
    enabled: true,
    onEvent: () => { fetchIdentities(); },
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, page: '1' });
  };
  const setPage = (p: number) => setSearchParams({ q: searchParams.get('q') || '', page: p.toString() });

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const visible = query
    ? identities.filter((i) =>
        i.uuid.toLowerCase().includes(query)
        || (i.campaign_id || '').toLowerCase().includes(query),
      )
    : identities;

  const assignedCount = identities.filter((i) => i.campaign_id).length;

  return (
    <div className="bounty-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Fingerprint size={22} className="violet-accent" />
            <h1>IDENTITY RESOLUTION</h1>
          </div>
          <span className="page-sub">
            {total.toLocaleString()} IDENTITIES · {assignedCount} CAMPAIGN-ASSIGNED
          </span>
        </div>
      </div>

      <form className="controls-row" onSubmit={handleSearch}>
        <div className="search-container">
          <Search size={14} className="search-icon" />
          <input
            ref={searchRef}
            type="text"
            placeholder="Filter by UUID or campaign..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>
      </form>

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Filter size={14} />
            <span>{visible.length.toLocaleString()} IDENTITIES SHOWN</span>
          </div>
          <div className="section-actions">
            <div className="pager">
              <span className="dim">Page {page} of {totalPages}</span>
              <button disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label="Previous page">
                <ChevronLeft size={14} />
              </button>
              <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} aria-label="Next page">
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </div>

        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>UUID</th>
                <th>FIRST SEEN</th>
                <th>LAST SEEN</th>
                <th>JA3 / HASSH</th>
                <th>PAYLOADS / C2</th>
                <th>OBS</th>
                <th>CAMPAIGN</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visible.length > 0 ? visible.map((i) => (
                <tr
                  key={i.uuid}
                  className="clickable"
                  onClick={() => navigate(`/identities/${i.uuid}`)}
                >
                  <td className="matrix-text" style={{ fontFamily: 'var(--font-mono)' }}>
                    {i.uuid.slice(0, 12)}…
                  </td>
                  <td className="dim">{timeAgo(i.first_seen_at)}</td>
                  <td className="dim">{timeAgo(i.last_seen_at)}</td>
                  <td>
                    <span className="chip dim-chip">{safeListLen(i.ja3_hashes)} JA3</span>{' '}
                    <span className="chip dim-chip">{safeListLen(i.hassh_hashes)} HASSH</span>
                  </td>
                  <td>
                    <span className="chip dim-chip">{safeListLen(i.payload_simhashes)} PAYLOAD</span>{' '}
                    <span className="chip dim-chip">{safeListLen(i.c2_endpoints)} C2</span>
                  </td>
                  <td className="matrix-text">{i.observation_count}</td>
                  <td>
                    {i.campaign_id ? (
                      <span
                        className="chip violet"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/campaigns/${i.campaign_id}`);
                        }}
                      >
                        {i.campaign_id.slice(0, 8)}…
                      </span>
                    ) : (
                      <span className="dim">—</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right', opacity: 0.4 }}>
                    <ChevR size={14} />
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={8}>
                    <EmptyState
                      icon={Fingerprint}
                      title={loading ? 'RESOLVING IDENTITIES…' : 'NO IDENTITIES YET'}
                      hint={loading ? undefined : 'the clusterer populates this view as observations correlate'}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Identities;
