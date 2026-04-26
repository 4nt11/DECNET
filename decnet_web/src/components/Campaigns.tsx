import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  ChevronLeft, ChevronRight, ChevronRight as ChevR, Filter, Crosshair, Search,
} from '../icons';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import { useFocusSearch } from '../hooks/useFocusSearch';
import { useCampaignStream } from './useCampaignStream';
import './Dashboard.css';

interface CampaignEntry {
  uuid: string;
  schema_version: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  updated_at: string;
  confidence: number | null;
  identity_count: number;
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

const Campaigns: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = (searchParams.get('q') || '').toLowerCase();
  const page = parseInt(searchParams.get('page') || '1');

  const [campaigns, setCampaigns] = useState<CampaignEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(searchParams.get('q') || '');
  const searchRef = useRef<HTMLInputElement | null>(null);
  useFocusSearch(searchRef);

  const limit = 50;

  const fetchCampaigns = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const res = await api.get(`/campaigns?limit=${limit}&offset=${offset}`);
      setCampaigns(res.data.data ?? []);
      setTotal(res.data.total ?? 0);
    } catch (err) {
      console.error('Failed to fetch campaigns', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCampaigns(); }, [page]);

  useCampaignStream({
    enabled: true,
    onEvent: () => { fetchCampaigns(); },
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, page: '1' });
  };
  const setPage = (p: number) => setSearchParams({ q: searchParams.get('q') || '', page: p.toString() });

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const visible = query
    ? campaigns.filter((c) => c.uuid.toLowerCase().includes(query))
    : campaigns;

  const totalIdentities = campaigns.reduce((sum, c) => sum + c.identity_count, 0);

  return (
    <div className="bounty-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Crosshair size={22} className="violet-accent" />
            <h1>CAMPAIGN CLUSTERING</h1>
          </div>
          <span className="page-sub">
            {total.toLocaleString()} CAMPAIGNS · {totalIdentities} IDENTITIES GROUPED
          </span>
        </div>
      </div>

      <form className="controls-row" onSubmit={handleSearch}>
        <div className="search-container">
          <Search size={14} className="search-icon" />
          <input
            ref={searchRef}
            type="text"
            placeholder="Filter by UUID..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>
      </form>

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Filter size={14} />
            <span>{visible.length.toLocaleString()} CAMPAIGNS SHOWN</span>
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
                <th>FINGERPRINTS</th>
                <th>INFRA</th>
                <th>IDENTITIES</th>
                <th>CONFIDENCE</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visible.length > 0 ? visible.map((c) => (
                <tr
                  key={c.uuid}
                  className="clickable"
                  onClick={() => navigate(`/campaigns/${c.uuid}`)}
                >
                  <td className="matrix-text" style={{ fontFamily: 'var(--font-mono)' }}>
                    {c.uuid.slice(0, 12)}…
                  </td>
                  <td className="dim">{timeAgo(c.first_seen_at)}</td>
                  <td className="dim">{timeAgo(c.last_seen_at)}</td>
                  <td>
                    <span className="chip dim-chip">{safeListLen(c.ja3_hashes)} JA3</span>{' '}
                    <span className="chip dim-chip">{safeListLen(c.hassh_hashes)} HASSH</span>
                  </td>
                  <td>
                    <span className="chip dim-chip">{safeListLen(c.payload_simhashes)} PAYLOAD</span>{' '}
                    <span className="chip dim-chip">{safeListLen(c.c2_endpoints)} C2</span>
                  </td>
                  <td className="matrix-text">{c.identity_count}</td>
                  <td className="violet-accent">
                    {c.confidence !== null ? c.confidence.toFixed(2) : '—'}
                  </td>
                  <td style={{ textAlign: 'right', opacity: 0.4 }}>
                    <ChevR size={14} />
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={8}>
                    <EmptyState
                      icon={Crosshair}
                      title={loading ? 'CLUSTERING CAMPAIGNS…' : 'NO CAMPAIGNS YET'}
                      hint={loading ? undefined : 'the campaign clusterer groups identities into operations as they correlate'}
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

export default Campaigns;
