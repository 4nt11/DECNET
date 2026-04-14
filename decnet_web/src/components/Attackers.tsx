import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Crosshair, Search, ChevronLeft, ChevronRight, Filter } from 'lucide-react';
import api from '../utils/api';
import './Dashboard.css';

interface AttackerEntry {
  uuid: string;
  ip: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  service_count: number;
  decky_count: number;
  services: string[];
  deckies: string[];
  traversal_path: string | null;
  is_traversal: boolean;
  bounty_count: number;
  credential_count: number;
  fingerprints: any[];
  commands: any[];
  updated_at: string;
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

const Attackers: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const sortBy = searchParams.get('sort_by') || 'recent';
  const page = parseInt(searchParams.get('page') || '1');

  const [attackers, setAttackers] = useState<AttackerEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(query);

  const limit = 50;

  const fetchAttackers = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      let url = `/attackers?limit=${limit}&offset=${offset}&sort_by=${sortBy}`;
      if (query) url += `&search=${encodeURIComponent(query)}`;

      const res = await api.get(url);
      setAttackers(res.data.data);
      setTotal(res.data.total);
    } catch (err) {
      console.error('Failed to fetch attackers', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAttackers();
  }, [query, sortBy, page]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, sort_by: sortBy, page: '1' });
  };

  const setPage = (p: number) => {
    setSearchParams({ q: query, sort_by: sortBy, page: p.toString() });
  };

  const setSort = (s: string) => {
    setSearchParams({ q: query, sort_by: s, page: '1' });
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="dashboard">
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <Crosshair size={32} className="violet-accent" />
          <h1 style={{ fontSize: '1.5rem', letterSpacing: '4px' }}>ATTACKER PROFILES</h1>
        </div>

        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', border: '1px solid var(--border-color)', padding: '4px 12px' }}>
            <Filter size={16} className="dim" />
            <select
              value={sortBy}
              onChange={(e) => setSort(e.target.value)}
              style={{ background: 'transparent', border: 'none', color: 'inherit', fontSize: '0.8rem', outline: 'none' }}
            >
              <option value="recent">RECENT</option>
              <option value="active">MOST ACTIVE</option>
              <option value="traversals">TRAVERSALS</option>
            </select>
          </div>

          <form onSubmit={handleSearch} style={{ display: 'flex', alignItems: 'center', border: '1px solid var(--border-color)', padding: '4px 12px' }}>
            <Search size={18} style={{ opacity: 0.5, marginRight: '8px' }} />
            <input
              type="text"
              placeholder="Search by IP..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              style={{ background: 'transparent', border: 'none', padding: '4px', fontSize: '0.8rem', width: '200px' }}
            />
          </form>
        </div>
      </div>

      {/* Summary & Pagination */}
      <div className="logs-section">
        <div className="section-header" style={{ justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="matrix-text" style={{ fontSize: '0.8rem' }}>{total} THREATS PROFILED</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <span className="dim" style={{ fontSize: '0.8rem' }}>
              Page {page} of {totalPages || 1}
            </span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                style={{ padding: '4px', border: '1px solid var(--border-color)', opacity: page <= 1 ? 0.3 : 1 }}
              >
                <ChevronLeft size={16} />
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
                style={{ padding: '4px', border: '1px solid var(--border-color)', opacity: page >= totalPages ? 0.3 : 1 }}
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>

        {/* Card Grid */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '60px', opacity: 0.5, letterSpacing: '4px' }}>
            SCANNING THREAT PROFILES...
          </div>
        ) : attackers.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px', opacity: 0.5, letterSpacing: '4px' }}>
            NO ACTIVE THREATS PROFILED YET
          </div>
        ) : (
          <div className="attacker-grid">
            {attackers.map((a) => {
              const lastCmd = a.commands.length > 0
                ? a.commands[a.commands.length - 1]
                : null;

              return (
                <div
                  key={a.uuid}
                  className="attacker-card"
                  onClick={() => navigate(`/attackers/${a.uuid}`)}
                >
                  {/* Header row */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <span className="matrix-text" style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>{a.ip}</span>
                    {a.is_traversal && (
                      <span className="traversal-badge">TRAVERSAL</span>
                    )}
                  </div>

                  {/* Timestamps */}
                  <div style={{ display: 'flex', gap: '16px', marginBottom: '8px', fontSize: '0.75rem' }}>
                    <span className="dim">First: {new Date(a.first_seen).toLocaleDateString()}</span>
                    <span className="dim">Last: {timeAgo(a.last_seen)}</span>
                  </div>

                  {/* Counts */}
                  <div style={{ display: 'flex', gap: '16px', marginBottom: '10px', fontSize: '0.8rem' }}>
                    <span>Events: <span className="matrix-text">{a.event_count}</span></span>
                    <span>Bounties: <span className="violet-accent">{a.bounty_count}</span></span>
                    <span>Creds: <span className="violet-accent">{a.credential_count}</span></span>
                  </div>

                  {/* Services */}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '8px' }}>
                    {a.services.map((svc) => (
                      <span key={svc} className="service-badge">{svc.toUpperCase()}</span>
                    ))}
                  </div>

                  {/* Deckies / Traversal Path */}
                  {a.traversal_path ? (
                    <div style={{ fontSize: '0.75rem', marginBottom: '8px', opacity: 0.7 }}>
                      Path: {a.traversal_path}
                    </div>
                  ) : a.deckies.length > 0 ? (
                    <div style={{ fontSize: '0.75rem', marginBottom: '8px', opacity: 0.7 }}>
                      Deckies: {a.deckies.join(', ')}
                    </div>
                  ) : null}

                  {/* Commands & Fingerprints */}
                  <div style={{ display: 'flex', gap: '16px', fontSize: '0.75rem', marginBottom: '6px' }}>
                    <span>Cmds: <span className="matrix-text">{a.commands.length}</span></span>
                    <span>Fingerprints: <span className="matrix-text">{a.fingerprints.length}</span></span>
                  </div>

                  {/* Last command preview */}
                  {lastCmd && (
                    <div style={{ fontSize: '0.7rem', opacity: 0.6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      Last cmd: <span className="matrix-text">{lastCmd.command}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default Attackers;
