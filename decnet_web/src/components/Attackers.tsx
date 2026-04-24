import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Search, ChevronLeft, ChevronRight, Users } from 'lucide-react';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import { useFocusSearch } from '../hooks/useFocusSearch';
import './Dashboard.css';
import './Attackers.css';

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
  country_code: string | null;
  country_source: string | null;
  updated_at: string;
}

// Activity thresholds — tune here to adjust tier resolution.
const ACTIVE_MIN_EVENTS = 50;
const ACTIVE_MAX_AGE_MIN = 60;
const PASSIVE_MIN_EVENTS = 5;
const PASSIVE_MAX_AGE_HR = 24;

type ActivityTier = 'active' | 'passive' | 'inactive';

function deriveActivity(a: AttackerEntry): ActivityTier {
  const ageMin = (Date.now() - new Date(a.last_seen).getTime()) / 60000;
  if (a.event_count >= ACTIVE_MIN_EVENTS && ageMin <= ACTIVE_MAX_AGE_MIN) return 'active';
  if (a.event_count >= PASSIVE_MIN_EVENTS && ageMin <= PASSIVE_MAX_AGE_HR * 60) return 'passive';
  return 'inactive';
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
  const serviceFilter = searchParams.get('service') || '';
  const page = parseInt(searchParams.get('page') || '1');

  const [attackers, setAttackers] = useState<AttackerEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(query);
  const searchRef = useRef<HTMLInputElement | null>(null);
  useFocusSearch(searchRef);

  const limit = 50;

  const fetchAttackers = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      let url = `/attackers?limit=${limit}&offset=${offset}&sort_by=${sortBy}`;
      if (query) url += `&search=${encodeURIComponent(query)}`;
      if (serviceFilter) url += `&service=${encodeURIComponent(serviceFilter)}`;
      const res = await api.get(url);
      setAttackers(res.data.data);
      setTotal(res.data.total);
    } catch (err) {
      console.error('Failed to fetch attackers', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAttackers(); }, [query, sortBy, serviceFilter, page]);

  useEffect(() => { setSearchInput(query); }, [query]);

  const _params = (overrides: Record<string, string> = {}) => {
    const base: Record<string, string> = { q: query, sort_by: sortBy, service: serviceFilter, page: '1' };
    return Object.fromEntries(Object.entries({ ...base, ...overrides }).filter(([, v]) => v !== ''));
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams(_params({ q: searchInput }));
  };
  const setPage = (p: number) => setSearchParams(_params({ page: p.toString() }));
  const setSort = (s: string) => setSearchParams(_params({ sort_by: s }));
  const clearService = () => setSearchParams(_params({ service: '' }));

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const activityCounts = attackers.reduce(
    (acc, a) => { acc[deriveActivity(a)]++; return acc; },
    { active: 0, passive: 0, inactive: 0 } as Record<ActivityTier, number>,
  );

  return (
    <div className="attackers-root">
      <div className="page-header">
        <div className="page-title-group">
          <h1>ATTACKERS</h1>
          <span className="page-sub">
            {total.toLocaleString()} UNIQUE SOURCES · {activityCounts.active} ACTIVE · {activityCounts.passive} PASSIVE · {activityCounts.inactive} INACTIVE
          </span>
        </div>
      </div>

      <form className="controls-row" onSubmit={handleSearch}>
        <div className="search-container">
          <Search size={14} className="search-icon" />
          <input
            ref={searchRef}
            type="text"
            placeholder="Search by IP..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>
        <select className="sort-select" value={sortBy} onChange={(e) => setSort(e.target.value)}>
          <option value="recent">RECENT</option>
          <option value="active">MOST ACTIVE</option>
          <option value="traversals">TRAVERSALS</option>
        </select>
      </form>

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <span>SOURCE INTEL</span>
            {serviceFilter && (
              <button
                type="button"
                className="service-filter-chip"
                onClick={clearService}
                style={{ marginLeft: 12 }}
              >
                {serviceFilter.toUpperCase()} ×
              </button>
            )}
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

        {loading ? (
          <EmptyState icon={Users} title="SCANNING THREAT PROFILES…" />
        ) : attackers.length === 0 ? (
          <EmptyState
            icon={Users}
            title="NO ACTIVE THREATS PROFILED YET"
            hint="waiting on attacker traffic to correlate"
          />
        ) : (
          <div className="ak-grid">
            {attackers.map(a => {
              const activity = deriveActivity(a);
              const lastCmd = a.commands.length > 0 ? a.commands[a.commands.length - 1] : null;
              return (
                <div
                  key={a.uuid}
                  className="ak-card"
                  onClick={() => navigate(`/attackers/${a.uuid}`)}
                >
                  <div className="ak-top">
                    <span className="ak-ip">
                      {a.ip}
                      {a.country_code && (
                        <span
                          className="ak-cc"
                          title={`Origin: ${a.country_code}${a.country_source ? ` (${a.country_source})` : ''}`}
                        >
                          {a.country_code}
                        </span>
                      )}
                    </span>
                    <span className={`activity-chip ${activity}`}>
                      <span className="dot" />
                      {activity.toUpperCase()}
                    </span>
                  </div>

                  <div className="ak-meta">
                    <span>First: {new Date(a.first_seen).toLocaleDateString()}</span>
                    <span>Last: {timeAgo(a.last_seen)}</span>
                    {a.is_traversal && <span className="chip violet" style={{ fontSize: '0.6rem' }}>TRAVERSAL</span>}
                  </div>

                  <div className="ak-stats">
                    <span><span className="lbl">EVENTS</span><span className="n matrix">{a.event_count}</span></span>
                    <span><span className="lbl">BOUNTIES</span><span className="n violet">{a.bounty_count}</span></span>
                    <span><span className="lbl">CREDS</span><span className="n violet">{a.credential_count}</span></span>
                  </div>

                  {a.services.length > 0 && (
                    <div className="ak-chips">
                      {a.services.map(svc => (
                        <span
                          key={svc}
                          className="chip dim-chip"
                          style={{ cursor: 'pointer' }}
                          onClick={(e) => { e.stopPropagation(); setSearchParams(_params({ service: svc })); }}
                        >
                          {svc.toUpperCase()}
                        </span>
                      ))}
                    </div>
                  )}

                  {a.traversal_path ? (
                    <div className="ak-path"><span className="lbl">PATH</span>{a.traversal_path}</div>
                  ) : a.deckies.length > 0 ? (
                    <div className="ak-path"><span className="lbl">DECKIES</span>{a.deckies.join(', ')}</div>
                  ) : null}

                  <div className="ak-stats">
                    <span><span className="lbl">CMDS</span><span className="n matrix">{a.commands.length}</span></span>
                    <span><span className="lbl">FPS</span><span className="n matrix">{a.fingerprints.length}</span></span>
                  </div>

                  {lastCmd && (
                    <div className="ak-lastcmd">
                      <span className="lbl" style={{ opacity: 0.5, marginRight: 6, fontSize: '0.62rem', letterSpacing: 1 }}>LAST</span>
                      <span className="cmd">{lastCmd.command}</span>
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
