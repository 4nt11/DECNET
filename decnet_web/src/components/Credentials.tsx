import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Lock, Search, ChevronLeft, ChevronRight, Filter, ChevronRight as ChevR,
  Target,
} from '../icons';
import api from '../utils/api';
import CredentialsInspector from './CredentialsInspector';
import type { CredentialEntry } from './CredentialsInspector';
import EmptyState from './EmptyState/EmptyState';
import { useFocusSearch } from '../hooks/useFocusSearch';
import './Dashboard.css';
import './Credentials.css';

const truncHash = (h: string | null | undefined, n = 12): string =>
  h ? `${h.slice(0, n)}…` : '—';

const Credentials: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const serviceFilter = searchParams.get('service') || '';
  const page = parseInt(searchParams.get('page') || '1');

  const [creds, setCreds] = useState<CredentialEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(query);
  const searchRef = useRef<HTMLInputElement | null>(null);
  useFocusSearch(searchRef);
  const [selected, setSelected] = useState<CredentialEntry | null>(null);

  const limit = 50;

  const fetchCreds = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      let url = `/credentials?limit=${limit}&offset=${offset}`;
      if (query) url += `&search=${encodeURIComponent(query)}`;
      if (serviceFilter) url += `&service=${encodeURIComponent(serviceFilter)}`;
      const res = await api.get(url);
      setCreds(res.data.data);
      setTotal(res.data.total);
    } catch (err) {
      console.error('Failed to fetch credentials', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCreds(); }, [query, serviceFilter, page]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, service: serviceFilter, page: '1' });
  };
  const setPage = (p: number) =>
    setSearchParams({ q: query, service: serviceFilter, page: p.toString() });
  const setService = (s: string) =>
    setSearchParams({ q: query, service: s, page: '1' });

  const totalPages = Math.max(1, Math.ceil(total / limit));

  // Derive service chips dynamically from the visible page so the segment
  // group reflects whatever services are actually capturing creds.
  const services = useMemo(() => {
    const set = new Set<string>();
    creds.forEach(c => set.add(c.service));
    return Array.from(set).sort();
  }, [creds]);

  const plaintextCount = creds.filter(c => c.secret_kind === 'plaintext').length;
  const hashedCount = creds.length - plaintextCount;

  return (
    <div className="credentials-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Lock size={22} className="violet-accent" />
            <h1>CREDENTIAL VAULT</h1>
          </div>
          <span className="page-sub">
            {total.toLocaleString()} CAPTURED · {plaintextCount} PLAINTEXT · {hashedCount} CHALLENGED
          </span>
        </div>
      </div>

      <form className="controls-row" onSubmit={handleSearch}>
        <div className="search-container">
          <Search size={14} className="search-icon" />
          <input
            ref={searchRef}
            type="text"
            placeholder="Filter by IP, decky, principal, secret..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>
        <div className="seg-group" role="tablist">
          <button
            type="button"
            className={serviceFilter === '' ? 'active' : ''}
            onClick={() => setService('')}
          >
            ALL
          </button>
          {services.map(svc => (
            <button
              key={svc}
              type="button"
              className={serviceFilter === svc ? 'active' : ''}
              onClick={() => setService(svc)}
            >
              {svc.toUpperCase()}
            </button>
          ))}
        </div>
      </form>

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Filter size={14} />
            <span>{total.toLocaleString()} CREDENTIALS CAPTURED</span>
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
                <th>LAST SEEN</th>
                <th>DECKY</th>
                <th>SVC</th>
                <th>ATTACKER</th>
                <th>PRINCIPAL</th>
                <th>SECRET</th>
                <th>KIND</th>
                <th>HITS</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {creds.length > 0 ? creds.map(c => {
                const isPlain = c.secret_kind === 'plaintext';
                const secretText = isPlain
                  ? (c.secret_printable ?? '—')
                  : truncHash(c.secret_sha256, 16);
                return (
                  <tr key={c.id} className="clickable" onClick={() => setSelected(c)}>
                    <td className="dim" style={{ fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
                      {new Date(c.last_seen).toLocaleTimeString()}
                    </td>
                    <td className="violet-accent">{c.decky_name}</td>
                    <td><span className="chip dim-chip">{c.service}</span></td>
                    <td>
                      <span
                        className="matrix-text attacker-link"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/attackers?q=${encodeURIComponent(c.attacker_ip)}`);
                        }}
                      >
                        {c.attacker_ip}
                      </span>
                    </td>
                    <td className="principal-cell">
                      {c.principal ?? <span className="dim">—</span>}
                    </td>
                    <td>
                      <span className={`secret-cell${isPlain ? '' : ' hashed'}`} title={secretText}>
                        {secretText}
                      </span>
                    </td>
                    <td>
                      <span className={`chip ${isPlain ? 'matrix' : 'violet'}`}>
                        {c.secret_kind.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span className="attempt-pill">{c.attempt_count}</span>
                    </td>
                    <td style={{ textAlign: 'right', opacity: 0.4 }}>
                      <ChevR size={14} />
                    </td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan={9}>
                    <EmptyState
                      icon={Target}
                      title={loading ? 'RETRIEVING CREDENTIALS…' : 'NO CREDENTIALS YET'}
                      hint={loading ? undefined : 'captured auth attempts will land here'}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <CredentialsInspector
          cred={selected}
          onClose={() => setSelected(null)}
          onSelectAttacker={(ip) => {
            setSelected(null);
            navigate(`/attackers?q=${encodeURIComponent(ip)}`);
          }}
        />
      )}
    </div>
  );
};

export default Credentials;
