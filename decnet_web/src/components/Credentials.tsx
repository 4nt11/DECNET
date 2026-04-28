import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Lock, Search, ChevronLeft, ChevronRight, Filter, ChevronRight as ChevR,
  Target, RefreshCw,
} from '../icons';
import api from '../utils/api';
import CredentialsInspector from './CredentialsInspector';
import type { CredentialEntry } from './CredentialsInspector';
import CredentialReuseInspector from './CredentialReuseInspector';
import type { CredentialReuseRow } from './CredentialReuseInspector';
import EmptyState from './EmptyState/EmptyState';
import { useFocusSearch } from '../hooks/useFocusSearch';
import './Dashboard.css';
import './Credentials.css';

const truncHash = (h: string | null | undefined, n = 12): string =>
  h ? `${h.slice(0, n)}…` : '—';

const CREDS_LIMIT = 50;
const REUSE_LIMIT = 25;
const REUSE_MAP_CAP = 500;

type Tab = 'creds' | 'reuse';

const reuseKey = (sha: string, kind: string, principal: string | null): string =>
  `${sha}|${kind}|${principal ?? ''}`;

const Credentials: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const serviceFilter = searchParams.get('service') || '';
  const tab = (searchParams.get('tab') === 'reuse' ? 'reuse' : 'creds') as Tab;
  const page = parseInt(searchParams.get('page') || '1');

  const [creds, setCreds] = useState<CredentialEntry[]>([]);
  const [credsTotal, setCredsTotal] = useState(0);
  const [reuseRows, setReuseRows] = useState<CredentialReuseRow[]>([]);
  const [reuseTotal, setReuseTotal] = useState(0);
  const [reuseMap, setReuseMap] = useState<Map<string, { id: string; target_count: number }>>(new Map());
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(query);
  const searchRef = useRef<HTMLInputElement | null>(null);
  useFocusSearch(searchRef);
  const [selectedCred, setSelectedCred] = useState<CredentialEntry | null>(null);
  const [selectedReuse, setSelectedReuse] = useState<CredentialReuseRow | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);

  // ── Fetch credentials (CREDS tab + always for badge totals)
  useEffect(() => {
    if (tab !== 'creds') return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const offset = (page - 1) * CREDS_LIMIT;
        let url = `/credentials?limit=${CREDS_LIMIT}&offset=${offset}`;
        if (query) url += `&search=${encodeURIComponent(query)}`;
        if (serviceFilter) url += `&service=${encodeURIComponent(serviceFilter)}`;
        const res = await api.get(url);
        if (cancelled) return;
        setCreds(res.data.data);
        setCredsTotal(res.data.total);
      } catch (err) {
        console.error('Failed to fetch credentials', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [tab, query, serviceFilter, page, refreshTick]);

  // ── Fetch reuse rows (REUSE tab)
  useEffect(() => {
    if (tab !== 'reuse') return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const offset = (page - 1) * REUSE_LIMIT;
        const res = await api.get(`/credential-reuse?limit=${REUSE_LIMIT}&offset=${offset}`);
        if (cancelled) return;
        setReuseRows(res.data.data);
        setReuseTotal(res.data.total);
      } catch (err) {
        console.error('Failed to fetch credential-reuse', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [tab, page, refreshTick]);

  // ── Build reuse-map for the badge column on the CREDS tab
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.get(`/credential-reuse?limit=${REUSE_MAP_CAP}&offset=0`);
        if (cancelled) return;
        const m = new Map<string, { id: string; target_count: number }>();
        (res.data.data as CredentialReuseRow[]).forEach(r => {
          m.set(reuseKey(r.secret_sha256, r.secret_kind, r.principal), {
            id: r.id,
            target_count: r.target_count,
          });
        });
        setReuseMap(m);
      } catch {
        /* badge column degrades silently to "—" */
      }
    })();
    return () => { cancelled = true; };
  }, [refreshTick]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, service: serviceFilter, tab, page: '1' });
  };
  const setPage = (p: number) =>
    setSearchParams({ q: query, service: serviceFilter, tab, page: p.toString() });
  const setService = (s: string) =>
    setSearchParams({ q: query, service: s, tab, page: '1' });
  const setTab = (t: Tab) =>
    setSearchParams({ q: query, service: serviceFilter, tab: t, page: '1' });

  const limit = tab === 'creds' ? CREDS_LIMIT : REUSE_LIMIT;
  const total = tab === 'creds' ? credsTotal : reuseTotal;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  // Service chips derived from visible creds page
  const services = useMemo(() => {
    const set = new Set<string>();
    creds.forEach(c => set.add(c.service));
    return Array.from(set).sort();
  }, [creds]);

  const plaintextCount = creds.filter(c => c.secret_kind === 'plaintext').length;
  const hashedCount = creds.length - plaintextCount;

  const openReuseFromCred = async (key: string) => {
    const hit = reuseMap.get(key);
    if (!hit) return;
    try {
      const res = await api.get(`/credential-reuse/${hit.id}`);
      setSelectedReuse(res.data as CredentialReuseRow);
    } catch (err) {
      console.error('Failed to fetch reuse detail', err);
    }
  };

  return (
    <div className="credentials-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Lock size={22} className="violet-accent" />
            <h1>CREDENTIAL VAULT</h1>
          </div>
          <span className="page-sub">
            {tab === 'creds'
              ? `${credsTotal.toLocaleString()} CAPTURED · ${plaintextCount} PLAINTEXT · ${hashedCount} CHALLENGED`
              : `${reuseTotal.toLocaleString()} REUSE FINDINGS`}
          </span>
        </div>
      </div>

      <div className="seg-group" role="tablist" style={{ marginBottom: 12 }}>
        <button
          type="button"
          className={tab === 'creds' ? 'active' : ''}
          onClick={() => setTab('creds')}
        >
          CREDS
        </button>
        <button
          type="button"
          className={tab === 'reuse' ? 'active' : ''}
          onClick={() => setTab('reuse')}
        >
          REUSE
        </button>
      </div>

      {tab === 'creds' && (
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
      )}

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Filter size={14} />
            <span>
              {tab === 'creds'
                ? `${credsTotal.toLocaleString()} CREDENTIALS CAPTURED`
                : `${reuseTotal.toLocaleString()} REUSE FINDINGS`}
            </span>
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
              <button onClick={() => setRefreshTick(t => t + 1)} aria-label="Refresh">
                <RefreshCw size={14} />
              </button>
            </div>
          </div>
        </div>

        <div className="logs-table-container">
          {tab === 'creds' ? (
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
                  <th>REUSE</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {creds.length > 0 ? creds.map(c => {
                  const isPlain = c.secret_kind === 'plaintext';
                  const secretText = isPlain
                    ? (c.secret_printable ?? '—')
                    : truncHash(c.secret_sha256, 16);
                  const key = reuseKey(c.secret_sha256, c.secret_kind, c.principal);
                  const reuseHit = reuseMap.get(key);
                  return (
                    <tr key={c.id} className="clickable" onClick={() => setSelectedCred(c)}>
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
                      <td>
                        {reuseHit ? (
                          <span
                            className="attempt-pill"
                            style={{ cursor: 'pointer', color: 'var(--violet)' }}
                            title="Open reuse finding"
                            onClick={(e) => {
                              e.stopPropagation();
                              openReuseFromCred(key);
                            }}
                          >
                            ×{reuseHit.target_count}
                          </span>
                        ) : (
                          <span className="dim">—</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right', opacity: 0.4 }}>
                        <ChevR size={14} />
                      </td>
                    </tr>
                  );
                }) : (
                  <tr>
                    <td colSpan={10}>
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
          ) : (
            <table className="logs-table">
              <thead>
                <tr>
                  <th>LAST SEEN</th>
                  <th>PRINCIPAL</th>
                  <th>KIND</th>
                  <th>TARGETS</th>
                  <th>ATTEMPTS</th>
                  <th>DECKIES</th>
                  <th>SERVICES</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {reuseRows.length > 0 ? reuseRows.map(r => {
                  const isPlain = r.secret_kind === 'plaintext';
                  const moreDeckies = Math.max(0, r.deckies.length - 3);
                  const moreServices = Math.max(0, r.services.length - 3);
                  return (
                    <tr key={r.id} className="clickable" onClick={() => setSelectedReuse(r)}>
                      <td className="dim" style={{ fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
                        {new Date(r.last_seen).toLocaleTimeString()}
                      </td>
                      <td className="principal-cell">
                        {r.principal ?? <span className="dim">—</span>}
                      </td>
                      <td>
                        <span className={`chip ${isPlain ? 'matrix' : 'violet'}`}>
                          {r.secret_kind.toUpperCase()}
                        </span>
                      </td>
                      <td><span className="attempt-pill">{r.target_count}</span></td>
                      <td><span className="attempt-pill">{r.attempt_count}</span></td>
                      <td>
                        {r.deckies.slice(0, 3).map(d => (
                          <span key={d} className="chip dim-chip" style={{ marginRight: 4 }}>{d}</span>
                        ))}
                        {moreDeckies > 0 && <span className="dim">+{moreDeckies}</span>}
                      </td>
                      <td>
                        {r.services.slice(0, 3).map(s => (
                          <span key={s} className="chip dim-chip" style={{ marginRight: 4 }}>{s}</span>
                        ))}
                        {moreServices > 0 && <span className="dim">+{moreServices}</span>}
                      </td>
                      <td style={{ textAlign: 'right', opacity: 0.4 }}>
                        <ChevR size={14} />
                      </td>
                    </tr>
                  );
                }) : (
                  <tr>
                    <td colSpan={8}>
                      <EmptyState
                        icon={Target}
                        title={loading ? 'RETRIEVING REUSE…' : 'NO REUSE FINDINGS YET'}
                        hint={loading ? undefined : 'a credential captured on ≥2 deckies will land here'}
                      />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {selectedCred && (
        <CredentialsInspector
          cred={selectedCred}
          onClose={() => setSelectedCred(null)}
          onSelectAttacker={(ip) => {
            setSelectedCred(null);
            navigate(`/attackers?q=${encodeURIComponent(ip)}`);
          }}
        />
      )}

      {selectedReuse && (
        <CredentialReuseInspector
          row={selectedReuse}
          onClose={() => setSelectedReuse(null)}
        />
      )}
    </div>
  );
};

export default Credentials;
