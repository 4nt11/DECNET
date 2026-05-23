// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Lock, Search, ChevronLeft, ChevronRight, Filter, RefreshCw,
} from '../icons';
import CredentialsInspector from './CredentialsInspector';
import CredentialReuseInspector from './CredentialReuseInspector';
import { useFocusSearch } from '../hooks/useFocusSearch';
import CredsTable from './Credentials/CredsTable';
import ReuseTable from './Credentials/ReuseTable';
import { useCredentials } from './Credentials/useCredentials';
import {
  CREDS_LIMIT, REUSE_LIMIT, nextSortState, sortCreds, sortReuse,
} from './Credentials/helpers';
import type {
  CredentialEntry, CredentialReuseRow, SortDir, Tab,
} from './Credentials/types';
import './Dashboard.css';
import './Credentials.css';

const Credentials: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const serviceFilter = searchParams.get('service') || '';
  const tab = (searchParams.get('tab') === 'reuse' ? 'reuse' : 'creds') as Tab;
  const page = parseInt(searchParams.get('page') || '1');

  const [searchInput, setSearchInput] = useState(query);
  const searchRef = useRef<HTMLInputElement | null>(null);
  useFocusSearch(searchRef);

  const [selectedCred, setSelectedCred] = useState<CredentialEntry | null>(null);
  const [selectedReuse, setSelectedReuse] = useState<CredentialReuseRow | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [sortCol, setSortCol] = useState<string>('');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const {
    creds, credsTotal, reuseRows, reuseTotal, reuseMap, loading, fetchReuseDetail,
  } = useCredentials({ tab, page, query, serviceFilter, refreshTick });

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

  // Service chips derived from visible creds page.
  const services = useMemo(() => {
    const set = new Set<string>();
    creds.forEach((c) => set.add(c.service));
    return Array.from(set).sort();
  }, [creds]);

  const plaintextCount = creds.filter((c) => c.secret_kind === 'plaintext').length;
  const hashedCount = creds.length - plaintextCount;

  const handleSortCol = (col: string) => {
    const next = nextSortState({ col: sortCol, dir: sortDir }, col);
    setSortCol(next.col);
    setSortDir(next.dir);
  };

  const sortedCreds = useMemo(
    () => sortCreds(creds, sortCol as Parameters<typeof sortCreds>[1], sortDir),
    [creds, sortCol, sortDir],
  );

  const sortedReuseRows = useMemo(
    () => sortReuse(reuseRows, sortCol as Parameters<typeof sortReuse>[1], sortDir),
    [reuseRows, sortCol, sortDir],
  );

  const openReuseFromCred = async (key: string) => {
    const hit = reuseMap.get(key);
    if (!hit) return;
    const row = await fetchReuseDetail(hit.id);
    if (row) setSelectedReuse(row);
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
            {services.map((svc) => (
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
              <button onClick={() => setRefreshTick((t) => t + 1)} aria-label="Refresh">
                <RefreshCw size={14} />
              </button>
            </div>
          </div>
        </div>

        <div className="logs-table-container">
          {tab === 'creds' ? (
            <CredsTable
              rows={sortedCreds}
              reuseMap={reuseMap}
              loading={loading}
              sortCol={sortCol}
              sortDir={sortDir}
              onSort={handleSortCol}
              onSelectCred={setSelectedCred}
              onSelectAttacker={(ip) => navigate(`/attackers?q=${encodeURIComponent(ip)}`)}
              onOpenReuse={openReuseFromCred}
            />
          ) : (
            <ReuseTable
              rows={sortedReuseRows}
              loading={loading}
              sortCol={sortCol}
              sortDir={sortDir}
              onSort={handleSortCol}
              onSelect={setSelectedReuse}
            />
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
