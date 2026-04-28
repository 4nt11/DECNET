import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Archive, Search, ChevronLeft, ChevronRight, Filter, Key, Package, ChevronRight as ChevR,
  Target,
} from '../icons';
import api from '../utils/api';
import BountyInspector from './BountyInspector';
import EmptyState from './EmptyState/EmptyState';
import { useFocusSearch } from '../hooks/useFocusSearch';
import './Dashboard.css';
import './Bounty.css';

interface BountyEntry {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  attacker_ip: string;
  bounty_type: string;
  payload: any;
}

const FINGERPRINT_LABELS: Record<string, string> = {
  fingerprint_type: 'TYPE', ja3: 'JA3', ja3s: 'JA3S', ja4: 'JA4', ja4s: 'JA4S', ja4l: 'JA4L',
  sni: 'SNI', alpn: 'ALPN', dst_port: 'PORT', mechanisms: 'MECHANISM', raw_ciphers: 'CIPHERS',
  hash: 'HASH', target_ip: 'TARGET', target_port: 'PORT', ssh_banner: 'BANNER',
  kex_algorithms: 'KEX', encryption_s2c: 'ENC (S→C)', mac_s2c: 'MAC (S→C)',
  compression_s2c: 'COMP (S→C)', raw: 'RAW', ttl: 'TTL', window_size: 'WINDOW', df_bit: 'DF',
  mss: 'MSS', window_scale: 'WSCALE', sack_ok: 'SACK', timestamp: 'TS', options_order: 'OPTS ORDER',
};

const FingerprintPreview: React.FC<{ payload: any }> = ({ payload }) => {
  if (!payload || typeof payload !== 'object') {
    return <span className="data-preview">{JSON.stringify(payload)}</span>;
  }
  const keys = Object.keys(payload);
  const priority = ['fingerprint_type', 'ja3', 'ja4', 'hash', 'sni', 'target_ip', 'ssh_banner'];
  const show = priority.filter(k => payload[k] !== undefined && payload[k] !== null).slice(0, 2);
  if (!show.length) {
    return <span className="data-preview">{keys.slice(0, 3).join(', ')}</span>;
  }
  return (
    <span className="data-preview">
      {show.map(k => `${FINGERPRINT_LABELS[k] || k.toUpperCase()}: ${payload[k]}`).join(' · ')}
    </span>
  );
};

const Bounty: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const typeFilter = searchParams.get('type') || '';
  const page = parseInt(searchParams.get('page') || '1');

  const [bounties, setBounties] = useState<BountyEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(query);
  const searchRef = useRef<HTMLInputElement | null>(null);
  useFocusSearch(searchRef);
  const [selected, setSelected] = useState<BountyEntry | null>(null);

  const limit = 50;

  const fetchBounties = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      let url = `/bounty?limit=${limit}&offset=${offset}`;
      if (query) url += `&search=${encodeURIComponent(query)}`;
      if (typeFilter) url += `&bounty_type=${typeFilter}`;
      const res = await api.get(url);
      setBounties(res.data.data);
      setTotal(res.data.total);
    } catch (err) {
      console.error('Failed to fetch bounties', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchBounties(); }, [query, typeFilter, page]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, type: typeFilter, page: '1' });
  };
  const setPage = (p: number) => setSearchParams({ q: query, type: typeFilter, page: p.toString() });
  const setType = (t: string) => setSearchParams({ q: query, type: t, page: '1' });

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const credCount = bounties.filter(b => b.bounty_type === 'credential').length;
  const payCount = bounties.filter(b => b.bounty_type === 'payload').length;
  const fpCount = bounties.filter(b => b.bounty_type === 'fingerprint').length;

  const SEGMENTS: [string, string][] = [
    ['', 'ALL'],
    ['credential', 'CREDENTIALS'],
    ['payload', 'PAYLOADS'],
    ['fingerprint', 'FINGERPRINTS'],
  ];

  return (
    <div className="bounty-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Archive size={22} className="violet-accent" />
            <h1>BOUNTY VAULT</h1>
          </div>
          <span className="page-sub">
            {total.toLocaleString()} ARTIFACTS · {credCount} CREDENTIALS · {payCount} PAYLOADS · {fpCount} FINGERPRINTS
          </span>
        </div>
      </div>

      <form className="controls-row" onSubmit={handleSearch}>
        <div className="search-container">
          <Search size={14} className="search-icon" />
          <input
            ref={searchRef}
            type="text"
            placeholder="Filter by IP, decky, payload..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>
        <div className="seg-group" role="tablist">
          {SEGMENTS.map(([v, l]) => (
            <button
              key={v || 'all'}
              type="button"
              className={typeFilter === v ? 'active' : ''}
              onClick={() => setType(v)}
            >
              {l}
            </button>
          ))}
        </div>
      </form>

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Filter size={14} />
            <span>{total.toLocaleString()} ARTIFACTS CAPTURED</span>
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
                <th>TIME</th>
                <th>DECKY</th>
                <th>SVC</th>
                <th>ATTACKER</th>
                <th>TYPE</th>
                <th>DATA</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {bounties.length > 0 ? bounties.map(b => {
                const isCred = b.bounty_type === 'credential';
                const isFp = b.bounty_type === 'fingerprint';
                const Icon = isCred ? Key : Package;
                return (
                  <tr key={b.id} className="clickable" onClick={() => setSelected(b)}>
                    <td className="dim" style={{ fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
                      {new Date(b.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="violet-accent">{b.decky}</td>
                    <td><span className="chip dim-chip">{b.service}</span></td>
                    <td>
                      <span
                        className="matrix-text attacker-link"
                        onClick={(e) => { e.stopPropagation(); navigate(`/attackers?q=${encodeURIComponent(b.attacker_ip)}`); }}
                      >
                        {b.attacker_ip}
                      </span>
                    </td>
                    <td>
                      <span className={`chip ${isCred ? 'matrix' : 'violet'}`}>
                        <Icon size={9} style={{ marginRight: 4 }} />
                        {b.bounty_type.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      {isCred ? (
                        <div className="cred-inline">
                          <span><span className="k-small">user:</span>{b.payload?.username ?? '—'}</span>
                          <span>
                            <span className="k-small">pass:</span>
                            <span className="matrix-text">{b.payload?.password ?? '—'}</span>
                          </span>
                        </div>
                      ) : isFp ? (
                        <FingerprintPreview payload={b.payload} />
                      ) : (
                        <span className="data-preview">
                          {b.payload?.query || b.payload?.body || b.payload?.command || JSON.stringify(b.payload)}
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'right', opacity: 0.4 }}>
                      <ChevR size={14} />
                    </td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan={7}>
                    <EmptyState
                      icon={Target}
                      title={loading ? 'RETRIEVING ARTIFACTS…' : 'THE VAULT IS EMPTY'}
                      hint={loading ? undefined : 'attacker-dropped artifacts will land here'}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <BountyInspector
          bounty={selected}
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

export default Bounty;
