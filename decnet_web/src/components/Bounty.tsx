import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Archive, Search, ChevronLeft, ChevronRight, Filter } from 'lucide-react';
import api from '../utils/api';
import './Dashboard.css';

interface BountyEntry {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  attacker_ip: string;
  bounty_type: string;
  payload: any;
}

const Bounty: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const typeFilter = searchParams.get('type') || '';
  const page = parseInt(searchParams.get('page') || '1');

  const [bounties, setBounties] = useState<BountyEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(query);
  
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

  useEffect(() => {
    fetchBounties();
  }, [query, typeFilter, page]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams({ q: searchInput, type: typeFilter, page: '1' });
  };

  const setPage = (p: number) => {
    setSearchParams({ q: query, type: typeFilter, page: p.toString() });
  };

  const setType = (t: string) => {
    setSearchParams({ q: query, type: t, page: '1' });
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="dashboard">
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <Archive size={32} className="violet-accent" />
          <h1 style={{ fontSize: '1.5rem', letterSpacing: '4px' }}>BOUNTY VAULT</h1>
        </div>

        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', border: '1px solid var(--border-color)', padding: '4px 12px' }}>
            <Filter size={16} className="dim" />
            <select 
              value={typeFilter} 
              onChange={(e) => setType(e.target.value)}
              style={{ background: 'transparent', border: 'none', color: 'inherit', fontSize: '0.8rem', outline: 'none' }}
            >
              <option value="">ALL TYPES</option>
              <option value="credential">CREDENTIALS</option>
              <option value="payload">PAYLOADS</option>
            </select>
          </div>

          <form onSubmit={handleSearch} style={{ display: 'flex', alignItems: 'center', border: '1px solid var(--border-color)', padding: '4px 12px' }}>
            <Search size={18} style={{ opacity: 0.5, marginRight: '8px' }} />
            <input 
              type="text" 
              placeholder="Search bounty..." 
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              style={{ background: 'transparent', border: 'none', padding: '4px', fontSize: '0.8rem', width: '200px' }}
            />
          </form>
        </div>
      </div>

      <div className="logs-section">
        <div className="section-header" style={{ justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="matrix-text" style={{ fontSize: '0.8rem' }}>{total} ARTIFACTS CAPTURED</span>
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

        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>DECKY</th>
                <th>SERVICE</th>
                <th>ATTACKER</th>
                <th>TYPE</th>
                <th>DATA</th>
              </tr>
            </thead>
            <tbody>
              {bounties.length > 0 ? bounties.map((b) => (
                <tr key={b.id}>
                  <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{new Date(b.timestamp).toLocaleString()}</td>
                  <td className="violet-accent">{b.decky}</td>
                  <td>{b.service}</td>
                  <td className="matrix-text">{b.attacker_ip}</td>
                  <td>
                    <span style={{ 
                      fontSize: '0.7rem', 
                      padding: '2px 8px', 
                      borderRadius: '4px', 
                      border: `1px solid ${b.bounty_type === 'credential' ? 'var(--text-color)' : 'var(--accent-color)'}`,
                      backgroundColor: b.bounty_type === 'credential' ? 'rgba(0, 255, 65, 0.1)' : 'rgba(238, 130, 238, 0.1)',
                      color: b.bounty_type === 'credential' ? 'var(--text-color)' : 'var(--accent-color)'
                    }}>
                      {b.bounty_type.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontSize: '0.9rem' }}>
                      {b.bounty_type === 'credential' ? (
                        <div style={{ display: 'flex', gap: '12px' }}>
                          <span><span className="dim" style={{ marginRight: '4px' }}>user:</span>{b.payload.username}</span>
                          <span><span className="dim" style={{ marginRight: '4px' }}>pass:</span>{b.payload.password}</span>
                        </div>
                      ) : (
                        <span className="dim" style={{ fontSize: '0.8rem' }}>{JSON.stringify(b.payload)}</span>
                      )}
                    </div>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '60px', opacity: 0.5, letterSpacing: '4px' }}>
                    {loading ? 'RETRIEVING ARTIFACTS...' : 'THE VAULT IS EMPTY'}
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

export default Bounty;
