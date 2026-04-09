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
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div className="header-title">
          <Archive size={24} className="violet-accent" />
          <h1>BOUNTY VAULT</h1>
        </div>
        
        <div className="header-actions">
          <div className="filter-group">
            <Filter size={16} className="dim-color" />
            <select value={typeFilter} onChange={(e) => setType(e.target.value)}>
              <option value="">ALL TYPES</option>
              <option value="credential">CREDENTIALS</option>
              <option value="payload">PAYLOADS</option>
            </select>
          </div>

          <form onSubmit={handleSearch} className="query-container">
            <Search size={18} className="search-icon" />
            <input 
              type="text" 
              placeholder="Search bounty..." 
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </form>
        </div>
      </div>

      <div className="card log-card">
        <div className="card-header">
          <div className="status-indicator">
            <span className="matrix-text">{total} ARTIFACTS CAPTURED</span>
          </div>
          <div className="pagination-controls">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="icon-btn">
              <ChevronLeft size={16} />
            </button>
            <span className="dim-color">PAGE {page} OF {totalPages || 1}</span>
            <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="icon-btn">
              <ChevronRight size={16} />
            </button>
          </div>
        </div>

        <div className="log-table-container">
          <table className="log-table">
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
              {bounties.map((b) => (
                <tr key={b.id}>
                  <td className="dim-color" style={{ whiteSpace: 'nowrap' }}>{b.timestamp}</td>
                  <td className="violet-accent">{b.decky}</td>
                  <td>{b.service}</td>
                  <td className="matrix-text">{b.attacker_ip}</td>
                  <td>
                    <span className={`severity-badge ${b.bounty_type === 'credential' ? 'high' : 'info'}`}>
                      {b.bounty_type.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <div className="payload-preview">
                      {b.bounty_type === 'credential' ? (
                        <>
                          <span className="dim-color">user:</span> {b.payload.username} 
                          <span className="dim-color" style={{marginLeft: '10px'}}>pass:</span> {b.payload.password}
                        </>
                      ) : (
                        JSON.stringify(b.payload)
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {!loading && bounties.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '40px' }} className="dim-color">
                    THE VAULT IS EMPTY
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
