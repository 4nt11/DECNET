import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import './Dashboard.css';
import './Swarm.css';
import { Boxes, PowerOff, RefreshCw } from 'lucide-react';

interface DeckyShard {
  decky_name: string;
  decky_ip: string | null;
  host_uuid: string;
  host_name: string;
  host_address: string;
  host_status: string;
  services: string[];
  state: string;
  last_error: string | null;
  compose_hash: string | null;
  updated_at: string;
}

const SwarmDeckies: React.FC = () => {
  const [shards, setShards] = useState<DeckyShard[]>([]);
  const [loading, setLoading] = useState(true);
  const [tearingDown, setTearingDown] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetch = async () => {
    try {
      const res = await api.get('/swarm/deckies');
      setShards(res.data);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to fetch swarm deckies');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetch();
    const t = setInterval(fetch, 10000);
    return () => clearInterval(t);
  }, []);

  const handleTeardown = async (s: DeckyShard) => {
    if (!window.confirm(`Tear down decky ${s.decky_name} on ${s.host_name}?`)) return;
    setTearingDown(s.decky_name);
    try {
      await api.post(`/swarm/hosts/${s.host_uuid}/teardown`, { decky_id: s.decky_name });
      await fetch();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Teardown failed');
    } finally {
      setTearingDown(null);
    }
  };

  const byHost: Record<string, { name: string; address: string; status: string; shards: DeckyShard[] }> = {};
  for (const s of shards) {
    if (!byHost[s.host_uuid]) {
      byHost[s.host_uuid] = { name: s.host_name, address: s.host_address, status: s.host_status, shards: [] };
    }
    byHost[s.host_uuid].shards.push(s);
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1><Boxes size={28} /> SWARM Deckies</h1>
        <button onClick={fetch} className="control-btn" disabled={loading}>
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {loading ? (
        <p>Loading deckies…</p>
      ) : shards.length === 0 ? (
        <div className="panel">
          <p>No deckies deployed to swarm workers yet.</p>
        </div>
      ) : (
        Object.entries(byHost).map(([uuid, h]) => (
          <div key={uuid} className="panel">
            <h3>{h.name} <small>({h.address}) — {h.status}</small></h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Decky</th>
                  <th>IP</th>
                  <th>State</th>
                  <th>Services</th>
                  <th>Updated</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {h.shards.map((s) => (
                  <tr key={`${uuid}-${s.decky_name}`}>
                    <td>{s.decky_name}</td>
                    <td><code>{s.decky_ip || '—'}</code></td>
                    <td>{s.state}{s.last_error ? ` — ${s.last_error}` : ''}</td>
                    <td>{s.services.join(', ')}</td>
                    <td>{new Date(s.updated_at).toLocaleString()}</td>
                    <td>
                      <button
                        className="control-btn danger"
                        disabled={tearingDown === s.decky_name}
                        onClick={() => handleTeardown(s)}
                        title="Stop this decky on its host"
                      >
                        <PowerOff size={14} /> {tearingDown === s.decky_name ? 'Tearing down…' : 'Teardown'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))
      )}
    </div>
  );
};

export default SwarmDeckies;
