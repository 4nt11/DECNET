import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import './Dashboard.css';
import './Swarm.css';
import { HardDrive, PowerOff, RefreshCw, Trash2, Wifi, WifiOff } from 'lucide-react';

interface SwarmHost {
  uuid: string;
  name: string;
  address: string;
  agent_port: number;
  status: string;
  last_heartbeat: string | null;
  client_cert_fingerprint: string;
  updater_cert_fingerprint: string | null;
  enrolled_at: string;
  notes: string | null;
}

const shortFp = (fp: string): string => (fp ? fp.slice(0, 16) + '…' : '—');

const SwarmHosts: React.FC = () => {
  const [hosts, setHosts] = useState<SwarmHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [decommissioning, setDecommissioning] = useState<string | null>(null);
  const [tearingDown, setTearingDown] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchHosts = async () => {
    try {
      const res = await api.get('/swarm/hosts');
      setHosts(res.data);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to fetch swarm hosts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHosts();
    const t = setInterval(fetchHosts, 10000);
    return () => clearInterval(t);
  }, []);

  const handleTeardownAll = async (host: SwarmHost) => {
    if (!window.confirm(`Tear down ALL deckies on ${host.name}? The host stays enrolled.`)) return;
    setTearingDown(host.uuid);
    try {
      await api.post(`/swarm/hosts/${host.uuid}/teardown`, {});
      await fetchHosts();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Teardown failed');
    } finally {
      setTearingDown(null);
    }
  };

  const handleDecommission = async (host: SwarmHost) => {
    if (!window.confirm(`Decommission ${host.name} (${host.address})? This removes certs and decky mappings.`)) return;
    setDecommissioning(host.uuid);
    try {
      await api.delete(`/swarm/hosts/${host.uuid}`);
      await fetchHosts();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Decommission failed');
    } finally {
      setDecommissioning(null);
    }
  };

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1><HardDrive size={28} /> SWARM Hosts</h1>
        <button onClick={fetchHosts} className="control-btn" disabled={loading}>
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      <div className="panel">
        {loading ? (
          <p>Loading hosts…</p>
        ) : hosts.length === 0 ? (
          <p>No swarm hosts enrolled yet. Head to <strong>SWARM → Agent Enrollment</strong> to onboard one.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Name</th>
                <th>Address</th>
                <th>Last heartbeat</th>
                <th>Client cert</th>
                <th>Enrolled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.uuid}>
                  <td>
                    {h.status === 'active' ? <Wifi size={16} /> : <WifiOff size={16} />} {h.status}
                  </td>
                  <td>{h.name}</td>
                  <td>{h.address ? `${h.address}:${h.agent_port}` : <em>pending first connect</em>}</td>
                  <td>{h.last_heartbeat ? new Date(h.last_heartbeat).toLocaleString() : '—'}</td>
                  <td title={h.client_cert_fingerprint}><code>{shortFp(h.client_cert_fingerprint)}</code></td>
                  <td>{new Date(h.enrolled_at).toLocaleString()}</td>
                  <td>
                    <button
                      className="control-btn"
                      disabled={tearingDown === h.uuid || h.status !== 'active'}
                      onClick={() => handleTeardownAll(h)}
                      title="Stop all deckies on this host (keeps it enrolled)"
                    >
                      <PowerOff size={14} /> {tearingDown === h.uuid ? 'Tearing down…' : 'Teardown all'}
                    </button>
                    <button
                      className="control-btn danger"
                      disabled={decommissioning === h.uuid}
                      onClick={() => handleDecommission(h)}
                    >
                      <Trash2 size={14} /> {decommissioning === h.uuid ? 'Decommissioning…' : 'Decommission'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default SwarmHosts;
