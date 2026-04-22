import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import './Dashboard.css';
import './Swarm.css';
import { HardDrive, PowerOff, RefreshCw, Server, Trash2, Wifi, WifiOff } from 'lucide-react';

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
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<SwarmHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [decommissioning, setDecommissioning] = useState<Set<string>>(new Set());
  const [tearingDown, setTearingDown] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  // Two-click arm/commit replaces window.confirm(). Browsers silently
  // suppress confirm() after the "prevent additional dialogs" opt-out,
  // which manifests as a dead button — no network request, no console
  // error. Key format: "<action>:<uuid>".
  const [armed, setArmed] = useState<string | null>(null);
  const arm = (key: string) => {
    setArmed(key);
    setTimeout(() => setArmed((prev) => (prev === key ? null : prev)), 4000);
  };

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

  const addTo = (set: Set<string>, id: string) => { const n = new Set(set); n.add(id); return n; };
  const removeFrom = (set: Set<string>, id: string) => { const n = new Set(set); n.delete(id); return n; };

  const handleTeardownAll = async (host: SwarmHost) => {
    const key = `teardown:${host.uuid}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setTearingDown((s) => addTo(s, host.uuid));
    try {
      // 202 Accepted — teardown runs async on the backend.
      await api.post(`/swarm/hosts/${host.uuid}/teardown`, {});
      await fetchHosts();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Teardown failed');
    } finally {
      setTearingDown((s) => removeFrom(s, host.uuid));
    }
  };

  const handleDecommission = async (host: SwarmHost) => {
    const key = `decom:${host.uuid}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setDecommissioning((s) => addTo(s, host.uuid));
    try {
      await api.delete(`/swarm/hosts/${host.uuid}`);
      await fetchHosts();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Decommission failed');
    } finally {
      setDecommissioning((s) => removeFrom(s, host.uuid));
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
          <EmptyState
            icon={Server}
            title="NO SWARM HOSTS ENROLLED"
            hint="onboard an agent to expand the fleet"
            cta={{ label: 'ENROLL HOST', onClick: () => navigate('/swarm/enroll') }}
          />
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
                      className={`control-btn${armed === `teardown:${h.uuid}` ? ' danger' : ''}`}
                      disabled={tearingDown.has(h.uuid) || h.status !== 'active'}
                      onClick={() => handleTeardownAll(h)}
                      title="Stop all deckies on this host (keeps it enrolled)"
                    >
                      <PowerOff size={14} />{' '}
                      {tearingDown.has(h.uuid)
                        ? 'Tearing down…'
                        : armed === `teardown:${h.uuid}`
                          ? 'Click again to confirm'
                          : 'Teardown all'}
                    </button>
                    <button
                      className="control-btn danger"
                      disabled={decommissioning.has(h.uuid)}
                      onClick={() => handleDecommission(h)}
                    >
                      <Trash2 size={14} />{' '}
                      {decommissioning.has(h.uuid)
                        ? 'Decommissioning…'
                        : armed === `decom:${h.uuid}`
                          ? 'Click again to confirm'
                          : 'Decommission'}
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
