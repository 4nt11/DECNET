import React, { useState } from 'react';
import EmptyState from './EmptyState/EmptyState';
import EnrollmentWizard from './SwarmHosts/EnrollmentWizard';
import { useSwarmHosts } from './SwarmHosts/useSwarmHosts';
import { shortFp } from './SwarmHosts/helpers';
import type { SwarmHost } from './SwarmHosts/types';
import './Dashboard.css';
import './Swarm.css';
import './DeckyFleet.css';
import {
  HardDrive, PowerOff, RefreshCw, Server,
  Trash2, UserPlus, Wifi, WifiOff,
} from '../icons';

const SwarmHosts: React.FC = () => {
  const {
    hosts, loading, error, reload,
    teardownHost, decommissionHost, generateBundle,
  } = useSwarmHosts();

  const [decommissioning, setDecommissioning] = useState<Set<string>>(new Set());
  const [tearingDown, setTearingDown] = useState<Set<string>>(new Set());
  const [showEnroll, setShowEnroll] = useState(false);
  // Two-click arm/commit replaces window.confirm(). Browsers silently
  // suppress confirm() after the "prevent additional dialogs" opt-out,
  // which manifests as a dead button — no network request, no console
  // error. Key format: "<action>:<uuid>".
  const [armed, setArmed] = useState<string | null>(null);
  const arm = (key: string) => {
    setArmed(key);
    setTimeout(() => setArmed((prev) => (prev === key ? null : prev)), 4000);
  };

  const addTo = (set: Set<string>, id: string) => { const n = new Set(set); n.add(id); return n; };
  const removeFrom = (set: Set<string>, id: string) => { const n = new Set(set); n.delete(id); return n; };

  const handleTeardownAll = async (host: SwarmHost) => {
    const key = `teardown:${host.uuid}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setTearingDown((s) => addTo(s, host.uuid));
    const r = await teardownHost(host.uuid);
    if (!r.ok) alert(r.reason ?? 'Teardown failed');
    setTearingDown((s) => removeFrom(s, host.uuid));
  };

  const handleDecommission = async (host: SwarmHost) => {
    const key = `decom:${host.uuid}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setDecommissioning((s) => addTo(s, host.uuid));
    const r = await decommissionHost(host.uuid);
    if (!r.ok) alert(r.reason ?? 'Decommission failed');
    setDecommissioning((s) => removeFrom(s, host.uuid));
  };

  const online = hosts.filter((h) => h.status === 'online').length;

  return (
    <div className="dashboard swarm-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <HardDrive size={22} className="violet-accent" />
            <h1>SWARM HOSTS</h1>
          </div>
          <span className="page-sub">
            {loading ? 'LOADING…' : `${hosts.length} ENROLLED · ${online} ONLINE`}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={reload} className="control-btn" disabled={loading}>
            <RefreshCw size={14} /> REFRESH
          </button>
          <button onClick={() => setShowEnroll(true)} className="control-btn primary">
            <UserPlus size={14} /> ENROLL HOST
          </button>
        </div>
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
            cta={{ label: 'ENROLL HOST', onClick: () => setShowEnroll(true) }}
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

      <EnrollmentWizard
        open={showEnroll}
        onClose={() => setShowEnroll(false)}
        onEnrolled={reload}
        generateBundle={generateBundle}
      />
    </div>
  );
};

export default SwarmHosts;
