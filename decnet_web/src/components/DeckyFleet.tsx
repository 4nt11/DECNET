import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import './Dashboard.css'; // Re-use common dashboard styles
import { Server, Cpu, Globe, Database, Clock, RefreshCw, Upload, Network, PowerOff } from 'lucide-react';

interface SwarmMeta {
  host_uuid: string;
  host_name: string;
  host_address: string;
  host_status: string;
  state: string;
  last_error: string | null;
  last_seen: string | null;
}

interface Decky {
  name: string;
  ip: string;
  services: string[];
  distro: string;
  hostname: string;
  archetype: string | null;
  service_config: Record<string, Record<string, any>>;
  mutate_interval: number | null;
  last_mutated: number;
  swarm?: SwarmMeta;
}

// Raw shape returned by /swarm/deckies (DeckyShardView on the backend).
// Pre-heartbeat rows have nullable metadata fields; we coerce to the
// shared Decky interface so the card grid renders uniformly either way.
interface SwarmDeckyRaw {
  decky_name: string;
  decky_ip: string | null;
  host_uuid: string;
  host_name: string;
  host_address: string;
  host_status: string;
  services: string[];
  state: string;
  last_error: string | null;
  last_seen: string | null;
  hostname: string | null;
  distro: string | null;
  archetype: string | null;
  service_config: Record<string, Record<string, any>>;
  mutate_interval: number | null;
  last_mutated: number;
}

const _stateColor = (state: string): string => {
  switch (state) {
    case 'running': return 'var(--accent-color)';
    case 'degraded': return '#f39c12';
    case 'tearing_down': return '#f39c12';
    case 'pending': return 'var(--dim-color)';
    case 'failed':
    case 'teardown_failed': return '#e74c3c';
    default: return 'var(--dim-color)';
  }
};

const DeckyFleet: React.FC = () => {
  const [deckies, setDeckies] = useState<Decky[]>([]);
  const [loading, setLoading] = useState(true);
  const [mutating, setMutating] = useState<string | null>(null);
  const [showDeploy, setShowDeploy] = useState(false);
  const [iniContent, setIniContent] = useState('');
  const [deploying, setDeploying] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [deployMode, setDeployMode] = useState<{ mode: string; swarm_host_count: number } | null>(null);
  // Two-click arm/commit for teardown — lifted from the old SwarmDeckies
  // component. browsers silently suppress window.confirm() after the user
  // opts out of further dialogs, so we gate destructive actions with a
  // 4-second "click again" window instead.
  const [armed, setArmed] = useState<string | null>(null);
  const [tearingDown, setTearingDown] = useState<Set<string>>(new Set());

  const arm = (key: string) => {
    setArmed(key);
    setTimeout(() => setArmed((prev) => (prev === key ? null : prev)), 4000);
  };

  const fetchDeckies = async (mode?: string) => {
    try {
      if (mode === 'swarm') {
        const res = await api.get<SwarmDeckyRaw[]>('/swarm/deckies');
        const normalized: Decky[] = res.data.map((s) => ({
          name: s.decky_name,
          ip: s.decky_ip || '—',
          services: s.services || [],
          distro: s.distro || 'unknown',
          hostname: s.hostname || '—',
          archetype: s.archetype,
          service_config: s.service_config || {},
          mutate_interval: s.mutate_interval,
          last_mutated: s.last_mutated || 0,
          swarm: {
            host_uuid: s.host_uuid,
            host_name: s.host_name,
            host_address: s.host_address,
            host_status: s.host_status,
            state: s.state,
            last_error: s.last_error,
            last_seen: s.last_seen,
          },
        }));
        setDeckies(normalized);
      } else {
        const res = await api.get('/deckies');
        setDeckies(res.data);
      }
    } catch (err) {
      console.error('Failed to fetch decky fleet', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchRole = async () => {
    try {
      const res = await api.get('/config');
      setIsAdmin(res.data.role === 'admin');
    } catch {
      setIsAdmin(false);
    }
  };

  const handleMutate = async (name: string) => {
    setMutating(name);
    try {
      await api.post(`/deckies/${name}/mutate`, {}, { timeout: 120000 });
      await fetchDeckies(deployMode?.mode);
    } catch (err: any) {
      console.error('Failed to mutate', err);
      if (err.code === 'ECONNABORTED') {
        alert('Mutation is still running in the background but the UI timed out.');
      } else {
        alert('Mutation failed');
      }
    } finally {
      setMutating(null);
    }
  };

  const handleIntervalChange = async (name: string, current: number | null) => {
    const _val = prompt(`Enter new mutation interval in minutes for ${name} (leave empty to disable):`, current?.toString() || '');
    if (_val === null) return;
    const mutate_interval = _val.trim() === '' ? null : parseInt(_val);
    try {
      await api.put(`/deckies/${name}/mutate-interval`, { mutate_interval });
      fetchDeckies(deployMode?.mode);
    } catch (err) {
      console.error('Failed to update interval', err);
      alert('Update failed');
    }
  };

  const handleTeardown = async (d: Decky) => {
    if (!d.swarm) return;
    const key = `td:${d.swarm.host_uuid}:${d.name}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setTearingDown((prev) => new Set(prev).add(d.name));
    try {
      await api.post(`/swarm/hosts/${d.swarm.host_uuid}/teardown`, { decky_id: d.name });
      await fetchDeckies(deployMode?.mode);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Teardown failed');
    } finally {
      setTearingDown((prev) => {
        const next = new Set(prev);
        next.delete(d.name);
        return next;
      });
    }
  };

  const handleDeploy = async () => {
    if (!iniContent.trim()) return;
    setDeploying(true);
    try {
      await api.post('/deckies/deploy', { ini_content: iniContent }, { timeout: 120000 });
      setIniContent('');
      setShowDeploy(false);
      fetchDeckies(deployMode?.mode);
    } catch (err: any) {
      console.error('Deploy failed', err);
      alert(`Deploy failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setDeploying(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setIniContent(content);
    };
    reader.readAsText(file);
  };

  const fetchDeployMode = async () => {
    try {
      const res = await api.get('/system/deployment-mode');
      const mode = res.data.mode;
      setDeployMode({ mode, swarm_host_count: res.data.swarm_host_count });
      return mode;
    } catch {
      setDeployMode(null);
      return undefined;
    }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const mode = await fetchDeployMode();
      if (cancelled) return;
      await fetchDeckies(mode);
      await fetchRole();
    })();
    // Keep the poll mode-aware by reading from the deployMode ref at tick time.
    const _interval = setInterval(() => {
      // Deployment mode itself can change (first host enrolls → swarm), so
      // re-check it alongside the fleet.
      fetchDeployMode().then((m) => fetchDeckies(m));
    }, 10000);
    return () => { cancelled = true; clearInterval(_interval); };
  }, []);

  if (loading) return <div className="loader">SCANNING NETWORK FOR DECOYS...</div>;

  const isSwarm = deployMode?.mode === 'swarm';

  return (
    <div className="dashboard">
      <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', border: '1px solid var(--border-color)', backgroundColor: 'var(--secondary-color)', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Server size={20} />
          <h2 style={{ margin: 0 }}>DECOY FLEET ASSET INVENTORY</h2>
          {deployMode && (
            <span className="dim" style={{ fontSize: '0.75rem', marginLeft: 8 }}>
              [{isSwarm ? `SWARM × ${deployMode.swarm_host_count}` : 'UNIHOST'}]
            </span>
          )}
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowDeploy(!showDeploy)}
            style={{ display: 'flex', alignItems: 'center', gap: '8px', border: '1px solid var(--accent-color)', color: 'var(--accent-color)' }}
          >
            + DEPLOY DECKIES
          </button>
        )}
      </div>

      {showDeploy && (
        <div style={{ marginBottom: '24px', padding: '24px', backgroundColor: 'var(--secondary-color)', border: '1px solid var(--accent-color)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '1rem', color: 'var(--text-color)' }}>
              Deploy via INI Configuration
              {deployMode && (
                <span style={{ marginLeft: 12, fontSize: '0.75rem', color: 'var(--dim-color)', fontWeight: 'normal' }}>
                  {deployMode.mode === 'swarm'
                    ? `→ will shard across ${deployMode.swarm_host_count} SWARM host(s)`
                    : '→ will deploy locally (UNIHOST)'}
                </span>
              )}
            </h3>
            <div>
              <input
                type="file"
                id="ini-upload"
                accept=".ini"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
              <label
                htmlFor="ini-upload"
                style={{
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  fontSize: '0.8rem',
                  color: 'var(--accent-color)',
                  border: '1px solid var(--accent-color)',
                  padding: '4px 12px'
                }}
              >
                <Upload size={14} /> UPLOAD FILE
              </label>
            </div>
          </div>
          <textarea
            value={iniContent}
            onChange={(e) => setIniContent(e.target.value)}
            placeholder="[decky-01]&#10;archetype=linux-server&#10;services=ssh,http"
            style={{ width: '100%', height: '200px', backgroundColor: '#000', color: 'var(--text-color)', border: '1px solid var(--border-color)', padding: '12px', fontFamily: 'monospace' }}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
            <button onClick={() => setShowDeploy(false)} style={{ border: '1px solid var(--border-color)', color: 'var(--dim-color)' }}>CANCEL</button>
            <button onClick={handleDeploy} disabled={deploying} style={{ background: 'var(--accent-color)', color: '#000', border: 'none', display: 'flex', alignItems: 'center', gap: '8px' }}>
              {deploying && <RefreshCw size={14} className="spin" />}
              {deploying ? 'DEPLOYING...' : 'DEPLOY'}
            </button>
          </div>
        </div>
      )}

      <div className="deckies-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '24px' }}>
        {deckies.length > 0 ? deckies.map(decky => {
          const tdKey = decky.swarm ? `td:${decky.swarm.host_uuid}:${decky.name}` : '';
          const tdBusy = tearingDown.has(decky.name) || decky.swarm?.state === 'tearing_down';
          return (
            <div key={decky.name} className="stat-card" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '16px', padding: '24px' }}>
              <div style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
                <span className="matrix-text" style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{decky.name}</span>
                <span className="dim" style={{ fontSize: '0.8rem', backgroundColor: 'rgba(0, 255, 65, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>{decky.ip}</span>
              </div>

              {decky.swarm && (
                <div style={{ width: '100%', display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', fontSize: '0.8rem' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px', border: '1px solid var(--border-color)', padding: '2px 8px', borderRadius: '2px' }}>
                    <Network size={12} className="dim" />
                    <span className="dim">{decky.swarm.host_name}</span>
                    <span style={{ color: 'var(--dim-color)' }}>@ {decky.swarm.host_address || '—'}</span>
                  </span>
                  <span style={{
                    padding: '2px 8px', borderRadius: '2px',
                    border: `1px solid ${_stateColor(decky.swarm.state)}`,
                    color: _stateColor(decky.swarm.state),
                    fontSize: '0.7rem', letterSpacing: '1px',
                  }}>
                    {decky.swarm.state.toUpperCase()}
                  </span>
                  {decky.swarm.last_error && (
                    <span style={{ color: '#e74c3c', fontSize: '0.7rem' }} title={decky.swarm.last_error}>
                      ⚠ {decky.swarm.last_error.slice(0, 60)}{decky.swarm.last_error.length > 60 ? '…' : ''}
                    </span>
                  )}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
                  <Cpu size={14} className="dim" />
                  <span className="dim">HOSTNAME:</span> {decky.hostname}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
                  <Globe size={14} className="dim" />
                  <span className="dim">DISTRO:</span> {decky.distro}
                </div>
                {decky.archetype && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
                    <Database size={14} className="dim" />
                    <span className="dim">ARCHETYPE:</span> <span style={{ color: 'var(--highlight-color)' }}>{decky.archetype}</span>
                  </div>
                )}
                {/* Mutate controls are unihost-only for v1 — swarm-side mutation
                    belongs in a separate ticket (the worker /mutate endpoint
                    still returns 501). */}
                {!decky.swarm && (
                  <>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem', marginTop: '8px' }}>
                      <Clock size={14} className="dim" />
                      <span className="dim">MUTATION:</span>
                      {isAdmin ? (
                        <span
                          style={{ color: 'var(--accent-color)', cursor: 'pointer', textDecoration: 'underline' }}
                          onClick={() => handleIntervalChange(decky.name, decky.mutate_interval)}
                        >
                          {decky.mutate_interval ? `EVERY ${decky.mutate_interval}m` : 'DISABLED'}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--accent-color)' }}>
                          {decky.mutate_interval ? `EVERY ${decky.mutate_interval}m` : 'DISABLED'}
                        </span>
                      )}
                      {isAdmin && (
                        <button
                          onClick={() => handleMutate(decky.name)}
                          disabled={!!mutating}
                          style={{
                            background: 'transparent', border: '1px solid var(--accent-color)',
                            color: 'var(--accent-color)', padding: '2px 8px', fontSize: '0.7rem',
                            cursor: mutating ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: '4px', marginLeft: 'auto',
                            opacity: mutating ? 0.5 : 1
                          }}
                        >
                          <RefreshCw size={10} className={mutating === decky.name ? "spin" : ""} /> {mutating === decky.name ? 'MUTATING...' : 'FORCE'}
                        </button>
                      )}
                    </div>
                    {decky.last_mutated > 0 && (
                      <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', fontStyle: 'italic', marginTop: '4px' }}>
                        Last mutated: {new Date(decky.last_mutated * 1000).toLocaleString()}
                      </div>
                    )}
                  </>
                )}
              </div>

              <div style={{ width: '100%' }}>
                <div className="dim" style={{ fontSize: '0.7rem', marginBottom: '8px', letterSpacing: '1px' }}>EXPOSED SERVICES:</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {decky.services.map(svc => {
                    const _config = decky.service_config[svc];
                    return (
                      <div key={svc} className="service-tag-container" style={{ position: 'relative' }}>
                        <span className="service-tag" style={{
                          display: 'inline-block',
                          padding: '4px 10px',
                          fontSize: '0.75rem',
                          backgroundColor: 'var(--bg-color)',
                          border: '1px solid var(--accent-color)',
                          color: 'var(--accent-color)',
                          borderRadius: '2px',
                          cursor: 'help'
                        }}>
                          {svc}
                        </span>
                        {_config && Object.keys(_config).length > 0 && (
                          <div className="service-config-tooltip" style={{
                            display: 'none',
                            position: 'absolute',
                            bottom: '100%',
                            left: '0',
                            backgroundColor: 'rgba(10, 10, 10, 0.95)',
                            border: '1px solid var(--accent-color)',
                            padding: '12px',
                            zIndex: 100,
                            minWidth: '200px',
                            boxShadow: '0 0 15px rgba(0, 255, 65, 0.2)',
                            marginBottom: '8px'
                          }}>
                            {Object.entries(_config).map(([k, v]) => (
                              <div key={k} style={{ fontSize: '0.7rem', marginBottom: '4px' }}>
                                <span style={{ color: 'var(--highlight-color)', fontWeight: 'bold' }}>{k}:</span>
                                <span style={{ marginLeft: '6px', opacity: 0.9 }}>{String(v)}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {decky.swarm && isAdmin && (
                <div style={{ width: '100%', display: 'flex', justifyContent: 'flex-end', borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
                  <button
                    onClick={() => handleTeardown(decky)}
                    disabled={tdBusy}
                    style={{
                      background: 'transparent',
                      border: '1px solid #e74c3c',
                      color: '#e74c3c',
                      padding: '4px 12px',
                      fontSize: '0.75rem',
                      display: 'flex', alignItems: 'center', gap: '6px',
                      cursor: tdBusy ? 'not-allowed' : 'pointer',
                      opacity: tdBusy ? 0.5 : 1,
                    }}
                    title="Stop this decky on its host"
                  >
                    <PowerOff size={12} />
                    {tdBusy
                      ? 'TEARING DOWN…'
                      : armed === tdKey
                        ? 'CLICK AGAIN TO CONFIRM'
                        : 'TEARDOWN'}
                  </button>
                </div>
              )}
            </div>
          );
        }) : (
          <div className="stat-card" style={{ gridColumn: '1 / -1', justifyContent: 'center', padding: '60px' }}>
            <span className="dim">NO DECOYS CURRENTLY DEPLOYED IN THIS SECTOR</span>
          </div>
        )}
      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .service-tag-container:hover .service-config-tooltip {
          display: block !important;
        }
      `}} />
    </div>
  );
};

export default DeckyFleet;
