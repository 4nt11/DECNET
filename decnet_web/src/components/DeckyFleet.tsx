import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import './Dashboard.css'; // Re-use common dashboard styles
import { Server, Cpu, Globe, Database, Clock, RefreshCw } from 'lucide-react';

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
}

const DeckyFleet: React.FC = () => {
  const [deckies, setDeckies] = useState<Decky[]>([]);
  const [loading, setLoading] = useState(true);
  const [mutating, setMutating] = useState<string | null>(null);

  const fetchDeckies = async () => {
    try {
      const _res = await api.get('/deckies');
      setDeckies(_res.data);
    } catch (err) {
      console.error('Failed to fetch decky fleet', err);
    } finally {
      setLoading(false);
    }
  };

  const handleMutate = async (name: string) => {
    setMutating(name);
    try {
      await api.post(`/deckies/${name}/mutate`, {}, { timeout: 120000 });
      await fetchDeckies();
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
      fetchDeckies();
    } catch (err) {
      console.error('Failed to update interval', err);
      alert('Update failed');
    }
  };

  useEffect(() => {
    fetchDeckies();
    const _interval = setInterval(fetchDeckies, 10000); // Fleet state updates less frequently than logs
    return () => clearInterval(_interval);
  }, []);

  if (loading) return <div className="loader">SCANNING NETWORK FOR DECOYS...</div>;

  return (
    <div className="dashboard">
      <div className="section-header" style={{ border: '1px solid var(--border-color)', backgroundColor: 'var(--secondary-color)', marginBottom: '24px' }}>
        <Server size={20} />
        <h2 style={{ margin: 0 }}>DECOY FLEET ASSET INVENTORY</h2>
      </div>

      <div className="deckies-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '24px' }}>
        {deckies.length > 0 ? deckies.map(decky => (
          <div key={decky.name} className="stat-card" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '16px', padding: '24px' }}>
            <div style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
              <span className="matrix-text" style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{decky.name}</span>
              <span className="dim" style={{ fontSize: '0.8rem', backgroundColor: 'rgba(0, 255, 65, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>{decky.ip}</span>
            </div>
            
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem', marginTop: '8px' }}>
                <Clock size={14} className="dim" />
                <span className="dim">MUTATION:</span>
                <span 
                  style={{ color: 'var(--accent-color)', cursor: 'pointer', textDecoration: 'underline' }}
                  onClick={() => handleIntervalChange(decky.name, decky.mutate_interval)}
                >
                  {decky.mutate_interval ? `EVERY ${decky.mutate_interval}m` : 'DISABLED'}
                </span>
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
              </div>
              {decky.last_mutated > 0 && (
                <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', fontStyle: 'italic', marginTop: '4px' }}>
                  Last mutated: {new Date(decky.last_mutated * 1000).toLocaleString()}
                </div>
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
          </div>
        )) : (
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
