import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Crosshair } from 'lucide-react';
import api from '../utils/api';
import './Dashboard.css';

interface AttackerData {
  uuid: string;
  ip: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  service_count: number;
  decky_count: number;
  services: string[];
  deckies: string[];
  traversal_path: string | null;
  is_traversal: boolean;
  bounty_count: number;
  credential_count: number;
  fingerprints: any[];
  commands: { service: string; decky: string; command: string; timestamp: string }[];
  updated_at: string;
}

const AttackerDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [attacker, setAttacker] = useState<AttackerData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchAttacker = async () => {
      setLoading(true);
      try {
        const res = await api.get(`/attackers/${id}`);
        setAttacker(res.data);
      } catch (err: any) {
        if (err.response?.status === 404) {
          setError('ATTACKER NOT FOUND');
        } else {
          setError('FAILED TO LOAD ATTACKER PROFILE');
        }
      } finally {
        setLoading(false);
      }
    };
    fetchAttacker();
  }, [id]);

  if (loading) {
    return (
      <div className="dashboard">
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          LOADING THREAT PROFILE...
        </div>
      </div>
    );
  }

  if (error || !attacker) {
    return (
      <div className="dashboard">
        <button onClick={() => navigate('/attackers')} className="back-button">
          <ArrowLeft size={18} />
          <span>BACK TO PROFILES</span>
        </button>
        <div style={{ textAlign: 'center', padding: '80px', opacity: 0.5, letterSpacing: '4px' }}>
          {error || 'ATTACKER NOT FOUND'}
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      {/* Back Button */}
      <button onClick={() => navigate('/attackers')} className="back-button">
        <ArrowLeft size={18} />
        <span>BACK TO PROFILES</span>
      </button>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <Crosshair size={32} className="violet-accent" />
        <h1 className="matrix-text" style={{ fontSize: '1.8rem', letterSpacing: '2px' }}>
          {attacker.ip}
        </h1>
        {attacker.is_traversal && (
          <span className="traversal-badge" style={{ fontSize: '0.8rem' }}>TRAVERSAL</span>
        )}
      </div>

      {/* Stats Row */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card">
          <div className="stat-value matrix-text">{attacker.event_count}</div>
          <div className="stat-label">EVENTS</div>
        </div>
        <div className="stat-card">
          <div className="stat-value violet-accent">{attacker.bounty_count}</div>
          <div className="stat-label">BOUNTIES</div>
        </div>
        <div className="stat-card">
          <div className="stat-value violet-accent">{attacker.credential_count}</div>
          <div className="stat-label">CREDENTIALS</div>
        </div>
        <div className="stat-card">
          <div className="stat-value matrix-text">{attacker.service_count}</div>
          <div className="stat-label">SERVICES</div>
        </div>
        <div className="stat-card">
          <div className="stat-value matrix-text">{attacker.decky_count}</div>
          <div className="stat-label">DECKIES</div>
        </div>
      </div>

      {/* Timestamps */}
      <div className="logs-section">
        <div className="section-header">
          <h2>TIMELINE</h2>
        </div>
        <div style={{ padding: '16px', display: 'flex', gap: '32px', fontSize: '0.85rem' }}>
          <div>
            <span className="dim">FIRST SEEN: </span>
            <span className="matrix-text">{new Date(attacker.first_seen).toLocaleString()}</span>
          </div>
          <div>
            <span className="dim">LAST SEEN: </span>
            <span className="matrix-text">{new Date(attacker.last_seen).toLocaleString()}</span>
          </div>
          <div>
            <span className="dim">UPDATED: </span>
            <span className="dim">{new Date(attacker.updated_at).toLocaleString()}</span>
          </div>
        </div>
      </div>

      {/* Services */}
      <div className="logs-section">
        <div className="section-header">
          <h2>SERVICES TARGETED</h2>
        </div>
        <div style={{ padding: '16px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {attacker.services.length > 0 ? attacker.services.map((svc) => (
            <span key={svc} className="service-badge" style={{ fontSize: '0.85rem', padding: '4px 12px' }}>
              {svc.toUpperCase()}
            </span>
          )) : (
            <span className="dim">No services recorded</span>
          )}
        </div>
      </div>

      {/* Deckies & Traversal */}
      <div className="logs-section">
        <div className="section-header">
          <h2>DECKY INTERACTIONS</h2>
        </div>
        <div style={{ padding: '16px', fontSize: '0.85rem' }}>
          {attacker.traversal_path ? (
            <div>
              <span className="dim">TRAVERSAL PATH: </span>
              <span className="violet-accent">{attacker.traversal_path}</span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {attacker.deckies.map((d) => (
                <span key={d} className="service-badge" style={{ borderColor: 'var(--accent-color)', color: 'var(--accent-color)' }}>
                  {d}
                </span>
              ))}
              {attacker.deckies.length === 0 && <span className="dim">No deckies recorded</span>}
            </div>
          )}
        </div>
      </div>

      {/* Commands */}
      <div className="logs-section">
        <div className="section-header">
          <h2>COMMANDS ({attacker.commands.length})</h2>
        </div>
        {attacker.commands.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>SERVICE</th>
                  <th>DECKY</th>
                  <th>COMMAND</th>
                </tr>
              </thead>
              <tbody>
                {attacker.commands.map((cmd, i) => (
                  <tr key={i}>
                    <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {cmd.timestamp ? new Date(cmd.timestamp).toLocaleString() : '-'}
                    </td>
                    <td>{cmd.service}</td>
                    <td className="violet-accent">{cmd.decky}</td>
                    <td className="matrix-text" style={{ fontFamily: 'monospace' }}>{cmd.command}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
            NO COMMANDS CAPTURED
          </div>
        )}
      </div>

      {/* Fingerprints */}
      <div className="logs-section">
        <div className="section-header">
          <h2>FINGERPRINTS ({attacker.fingerprints.length})</h2>
        </div>
        {attacker.fingerprints.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>TYPE</th>
                  <th>VALUE</th>
                </tr>
              </thead>
              <tbody>
                {attacker.fingerprints.map((fp, i) => (
                  <tr key={i}>
                    <td className="violet-accent">{fp.type || fp.bounty_type || 'unknown'}</td>
                    <td className="dim" style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                      {typeof fp === 'object' ? JSON.stringify(fp) : String(fp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
            NO FINGERPRINTS CAPTURED
          </div>
        )}
      </div>

      {/* UUID footer */}
      <div style={{ textAlign: 'right', fontSize: '0.65rem', opacity: 0.3, marginTop: '8px' }}>
        UUID: {attacker.uuid}
      </div>
    </div>
  );
};

export default AttackerDetail;
