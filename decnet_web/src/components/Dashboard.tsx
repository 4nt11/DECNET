import React, { useEffect, useState, useRef } from 'react';
import './Dashboard.css';
import { Shield, Users, Activity, Clock, Paperclip } from 'lucide-react';
import { parseEventBody } from '../utils/parseEventBody';
import ArtifactDrawer from './ArtifactDrawer';

interface Stats {
  total_logs: number;
  unique_attackers: number;
  active_deckies: number;
  deployed_deckies: number;
}

interface LogEntry {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  event_type: string | null;
  attacker_ip: string;
  raw_line: string;
  fields: string | null;
  msg: string | null;
}

interface DashboardProps {
  searchQuery: string;
}

const Dashboard: React.FC<DashboardProps> = ({ searchQuery }) => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [artifact, setArtifact] = useState<{ decky: string; storedAs: string; fields: Record<string, any> } | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const connect = () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      const token = localStorage.getItem('token');
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      let url = `${baseUrl}/stream?token=${token}`;
      if (searchQuery) {
        url += `&search=${encodeURIComponent(searchQuery)}`;
      }

      const es = new EventSource(url);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'logs') {
            setLogs(prev => [...payload.data, ...prev].slice(0, 100));
          } else if (payload.type === 'stats') {
            setStats(payload.data);
            setLoading(false);
            window.dispatchEvent(new CustomEvent('decnet:stats', { detail: payload.data }));
          }
        } catch (err) {
          console.error('Failed to parse SSE payload', err);
        }
      };

      es.onerror = () => {
        es.close();
        eventSourceRef.current = null;
        reconnectTimerRef.current = setTimeout(connect, 3000);
      };
    };

    connect();

    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, [searchQuery]);

  if (loading && !stats) return <div className="loader">INITIALIZING SENSORS...</div>;

  return (
    <div className="dashboard">
      <div className="stats-grid">
        <StatCard 
          icon={<Activity size={32} />} 
          label="TOTAL INTERACTIONS" 
          value={stats?.total_logs || 0} 
        />
        <StatCard 
          icon={<Users size={32} />} 
          label="UNIQUE ATTACKERS" 
          value={stats?.unique_attackers || 0} 
        />
        <StatCard 
          icon={<Shield size={32} />} 
          label="ACTIVE DECKIES" 
          value={`${stats?.active_deckies || 0} / ${stats?.deployed_deckies || 0}`} 
        />
      </div>

      <div className="logs-section">
        <div className="section-header">
          <Clock size={20} />
          <h2>LIVE INTERACTION LOG</h2>
        </div>
        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>DECKY</th>
                <th>SERVICE</th>
                <th>ATTACKER IP</th>
                <th>EVENT</th>
              </tr>
            </thead>
            <tbody>
              {logs.length > 0 ? logs.map(log => {
                let parsedFields: Record<string, string> = {};
                if (log.fields) {
                  try {
                    parsedFields = JSON.parse(log.fields);
                  } catch (e) {
                    // Ignore parsing errors
                  }
                }

                let msgHead: string | null = null;
                let msgTail: string | null = null;
                if (Object.keys(parsedFields).length === 0) {
                  const parsed = parseEventBody(log.msg);
                  parsedFields = parsed.fields;
                  msgHead = parsed.head;
                  msgTail = parsed.tail;
                } else if (log.msg && log.msg !== '-') {
                  msgTail = log.msg;
                }

                return (
                  <tr key={log.id}>
                    <td className="dim">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="violet-accent">{log.decky}</td>
                    <td className="matrix-text">{log.service}</td>
                    <td>{log.attacker_ip}</td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <div style={{ fontWeight: 'bold', color: 'var(--text-color)' }}>
                          {(() => {
                            const et = log.event_type && log.event_type !== '-' ? log.event_type : null;
                            const parts = [et, msgHead].filter(Boolean) as string[];
                            return (
                              <>
                                {parts.join(' · ')}
                                {msgTail && <span style={{ fontWeight: 'normal', opacity: 0.8 }}>{parts.length ? ' — ' : ''}{msgTail}</span>}
                              </>
                            );
                          })()}
                        </div>
                        {(Object.keys(parsedFields).length > 0 || parsedFields.stored_as) && (
                          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                            {parsedFields.stored_as && (
                              <button
                                onClick={() => setArtifact({
                                  decky: log.decky,
                                  storedAs: String(parsedFields.stored_as),
                                  fields: parsedFields,
                                })}
                                title="Inspect captured artifact"
                                style={{
                                  display: 'flex', alignItems: 'center', gap: '6px',
                                  fontSize: '0.7rem',
                                  backgroundColor: 'rgba(255, 170, 0, 0.1)',
                                  padding: '2px 8px',
                                  borderRadius: '4px',
                                  border: '1px solid rgba(255, 170, 0, 0.5)',
                                  color: '#ffaa00',
                                  cursor: 'pointer',
                                }}
                              >
                                <Paperclip size={11} /> ARTIFACT
                              </button>
                            )}
                            {Object.entries(parsedFields)
                              .filter(([k]) => k !== 'meta_json_b64')
                              .map(([k, v]) => (
                              <span key={k} style={{
                                fontSize: '0.7rem',
                                backgroundColor: 'rgba(0, 255, 65, 0.1)',
                                padding: '2px 8px',
                                borderRadius: '4px',
                                border: '1px solid rgba(0, 255, 65, 0.3)',
                                wordBreak: 'break-all'
                              }}>
                                <span style={{ opacity: 0.6 }}>{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : v}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan={5} style={{textAlign: 'center', padding: '40px'}}>NO INTERACTION DETECTED</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      {artifact && (
        <ArtifactDrawer
          decky={artifact.decky}
          storedAs={artifact.storedAs}
          fields={artifact.fields}
          onClose={() => setArtifact(null)}
        />
      )}
    </div>
  );
};

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
}

const StatCard: React.FC<StatCardProps> = ({ icon, label, value }) => (
  <div className="stat-card">
    <div className="stat-icon">{icon}</div>
    <div className="stat-content">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value.toLocaleString()}</span>
    </div>
  </div>
);

export default Dashboard;
