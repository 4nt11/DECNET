import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, ChevronLeft, ChevronRight, Crosshair, Fingerprint, Shield, Clock, Wifi, Lock, FileKey } from 'lucide-react';
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

// ─── Fingerprint rendering ───────────────────────────────────────────────────

const fpTypeLabel: Record<string, string> = {
  ja3: 'TLS FINGERPRINT',
  ja4l: 'LATENCY (JA4L)',
  tls_resumption: 'SESSION RESUMPTION',
  tls_certificate: 'CERTIFICATE',
  http_useragent: 'HTTP USER-AGENT',
  vnc_client_version: 'VNC CLIENT',
  jarm: 'JARM',
  hassh_server: 'HASSH SERVER',
  tcpfp: 'TCP/IP STACK',
};

const fpTypeIcon: Record<string, React.ReactNode> = {
  ja3: <Fingerprint size={14} />,
  ja4l: <Clock size={14} />,
  tls_resumption: <Wifi size={14} />,
  tls_certificate: <FileKey size={14} />,
  http_useragent: <Shield size={14} />,
  vnc_client_version: <Lock size={14} />,
  jarm: <Crosshair size={14} />,
  hassh_server: <Lock size={14} />,
  tcpfp: <Wifi size={14} />,
};

function getPayload(bounty: any): any {
  if (bounty?.payload && typeof bounty.payload === 'object') return bounty.payload;
  if (bounty?.payload && typeof bounty.payload === 'string') {
    try { return JSON.parse(bounty.payload); } catch { return bounty; }
  }
  return bounty;
}

const HashRow: React.FC<{ label: string; value?: string | null }> = ({ label, value }) => {
  if (!value) return null;
  return (
    <div style={{ display: 'flex', gap: '8px', alignItems: 'baseline' }}>
      <span className="dim" style={{ fontSize: '0.7rem', minWidth: '36px' }}>{label}</span>
      <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all' }}>
        {value}
      </span>
    </div>
  );
};

const Tag: React.FC<{ children: React.ReactNode; color?: string }> = ({ children, color }) => (
  <span style={{
    fontSize: '0.7rem', padding: '2px 8px', letterSpacing: '1px',
    border: `1px solid ${color || 'var(--text-color)'}`,
    color: color || 'var(--text-color)',
    background: `${color || 'var(--text-color)'}15`,
  }}>
    {children}
  </span>
);

const FpTlsHashes: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
    <HashRow label="JA3" value={p.ja3} />
    <HashRow label="JA3S" value={p.ja3s} />
    <HashRow label="JA4" value={p.ja4} />
    <HashRow label="JA4S" value={p.ja4s} />
    {(p.tls_version || p.sni || p.alpn) && (
      <div style={{ display: 'flex', gap: '8px', marginTop: '4px', flexWrap: 'wrap' }}>
        {p.tls_version && <Tag>{p.tls_version}</Tag>}
        {p.sni && <Tag color="var(--accent-color)">SNI: {p.sni}</Tag>}
        {p.alpn && <Tag>ALPN: {p.alpn}</Tag>}
        {p.dst_port && <Tag>:{p.dst_port}</Tag>}
      </div>
    )}
  </div>
);

const FpLatency: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
    <div>
      <span className="dim" style={{ fontSize: '0.7rem' }}>RTT </span>
      <span className="matrix-text" style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>
        {p.rtt_ms}
      </span>
      <span className="dim" style={{ fontSize: '0.7rem' }}> ms</span>
    </div>
    {p.client_ttl && (
      <div>
        <span className="dim" style={{ fontSize: '0.7rem' }}>TTL </span>
        <span className="matrix-text" style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>
          {p.client_ttl}
        </span>
      </div>
    )}
  </div>
);

const FpResumption: React.FC<{ p: any }> = ({ p }) => {
  const mechanisms = typeof p.mechanisms === 'string'
    ? p.mechanisms.split(',')
    : Array.isArray(p.mechanisms) ? p.mechanisms : [];
  return (
    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
      {mechanisms.map((m: string) => (
        <Tag key={m} color="var(--accent-color)">{m.trim().toUpperCase().replace(/_/g, ' ')}</Tag>
      ))}
    </div>
  );
};

const FpCertificate: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
      <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
        {p.subject_cn}
      </span>
      {p.self_signed === 'true' && (
        <Tag color="#ff6b6b">SELF-SIGNED</Tag>
      )}
    </div>
    {p.issuer && (
      <div>
        <span className="dim" style={{ fontSize: '0.7rem' }}>ISSUER: </span>
        <span style={{ fontSize: '0.8rem' }}>{p.issuer}</span>
      </div>
    )}
    {(p.not_before || p.not_after) && (
      <div>
        <span className="dim" style={{ fontSize: '0.7rem' }}>VALIDITY: </span>
        <span style={{ fontSize: '0.75rem', fontFamily: 'monospace' }}>
          {p.not_before || '?'} — {p.not_after || '?'}
        </span>
      </div>
    )}
    {p.sans && (
      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '2px' }}>
        <span className="dim" style={{ fontSize: '0.7rem' }}>SANs: </span>
        {(typeof p.sans === 'string' ? p.sans.split(',') : p.sans).map((san: string) => (
          <Tag key={san}>{san.trim()}</Tag>
        ))}
      </div>
    )}
  </div>
);

const FpJarm: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
    <HashRow label="HASH" value={p.hash} />
    {(p.target_ip || p.target_port) && (
      <div style={{ display: 'flex', gap: '8px', marginTop: '4px', flexWrap: 'wrap' }}>
        {p.target_ip && <Tag color="var(--accent-color)">{p.target_ip}</Tag>}
        {p.target_port && <Tag>:{p.target_port}</Tag>}
      </div>
    )}
  </div>
);

const FpHassh: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
    <HashRow label="HASH" value={p.hash} />
    {p.ssh_banner && (
      <div>
        <span className="dim" style={{ fontSize: '0.7rem' }}>BANNER: </span>
        <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{p.ssh_banner}</span>
      </div>
    )}
    {p.kex_algorithms && (
      <details style={{ marginTop: '2px' }}>
        <summary className="dim" style={{ fontSize: '0.7rem', cursor: 'pointer', letterSpacing: '1px' }}>
          KEX ALGORITHMS
        </summary>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
          {p.kex_algorithms.split(',').map((algo: string) => (
            <Tag key={algo}>{algo.trim()}</Tag>
          ))}
        </div>
      </details>
    )}
    {p.encryption_s2c && (
      <details>
        <summary className="dim" style={{ fontSize: '0.7rem', cursor: 'pointer', letterSpacing: '1px' }}>
          ENCRYPTION (S→C)
        </summary>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
          {p.encryption_s2c.split(',').map((algo: string) => (
            <Tag key={algo}>{algo.trim()}</Tag>
          ))}
        </div>
      </details>
    )}
    {(p.target_ip || p.target_port) && (
      <div style={{ display: 'flex', gap: '8px', marginTop: '4px', flexWrap: 'wrap' }}>
        {p.target_ip && <Tag color="var(--accent-color)">{p.target_ip}</Tag>}
        {p.target_port && <Tag>:{p.target_port}</Tag>}
      </div>
    )}
  </div>
);

const FpTcpStack: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
    <HashRow label="HASH" value={p.hash} />
    <div style={{ display: 'flex', gap: '24px', alignItems: 'center', flexWrap: 'wrap' }}>
      {p.ttl && (
        <div>
          <span className="dim" style={{ fontSize: '0.7rem' }}>TTL </span>
          <span className="matrix-text" style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{p.ttl}</span>
        </div>
      )}
      {p.window_size && (
        <div>
          <span className="dim" style={{ fontSize: '0.7rem' }}>WIN </span>
          <span className="matrix-text" style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{p.window_size}</span>
        </div>
      )}
      {p.mss && (
        <div>
          <span className="dim" style={{ fontSize: '0.7rem' }}>MSS </span>
          <span className="matrix-text" style={{ fontSize: '1rem' }}>{p.mss}</span>
        </div>
      )}
    </div>
    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
      {p.df_bit === '1' && <Tag color="#ff6b6b">DF</Tag>}
      {p.sack_ok === '1' && <Tag>SACK</Tag>}
      {p.timestamp === '1' && <Tag>TS</Tag>}
      {p.window_scale && p.window_scale !== '-1' && <Tag>WSCALE:{p.window_scale}</Tag>}
    </div>
    {p.options_order && (
      <div>
        <span className="dim" style={{ fontSize: '0.7rem' }}>OPTS: </span>
        <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{p.options_order}</span>
      </div>
    )}
    {(p.target_ip || p.target_port) && (
      <div style={{ display: 'flex', gap: '8px', marginTop: '2px', flexWrap: 'wrap' }}>
        {p.target_ip && <Tag color="var(--accent-color)">{p.target_ip}</Tag>}
        {p.target_port && <Tag>:{p.target_port}</Tag>}
      </div>
    )}
  </div>
);

const FpGeneric: React.FC<{ p: any }> = ({ p }) => (
  <div>
    {p.value ? (
      <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
        {p.value}
      </span>
    ) : (
      <span className="dim" style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
        {JSON.stringify(p)}
      </span>
    )}
  </div>
);

const FingerprintGroup: React.FC<{ fpType: string; items: any[] }> = ({ fpType, items }) => {
  const label = fpTypeLabel[fpType] || fpType.toUpperCase().replace(/_/g, ' ');
  const icon = fpTypeIcon[fpType] || <Fingerprint size={14} />;

  return (
    <div style={{
      border: '1px solid var(--border-color)',
      padding: '12px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <span style={{ opacity: 0.6 }}>{icon}</span>
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>{label}</span>
        {items.length > 1 && (
          <span className="dim" style={{ fontSize: '0.7rem' }}>({items.length})</span>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {items.map((fp, i) => {
          const p = getPayload(fp);
          switch (fpType) {
            case 'ja3': return <FpTlsHashes key={i} p={p} />;
            case 'ja4l': return <FpLatency key={i} p={p} />;
            case 'tls_resumption': return <FpResumption key={i} p={p} />;
            case 'tls_certificate': return <FpCertificate key={i} p={p} />;
            case 'jarm': return <FpJarm key={i} p={p} />;
            case 'hassh_server': return <FpHassh key={i} p={p} />;
            case 'tcpfp': return <FpTcpStack key={i} p={p} />;
            default: return <FpGeneric key={i} p={p} />;
          }
        })}
      </div>
    </div>
  );
};

// ─── Main component ─────────────────────────────────────────────────────────

const AttackerDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [attacker, setAttacker] = useState<AttackerData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [serviceFilter, setServiceFilter] = useState<string | null>(null);

  // Commands pagination state
  const [commands, setCommands] = useState<AttackerData['commands']>([]);
  const [cmdTotal, setCmdTotal] = useState(0);
  const [cmdPage, setCmdPage] = useState(1);
  const cmdLimit = 50;

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

  useEffect(() => {
    if (!id) return;
    const fetchCommands = async () => {
      try {
        const offset = (cmdPage - 1) * cmdLimit;
        let url = `/attackers/${id}/commands?limit=${cmdLimit}&offset=${offset}`;
        if (serviceFilter) url += `&service=${encodeURIComponent(serviceFilter)}`;
        const res = await api.get(url);
        setCommands(res.data.data);
        setCmdTotal(res.data.total);
      } catch (err: any) {
        if (err.response?.status === 422) {
          alert("Fuck off.");
        }
        setCommands([]);
        setCmdTotal(0);
      }
    };
    fetchCommands();
  }, [id, cmdPage, serviceFilter]);

  // Reset command page when service filter changes
  useEffect(() => {
    setCmdPage(1);
  }, [serviceFilter]);

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
          {attacker.services.length > 0 ? attacker.services.map((svc) => {
            const isActive = serviceFilter === svc;
            return (
              <span
                key={svc}
                className="service-badge"
                style={{
                  fontSize: '0.85rem', padding: '4px 12px', cursor: 'pointer',
                  ...(isActive ? {
                    backgroundColor: 'var(--text-color)',
                    color: 'var(--bg-color)',
                    borderColor: 'var(--text-color)',
                  } : {}),
                }}
                onClick={() => setServiceFilter(isActive ? null : svc)}
                title={isActive ? 'Clear filter' : `Filter by ${svc.toUpperCase()}`}
              >
                {svc.toUpperCase()}
              </span>
            );
          }) : (
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
      {(() => {
        const cmdTotalPages = Math.ceil(cmdTotal / cmdLimit);
        return (
          <div className="logs-section">
            <div className="section-header" style={{ justifyContent: 'space-between' }}>
              <h2>COMMANDS ({cmdTotal}{serviceFilter ? ` ${serviceFilter.toUpperCase()}` : ''})</h2>
              {cmdTotalPages > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <span className="dim" style={{ fontSize: '0.8rem' }}>
                    Page {cmdPage} of {cmdTotalPages}
                  </span>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      disabled={cmdPage <= 1}
                      onClick={() => setCmdPage(cmdPage - 1)}
                      style={{ padding: '4px', border: '1px solid var(--border-color)', opacity: cmdPage <= 1 ? 0.3 : 1 }}
                    >
                      <ChevronLeft size={16} />
                    </button>
                    <button
                      disabled={cmdPage >= cmdTotalPages}
                      onClick={() => setCmdPage(cmdPage + 1)}
                      style={{ padding: '4px', border: '1px solid var(--border-color)', opacity: cmdPage >= cmdTotalPages ? 0.3 : 1 }}
                    >
                      <ChevronRight size={16} />
                    </button>
                  </div>
                </div>
              )}
            </div>
            {commands.length > 0 ? (
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
                    {commands.map((cmd, i) => (
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
                {serviceFilter ? `NO ${serviceFilter.toUpperCase()} COMMANDS CAPTURED` : 'NO COMMANDS CAPTURED'}
              </div>
            )}
          </div>
        );
      })()}

      {/* Fingerprints — grouped by type */}
      {(() => {
        const filteredFps = serviceFilter
          ? attacker.fingerprints.filter((fp) => {
              const p = getPayload(fp);
              return p.service === serviceFilter;
            })
          : attacker.fingerprints;

        // Group fingerprints by type
        const groups: Record<string, any[]> = {};
        filteredFps.forEach((fp) => {
          const p = getPayload(fp);
          const fpType: string = p.fingerprint_type || 'unknown';
          if (!groups[fpType]) groups[fpType] = [];
          groups[fpType].push(fp);
        });

        // Active probes first, then passive, then unknown
        const activeTypes = ['jarm', 'hassh_server', 'tcpfp'];
        const passiveTypes = ['ja3', 'ja4l', 'tls_resumption', 'tls_certificate', 'http_useragent', 'vnc_client_version'];
        const knownTypes = [...activeTypes, ...passiveTypes];
        const unknownTypes = Object.keys(groups).filter((t) => !knownTypes.includes(t));
        const orderedTypes = [...activeTypes, ...passiveTypes, ...unknownTypes].filter((t) => groups[t]);

        const hasActive = activeTypes.some((t) => groups[t]);
        const hasPassive = [...passiveTypes, ...unknownTypes].some((t) => groups[t]);

        return (
          <div className="logs-section">
            <div className="section-header">
              <h2>FINGERPRINTS ({filteredFps.length}{serviceFilter ? ` / ${attacker.fingerprints.length}` : ''})</h2>
            </div>
            {filteredFps.length > 0 ? (
              <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Active probes section */}
                {hasActive && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <Crosshair size={14} className="violet-accent" />
                      <span style={{ fontSize: '0.75rem', letterSpacing: '2px', opacity: 0.6 }}>ACTIVE PROBES</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {activeTypes.filter((t) => groups[t]).map((fpType) => (
                        <FingerprintGroup key={fpType} fpType={fpType} items={groups[fpType]} />
                      ))}
                    </div>
                  </div>
                )}

                {/* Passive fingerprints section */}
                {hasPassive && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <Fingerprint size={14} className="violet-accent" />
                      <span style={{ fontSize: '0.75rem', letterSpacing: '2px', opacity: 0.6 }}>PASSIVE FINGERPRINTS</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {[...passiveTypes, ...unknownTypes].filter((t) => groups[t]).map((fpType) => (
                        <FingerprintGroup key={fpType} fpType={fpType} items={groups[fpType]} />
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
                {serviceFilter ? `NO ${serviceFilter.toUpperCase()} FINGERPRINTS CAPTURED` : 'NO FINGERPRINTS CAPTURED'}
              </div>
            )}
          </div>
        );
      })()}

      {/* UUID footer */}
      <div style={{ textAlign: 'right', fontSize: '0.65rem', opacity: 0.3, marginTop: '8px' }}>
        UUID: {attacker.uuid}
      </div>
    </div>
  );
};

export default AttackerDetail;
