import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Activity, ArrowLeft, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Crosshair, Fingerprint, Shield, Clock, Wifi, Lock, FileKey, Radio, Timer, Paperclip, Terminal, Package, FileText, Mail, AtSign } from 'lucide-react';
import api from '../utils/api';
import ArtifactDrawer from './ArtifactDrawer';
import MailDrawer from './MailDrawer';
import SessionDrawer from './SessionDrawer';
import EmptyState from './EmptyState/EmptyState';
import './Dashboard.css';

interface AttackerBehavior {
  os_guess: string | null;
  hop_distance: number | null;
  tcp_fingerprint: {
    window?: number | null;
    wscale?: number | null;
    mss?: number | null;
    options_sig?: string;
    has_sack?: boolean;
    has_timestamps?: boolean;
  } | null;
  retransmit_count: number;
  behavior_class: string | null;
  beacon_interval_s: number | null;
  beacon_jitter_pct: number | null;
  tool_guesses: string[] | null;
  timing_stats: {
    event_count?: number;
    duration_s?: number;
    mean_iat_s?: number | null;
    median_iat_s?: number | null;
    stdev_iat_s?: number | null;
    min_iat_s?: number | null;
    max_iat_s?: number | null;
    cv?: number | null;
  } | null;
  phase_sequence: {
    recon_end_ts?: string | null;
    exfil_start_ts?: string | null;
    exfil_latency_s?: number | null;
    large_payload_count?: number;
  } | null;
  updated_at?: string;
}

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
  country_code: string | null;
  country_source: string | null;
  ptr_record: string | null;
  updated_at: string;
  behavior: AttackerBehavior | null;
  service_activity?: {
    interacted: string[];
    scanned: string[];
  };
  ip_leaks?: Array<{
    timestamp: string;
    decky?: string;
    service?: string;
    bounty_type: string;
    payload: {
      source_ip?: string;
      real_ip_claim?: string;
      source_header?: string;
      headers_seen?: Record<string, string>;
      path?: string;
      method?: string;
    };
  }>;
}

// ─── Fingerprint rendering ───────────────────────────────────────────────────

const fpTypeLabel: Record<string, string> = {
  ja3: 'TLS FINGERPRINT',
  ja4l: 'LATENCY (JA4L)',
  tls_resumption: 'SESSION RESUMPTION',
  tls_certificate: 'CERTIFICATE',
  http_useragent: 'HTTP USER-AGENT',
  http_quirks: 'HTTP HEADER QUIRKS',
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
  http_quirks: <Fingerprint size={14} />,
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

const FpHttpQuirks: React.FC<{ p: any }> = ({ p }) => {
  const order: string[] = Array.isArray(p.order) ? p.order : [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      <HashRow label="ORDER HASH" value={p.order_hash} />
      <HashRow label="CASING HASH" value={p.casing_hash} />
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {p.tool_guess && (
          <Tag color="var(--violet)">{String(p.tool_guess).toUpperCase()}</Tag>
        )}
        {p.casing_category && (
          <Tag>CASE · {String(p.casing_category).toUpperCase()}</Tag>
        )}
        {typeof p.header_count === 'number' && (
          <Tag>{p.header_count} HEADERS</Tag>
        )}
        {p.duplicates && (
          <Tag color="var(--warn, #e0a040)">DUPLICATES</Tag>
        )}
      </div>
      {order.length > 0 && (
        <details>
          <summary className="dim" style={{ fontSize: '0.7rem', cursor: 'pointer', letterSpacing: '1px' }}>
            HEADER ORDER
          </summary>
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
            {order.map((h, i) => (
              <Tag key={`${h}-${i}`}>{h}</Tag>
            ))}
          </div>
        </details>
      )}
      {(p.method || p.path) && (
        <div className="dim" style={{ fontSize: '0.7rem', fontFamily: 'monospace', marginTop: '2px' }}>
          {p.method} {p.path}
        </div>
      )}
    </div>
  );
};

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
            case 'http_quirks': return <FpHttpQuirks key={i} p={p} />;
            default: return <FpGeneric key={i} p={p} />;
          }
        })}
      </div>
    </div>
  );
};

// ─── Behavioral profile blocks ──────────────────────────────────────────────

const OS_LABELS: Record<string, string> = {
  linux: 'LINUX',
  windows: 'WINDOWS',
  macos_ios: 'macOS / iOS',
  freebsd: 'FREEBSD',
  openbsd: 'OPENBSD',
  embedded: 'EMBEDDED',
  nmap: 'NMAP (SCANNER)',
  unknown: 'UNKNOWN',
};

const BEHAVIOR_LABELS: Record<string, string> = {
  beaconing:   'BEACONING',
  interactive: 'INTERACTIVE',
  scanning:    'SCANNING',
  brute_force: 'BRUTE FORCE',
  slow_scan:   'SLOW SCAN',
  mixed:       'MIXED',
  unknown:     'UNKNOWN',
};

const BEHAVIOR_COLORS: Record<string, string> = {
  beaconing:   '#ff6b6b',
  interactive: 'var(--accent-color)',
  scanning:    '#e5c07b',
  brute_force: '#ff9f43',
  slow_scan:   '#c8a96e',
  mixed:       'var(--text-color)',
  unknown:     'var(--text-color)',
};

const TOOL_LABELS: Record<string, string> = {
  cobalt_strike: 'COBALT STRIKE',
  sliver: 'SLIVER',
  havoc: 'HAVOC',
  mythic: 'MYTHIC',
  nmap: 'NMAP',
  gophish: 'GOPHISH',
  nikto: 'NIKTO',
  sqlmap: 'SQLMAP',
  nuclei: 'NUCLEI',
  masscan: 'MASSCAN',
  zgrab: 'ZGRAB',
  metasploit: 'METASPLOIT',
  gobuster: 'GOBUSTER',
  dirbuster: 'DIRBUSTER',
  hydra: 'HYDRA',
  wfuzz: 'WFUZZ',
  curl: 'CURL',
  python_requests: 'PYTHON-REQUESTS',
};

const fmtOpt = (v: number | null | undefined): string =>
  v === null || v === undefined ? '—' : String(v);

const fmtSecs = (v: number | null | undefined): string => {
  if (v === null || v === undefined) return '—';
  if (v < 1) return `${(v * 1000).toFixed(0)} ms`;
  if (v < 60) return `${v.toFixed(2)} s`;
  if (v < 3600) return `${(v / 60).toFixed(2)} m`;
  return `${(v / 3600).toFixed(2)} h`;
};

const StatBlock: React.FC<{ label: string; value: React.ReactNode; color?: string }> = ({
  label, value, color,
}) => (
  <div className="stat-card">
    <div className="stat-value" style={{ color: color || 'var(--text-color)' }}>
      {value}
    </div>
    <div className="stat-label">{label}</div>
  </div>
);

const KeyValueRow: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div style={{ display: 'flex', gap: '12px', alignItems: 'baseline' }}>
    <span className="dim" style={{ fontSize: '0.7rem', letterSpacing: '1px', minWidth: '120px' }}>
      {label}
    </span>
    <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
      {value}
    </span>
  </div>
);

// Tools detected via beacon timing (C2 frameworks).
const _C2_TOOLS = new Set(['cobalt_strike', 'sliver', 'havoc', 'mythic']);

const BehaviorHeadline: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const osLabel = b.os_guess ? (OS_LABELS[b.os_guess] || b.os_guess.toUpperCase()) : '—';
  const behaviorLabel = b.behavior_class
    ? (BEHAVIOR_LABELS[b.behavior_class] || b.behavior_class.toUpperCase())
    : 'UNKNOWN';
  const behaviorColor = b.behavior_class ? BEHAVIOR_COLORS[b.behavior_class] : undefined;
  return (
    <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
      <StatBlock label="OS GUESS" value={osLabel} />
      <StatBlock label="HOP DISTANCE" value={fmtOpt(b.hop_distance)} />
      <StatBlock label="ATTACK PATTERN" value={behaviorLabel} color={behaviorColor} />
    </div>
  );
};

const DetectedToolsBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const tools = b.tool_guesses && b.tool_guesses.length > 0 ? b.tool_guesses : null;
  if (!tools) return null;
  return (
    <div style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Crosshair size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          DETECTED TOOLS
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {tools.map(t => (
          <div key={t} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span
              style={{
                fontSize: '0.8rem',
                fontFamily: 'monospace',
                fontWeight: 'bold',
                color: '#ff6b6b',
                minWidth: '160px',
              }}
            >
              {TOOL_LABELS[t] || t.toUpperCase()}
            </span>
            <span
              style={{
                fontSize: '0.65rem',
                fontFamily: 'monospace',
                letterSpacing: '1px',
                color: 'var(--dim-color)',
                border: '1px solid var(--border-color)',
                borderRadius: '2px',
                padding: '1px 6px',
              }}
            >
              {_C2_TOOLS.has(t) ? 'BEACON TIMING' : 'HTTP HEADER'}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

const BeaconBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  if (b.behavior_class !== 'beaconing' || b.beacon_interval_s === null) return null;
  return (
    <div style={{
      border: '1px solid var(--border-color)', padding: '12px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Radio size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          BEACON CADENCE
        </span>
      </div>
      <div style={{ display: 'flex', gap: '32px', alignItems: 'baseline' }}>
        <div>
          <span className="dim" style={{ fontSize: '0.7rem' }}>INTERVAL </span>
          <span className="matrix-text" style={{ fontSize: '1.3rem', fontWeight: 'bold' }}>
            {fmtSecs(b.beacon_interval_s)}
          </span>
        </div>
        {b.beacon_jitter_pct !== null && (
          <div>
            <span className="dim" style={{ fontSize: '0.7rem' }}>JITTER </span>
            <span className="matrix-text" style={{ fontSize: '1.3rem', fontWeight: 'bold' }}>
              {b.beacon_jitter_pct.toFixed(1)}%
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

const TcpStackBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const fp = b.tcp_fingerprint;
  if (!fp || (!fp.window && !fp.mss && !fp.options_sig)) return null;
  return (
    <div style={{
      border: '1px solid var(--border-color)', padding: '12px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Wifi size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          TCP STACK (PASSIVE)
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
          {fp.window !== null && fp.window !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>WIN </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>
                {fp.window}
              </span>
            </div>
          )}
          {fp.wscale !== null && fp.wscale !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>WSCALE </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>
                {fp.wscale}
              </span>
            </div>
          )}
          {fp.mss !== null && fp.mss !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>MSS </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem' }}>{fp.mss}</span>
            </div>
          )}
          <div>
            <span className="dim" style={{ fontSize: '0.7rem' }}>RETRANSMITS </span>
            <span
              className="matrix-text"
              style={{
                fontSize: '1.1rem',
                fontWeight: 'bold',
                color: b.retransmit_count > 0 ? '#e5c07b' : undefined,
              }}
            >
              {b.retransmit_count}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {fp.has_sack && <Tag>SACK</Tag>}
          {fp.has_timestamps && <Tag>TS</Tag>}
        </div>
        {fp.options_sig && (
          <div>
            <span className="dim" style={{ fontSize: '0.7rem' }}>OPTS: </span>
            <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {fp.options_sig}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

const TimingStatsBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const s = b.timing_stats;
  if (!s || !s.event_count || s.event_count < 2) return null;
  return (
    <div style={{
      border: '1px solid var(--border-color)', padding: '12px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Timer size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          INTER-EVENT TIMING
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <KeyValueRow label="EVENT COUNT" value={s.event_count ?? '—'} />
        <KeyValueRow label="DURATION" value={fmtSecs(s.duration_s)} />
        <KeyValueRow label="MEAN IAT" value={fmtSecs(s.mean_iat_s)} />
        <KeyValueRow label="MEDIAN IAT" value={fmtSecs(s.median_iat_s)} />
        <KeyValueRow label="STDEV IAT" value={fmtSecs(s.stdev_iat_s)} />
        <KeyValueRow
          label="MIN / MAX IAT"
          value={`${fmtSecs(s.min_iat_s)} / ${fmtSecs(s.max_iat_s)}`}
        />
        <KeyValueRow
          label="CV (JITTER)"
          value={s.cv !== null && s.cv !== undefined ? s.cv.toFixed(3) : '—'}
        />
      </div>
    </div>
  );
};

const PhaseSequenceBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const p = b.phase_sequence;
  if (!p || (!p.recon_end_ts && !p.exfil_start_ts && !p.large_payload_count)) return null;
  return (
    <div style={{
      border: '1px solid var(--border-color)', padding: '12px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Activity size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          PHASE SEQUENCE
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <KeyValueRow
          label="RECON END"
          value={p.recon_end_ts ? new Date(p.recon_end_ts).toLocaleString() : '—'}
        />
        <KeyValueRow
          label="EXFIL START"
          value={p.exfil_start_ts ? new Date(p.exfil_start_ts).toLocaleString() : '—'}
        />
        <KeyValueRow label="RECON→EXFIL LATENCY" value={fmtSecs(p.exfil_latency_s)} />
        <KeyValueRow
          label="LARGE PAYLOADS"
          value={p.large_payload_count ?? 0}
        />
      </div>
    </div>
  );
};

// ─── Collapsible section ────────────────────────────────────────────────────

const Section: React.FC<{
  title: React.ReactNode;
  right?: React.ReactNode;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}> = ({ title, right, open, onToggle, children }) => (
  <div className="logs-section">
    <div
      className="section-header"
      style={{ justifyContent: 'space-between', cursor: 'pointer', userSelect: 'none' }}
      onClick={onToggle}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        {open ? <ChevronUp size={16} className="dim" /> : <ChevronDown size={16} className="dim" />}
        <h2>{title}</h2>
      </div>
      {right && <div onClick={(e) => e.stopPropagation()}>{right}</div>}
    </div>
    {open && children}
  </div>
);

// ─── Main component ─────────────────────────────────────────────────────────

const AttackerDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [attacker, setAttacker] = useState<AttackerData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [serviceFilter, setServiceFilter] = useState<string | null>(null);

  // Section collapse state
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    timeline: true,
    services: true,
    deckies: true,
    behavior: true,
    commands: true,
    fingerprints: true,
    artifacts: true,
    sessions: true,
    smtpTargets: true,
    mail: true,
  });

  // Captured file-drop artifacts (ssh inotify farm) for this attacker.
  type ArtifactLog = {
    id: number;
    timestamp: string;
    decky: string;
    service: string;
    fields: string; // JSON-encoded SD params (parsed lazily below)
  };
  const [artifacts, setArtifacts] = useState<ArtifactLog[]>([]);
  const [artifact, setArtifact] = useState<{ decky: string; storedAs: string; fields: Record<string, any> } | null>(null);

  // PTY session transcripts (sessrec) for this attacker.
  type SessionLog = {
    id: number;
    timestamp: string;
    decky: string;
    service: string;
    fields: string;
  };
  const [sessions, setSessions] = useState<SessionLog[]>([]);
  const [session, setSession] = useState<{ decky: string; sid: string; fields: Record<string, any> } | null>(null);

  // SMTP victim-domain rollup (viewer-safe: domains only, no local parts).
  type SmtpTargetRow = {
    domain: string;
    count: number;
    first_seen: string;
    last_seen: string;
  };
  const [smtpTargets, setSmtpTargets] = useState<SmtpTargetRow[]>([]);

  // Stored SMTP messages (admin-gated: full attacker-controlled bodies).
  type MailLog = {
    id: number;
    timestamp: string;
    decky: string;
    service: string;
    fields: string;
  };
  const [mail, setMail] = useState<MailLog[]>([]);
  const [mailForbidden, setMailForbidden] = useState(false);
  const [mailItem, setMailItem] = useState<{ decky: string; storedAs: string; fields: Record<string, any> } | null>(null);

  const toggle = (key: string) => setOpenSections((prev) => ({ ...prev, [key]: !prev[key] }));

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

  useEffect(() => {
    if (!id) return;
    const fetchArtifacts = async () => {
      try {
        const res = await api.get(`/attackers/${id}/artifacts`);
        setArtifacts(res.data.data ?? []);
      } catch {
        setArtifacts([]);
      }
    };
    fetchArtifacts();
  }, [id]);

  useEffect(() => {
    if (!id) return;
    const fetchSmtpTargets = async () => {
      try {
        const res = await api.get(`/attackers/${id}/smtp-targets`);
        setSmtpTargets(res.data.data ?? []);
      } catch {
        setSmtpTargets([]);
      }
    };
    fetchSmtpTargets();
  }, [id]);

  useEffect(() => {
    if (!id) return;
    const fetchMail = async () => {
      try {
        const res = await api.get(`/attackers/${id}/mail`);
        setMail(res.data.data ?? []);
        setMailForbidden(false);
      } catch (err: any) {
        setMail([]);
        setMailForbidden(err?.response?.status === 403);
      }
    };
    fetchMail();
  }, [id]);

  useEffect(() => {
    if (!id) return;
    const fetchSessions = async () => {
      try {
        const res = await api.get(`/attackers/${id}/transcripts`);
        setSessions(res.data.data ?? []);
      } catch {
        setSessions([]);
      }
    };
    fetchSessions();
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
        {attacker.country_code && (
          <Tag color="var(--text-color)">
            <span
              title={attacker.country_source ? `source: ${attacker.country_source}` : undefined}
              style={{ letterSpacing: '2px' }}
            >
              {attacker.country_code}
            </span>
          </Tag>
        )}
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

      {/* Scanned vs. Interacted — activity-depth signal */}
      {attacker.service_activity &&
        (attacker.service_activity.scanned.length > 0 ||
         attacker.service_activity.interacted.length > 0) && (
        <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)' }}>
          <div
            className="stat-card"
            title={
              attacker.service_activity.scanned.length > 0
                ? `Services: ${attacker.service_activity.scanned.join(', ')}`
                : 'No services were scanned without engagement.'
            }
          >
            <div className="stat-value matrix-text">
              {attacker.service_activity.scanned.length}
            </div>
            <div className="stat-label">SCANNED · SERVICES</div>
          </div>
          <div
            className="stat-card"
            title={
              attacker.service_activity.interacted.length > 0
                ? `Services: ${attacker.service_activity.interacted.join(', ')}`
                : 'No services were interacted with — scan-only attacker.'
            }
          >
            <div className="stat-value violet-accent">
              {attacker.service_activity.interacted.length}
            </div>
            <div className="stat-label">INTERACTED WITH · SERVICES</div>
          </div>
        </div>
      )}

      {/* Timestamps */}
      <Section title="TIMELINE" open={openSections.timeline} onToggle={() => toggle('timeline')}>
        <div style={{ padding: '16px', display: 'flex', flexWrap: 'wrap', gap: '32px', fontSize: '0.85rem' }}>
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
          <div>
            <span className="dim">ORIGIN: </span>
            {attacker.country_code ? (
              <span className="matrix-text">
                {attacker.country_code}
                {attacker.country_source && (
                  <span className="dim" style={{ marginLeft: 6, fontSize: '0.75rem' }}>
                    ({attacker.country_source})
                  </span>
                )}
              </span>
            ) : (
              <span className="dim">unknown</span>
            )}
          </div>
          <div>
            <span className="dim">REVERSE DNS: </span>
            {attacker.ptr_record ? (
              <span
                className="matrix-text"
                style={{ fontFamily: 'monospace' }}
                title="One-shot PTR record resolved at first sighting."
              >
                {attacker.ptr_record}
              </span>
            ) : (
              <span className="dim">—</span>
            )}
          </div>
          {attacker.ip_leaks && attacker.ip_leaks.length > 0 && (
            <div>
              <span className="dim" style={{ color: 'var(--warn, #e0a040)' }}>
                LEAKED IPs:{' '}
              </span>
              {Array.from(
                new Set(
                  (attacker.ip_leaks || [])
                    .map((l) => l.payload?.real_ip_claim)
                    .filter((v): v is string => !!v),
                ),
              ).map((ip, i, arr) => {
                const latest = (attacker.ip_leaks || []).find(
                  (l) => l.payload?.real_ip_claim === ip,
                );
                const tooltip = latest
                  ? `${latest.payload.source_header ?? '?'} on ${
                      latest.payload.method ?? '?'
                    } ${latest.payload.path ?? '/'}`
                  : '';
                return (
                  <span
                    key={ip}
                    style={{
                      color: 'var(--warn, #e0a040)',
                      fontFamily: 'monospace',
                    }}
                    title={tooltip}
                  >
                    {ip}
                    {i < arr.length - 1 ? ', ' : ''}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </Section>

      {/* Services */}
      <Section title="SERVICES TARGETED" open={openSections.services} onToggle={() => toggle('services')}>
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
      </Section>

      {/* Deckies & Traversal */}
      <Section title="DECKY INTERACTIONS" open={openSections.deckies} onToggle={() => toggle('deckies')}>
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
      </Section>

      {/* Behavioral Profile */}
      <Section
        title="BEHAVIORAL PROFILE"
        open={openSections.behavior}
        onToggle={() => toggle('behavior')}
      >
        {attacker.behavior ? (
          <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <BehaviorHeadline b={attacker.behavior} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <BeaconBlock b={attacker.behavior} />
              <DetectedToolsBlock b={attacker.behavior} />
              <TcpStackBlock b={attacker.behavior} />
              <TimingStatsBlock b={attacker.behavior} />
              <PhaseSequenceBlock b={attacker.behavior} />
            </div>
          </div>
        ) : (
          <EmptyState
            icon={Activity}
            title="NO BEHAVIORAL DATA YET"
            hint="profiler has not run for this attacker"
            size="compact"
          />
        )}
      </Section>

      {/* Commands */}
      {(() => {
        const cmdTotalPages = Math.ceil(cmdTotal / cmdLimit);
        return (
          <Section
            title={<>COMMANDS ({cmdTotal}{serviceFilter ? ` ${serviceFilter.toUpperCase()}` : ''})</>}
            open={openSections.commands}
            onToggle={() => toggle('commands')}
            right={openSections.commands && cmdTotalPages > 1 ? (
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
            ) : undefined}
          >
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
              <EmptyState
                icon={Terminal}
                title={serviceFilter ? `NO ${serviceFilter.toUpperCase()} COMMANDS CAPTURED` : 'NO COMMANDS CAPTURED'}
                size="compact"
              />
            )}
          </Section>
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
        const passiveTypes = ['ja3', 'ja4l', 'tls_resumption', 'tls_certificate', 'http_useragent', 'http_quirks', 'vnc_client_version'];
        const knownTypes = [...activeTypes, ...passiveTypes];
        const unknownTypes = Object.keys(groups).filter((t) => !knownTypes.includes(t));

        const hasActive = activeTypes.some((t) => groups[t]);
        const hasPassive = [...passiveTypes, ...unknownTypes].some((t) => groups[t]);

        return (
          <Section
            title={<>FINGERPRINTS ({filteredFps.length}{serviceFilter ? ` / ${attacker.fingerprints.length}` : ''})</>}
            open={openSections.fingerprints}
            onToggle={() => toggle('fingerprints')}
          >
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
          </Section>
        );
      })()}

      {/* Captured Artifacts */}
      <Section
        title={<>CAPTURED ARTIFACTS ({artifacts.length})</>}
        open={openSections.artifacts}
        onToggle={() => toggle('artifacts')}
      >
        {artifacts.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>DECKY</th>
                  <th>FILENAME</th>
                  <th>SIZE</th>
                  <th>SHA-256</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {artifacts.map((row) => {
                  let fields: Record<string, any> = {};
                  try { fields = JSON.parse(row.fields || '{}'); } catch {}
                  const storedAs = fields.stored_as ? String(fields.stored_as) : null;
                  const sha = fields.sha256 ? String(fields.sha256) : '';
                  return (
                    <tr key={row.id}>
                      <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {new Date(row.timestamp).toLocaleString()}
                      </td>
                      <td className="violet-accent">{row.decky}</td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {fields.orig_path ?? storedAs ?? '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {fields.size ? `${fields.size} B` : '—'}
                      </td>
                      <td className="dim" style={{ fontFamily: 'monospace', fontSize: '0.7rem' }}>
                        {sha ? `${sha.slice(0, 12)}…` : '—'}
                      </td>
                      <td>
                        {storedAs && (
                          <button
                            onClick={() => setArtifact({ decky: row.decky, storedAs, fields })}
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
                            <Paperclip size={11} /> OPEN
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={Package}
            title="NO ARTIFACTS CAPTURED"
            size="compact"
          />
        )}
      </Section>

      {artifact && (
        <ArtifactDrawer
          decky={artifact.decky}
          storedAs={artifact.storedAs}
          fields={artifact.fields}
          onClose={() => setArtifact(null)}
        />
      )}

      {/* SMTP Victim Domains (viewer-safe rollup) */}
      <Section
        title={<>SMTP VICTIM DOMAINS ({smtpTargets.length})</>}
        open={openSections.smtpTargets}
        onToggle={() => toggle('smtpTargets')}
      >
        {smtpTargets.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>DOMAIN</th>
                  <th>COUNT</th>
                  <th>FIRST SEEN</th>
                  <th>LAST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {smtpTargets.map((row) => (
                  <tr key={row.domain}>
                    <td className="matrix-text" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {row.domain}
                    </td>
                    <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                      {row.count}
                    </td>
                    <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {new Date(row.first_seen).toLocaleString()}
                    </td>
                    <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {new Date(row.last_seen).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={AtSign}
            title="NO SMTP VICTIMS OBSERVED"
            size="compact"
          />
        )}
      </Section>

      {/* Stored Mail (admin only — bodies are attacker-controlled) */}
      <Section
        title={<>STORED MAIL ({mail.length})</>}
        open={openSections.mail}
        onToggle={() => toggle('mail')}
      >
        {mailForbidden ? (
          <EmptyState
            icon={Mail}
            title="ADMIN ROLE REQUIRED"
            size="compact"
          />
        ) : mail.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>DECKY</th>
                  <th>SUBJECT</th>
                  <th>FROM</th>
                  <th>SIZE</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {mail.map((row) => {
                  let fields: Record<string, any> = {};
                  try { fields = JSON.parse(row.fields || '{}'); } catch {}
                  const storedAs = fields.stored_as ? String(fields.stored_as) : null;
                  return (
                    <tr key={row.id}>
                      <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {new Date(row.timestamp).toLocaleString()}
                      </td>
                      <td className="violet-accent">{row.decky}</td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {fields.subject || '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {fields.from_addr || fields.mail_from || '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {fields.size ? `${fields.size} B` : '—'}
                      </td>
                      <td>
                        {storedAs && (
                          <button
                            onClick={() => setMailItem({ decky: row.decky, storedAs, fields })}
                            title="Inspect stored message"
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
                            <Mail size={11} /> OPEN
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={Mail}
            title="NO MAIL STORED"
            size="compact"
          />
        )}
      </Section>

      {mailItem && (
        <MailDrawer
          decky={mailItem.decky}
          storedAs={mailItem.storedAs}
          fields={mailItem.fields}
          onClose={() => setMailItem(null)}
        />
      )}

      {/* Recorded PTY Sessions (SSH / Telnet) */}
      <Section
        title={<>SESSION TRANSCRIPTS ({sessions.length})</>}
        open={openSections.sessions}
        onToggle={() => toggle('sessions')}
      >
        {sessions.length > 0 ? (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>DECKY</th>
                  <th>SERVICE</th>
                  <th>DURATION</th>
                  <th>BYTES</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((row) => {
                  let fields: Record<string, any> = {};
                  try { fields = JSON.parse(row.fields || '{}'); } catch {}
                  const sid = fields.sid ? String(fields.sid) : null;
                  const dur = fields.duration_s;
                  const bytes = fields.bytes;
                  return (
                    <tr key={row.id}>
                      <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {new Date(row.timestamp).toLocaleString()}
                      </td>
                      <td className="violet-accent">{row.decky}</td>
                      <td className="matrix-text">{fields.service ?? row.service}</td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {dur ? `${dur}s` : '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {bytes ? `${bytes} B` : '—'}
                      </td>
                      <td>
                        {sid && (
                          <button
                            onClick={() => setSession({ decky: row.decky, sid, fields })}
                            title="Replay recorded session"
                            style={{
                              display: 'flex', alignItems: 'center', gap: '6px',
                              fontSize: '0.7rem',
                              backgroundColor: 'rgba(0, 200, 255, 0.1)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              border: '1px solid rgba(0, 200, 255, 0.5)',
                              color: '#00c8ff',
                              cursor: 'pointer',
                            }}
                          >
                            REPLAY
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={FileText}
            title="NO SESSION TRANSCRIPTS RECORDED"
            size="compact"
          />
        )}
      </Section>

      {session && (
        <SessionDrawer
          decky={session.decky}
          sid={session.sid}
          fields={session.fields}
          onClose={() => setSession(null)}
        />
      )}

      {/* UUID footer */}
      <div style={{ textAlign: 'right', fontSize: '0.65rem', opacity: 0.3, marginTop: '8px' }}>
        UUID: {attacker.uuid}
      </div>
    </div>
  );
};

export default AttackerDetail;
