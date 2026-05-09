import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowLeft, Cpu, Crosshair, Eye, Fingerprint, Globe, Keyboard, Shield, Clock, Sparkles, Wifi, Lock, FileKey, Radio, Timer, Paperclip, Package, FileText, Mail, AtSign } from '../icons';
import api from '../utils/api';
import ArtifactDrawer from './ArtifactDrawer';
import MailDrawer from './MailDrawer';
import SessionDrawer from './SessionDrawer';
import EmptyState from './EmptyState/EmptyState';
import TTPsObservedSection from './TTPsObservedSection';
import { useAttackerDetail } from './AttackerDetail/useAttackerDetail';
import { AttackerHeader } from './AttackerDetail/sections/AttackerHeader';
import { AttackerStats } from './AttackerDetail/sections/AttackerStats';
import { TimelineSection } from './AttackerDetail/sections/TimelineSection';
import { ServicesTargeted } from './AttackerDetail/sections/ServicesTargeted';
import { CommandsViewer } from './AttackerDetail/sections/CommandsViewer';
import { Tag, Section } from './AttackerDetail/ui';
import type {
  AttackerBehavior,
  BehaviouralObservation,
  AttributionPrimitiveState,
} from './AttackerDetail/types';
import './Dashboard.css';

// Re-export the types historically exposed from this module so external
// importers (tests, future siblings) keep their import paths stable
// while the canonical definitions live in ./AttackerDetail/types.
export type { BehaviouralObservation, AttributionPrimitiveState };


// ─── Fingerprint rendering ───────────────────────────────────────────────────

const fpTypeLabel: Record<string, string> = {
  ja3: 'TLS FINGERPRINT',
  ja4l: 'LATENCY (JA4L)',
  tls_resumption: 'SESSION RESUMPTION',
  tls_certificate: 'CERTIFICATE',
  tls_certificate_active: 'CERTIFICATE (ACTIVE PROBE)',
  tls_certificate_passive: 'CERTIFICATE',
  http_useragent: 'HTTP USER-AGENT',
  http_quirks: 'HTTP HEADER QUIRKS',
  spoofed_source: 'SPOOFED SOURCE IP',
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
  tls_certificate_active: <FileKey size={14} />,
  tls_certificate_passive: <FileKey size={14} />,
  http_useragent: <Shield size={14} />,
  http_quirks: <Fingerprint size={14} />,
  spoofed_source: <Crosshair size={14} />,
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

// Random ISN/IP-ID is the modern default; non-random patterns are
// fingerprinting gold (legacy stacks, custom raw-socket tools).
const seqClassColor = (cls: string): string | undefined => {
  switch (cls) {
    case 'random':      return undefined;        // neutral, expected
    case 'incremental': return '#e5c07b';        // amber — uncommon
    case 'zero':
    case 'constant':    return '#98c379';        // green — strong signal
    default:            return undefined;
  }
};

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
    {p.cert_sha256 && (
      <div>
        <span className="dim" style={{ fontSize: '0.7rem' }}>SHA-256: </span>
        <span style={{ fontSize: '0.75rem', fontFamily: 'monospace' }} title={p.cert_sha256}>
          {p.cert_sha256.slice(0, 16)}…{p.cert_sha256.slice(-8)}
        </span>
      </div>
    )}
    {p.target_ip && (
      <div>
        <span className="dim" style={{ fontSize: '0.7rem' }}>FROM: </span>
        <span style={{ fontSize: '0.75rem', fontFamily: 'monospace' }}>
          {p.target_ip}{p.target_port ? `:${p.target_port}` : ''}
        </span>
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

const UA_CATEGORY_COLOR: Record<string, string> = {
  scanner: 'var(--alert, #ff4d4d)',
  nonstandard: 'var(--warn, #e0a040)',
  empty: 'var(--warn, #e0a040)',
  bot: 'var(--violet)',
  cli: 'var(--matrix)',
  library: 'var(--matrix)',
  browser: 'var(--accent-color)',
};

const UA_SIGNAL_COLOR: Record<string, string> = {
  injection_like: 'var(--alert, #ff4d4d)',
  nonprintable: 'var(--alert, #ff4d4d)',
  suspicious_long: 'var(--warn, #e0a040)',
  suspicious_short: 'var(--warn, #e0a040)',
};

const FpUserAgent: React.FC<{ p: any }> = ({ p }) => {
  const category = typeof p.category === 'string' ? p.category : 'unknown';
  const color = UA_CATEGORY_COLOR[category] || 'var(--text-color)';
  const signals: string[] = Array.isArray(p.signals) ? p.signals : [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {p.value !== undefined && p.value !== '' ? (
        <span
          className="matrix-text"
          style={{
            fontFamily: 'monospace',
            fontSize: '0.85rem',
            wordBreak: 'break-all',
          }}
        >
          {p.value}
        </span>
      ) : (
        <span className="dim" style={{ fontStyle: 'italic' }}>
          (empty User-Agent)
        </span>
      )}
      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
        <Tag color={color}>{category.toUpperCase()}</Tag>
        {p.tool && <Tag>{String(p.tool).toUpperCase()}</Tag>}
        {signals.map((s) => (
          <Tag key={s} color={UA_SIGNAL_COLOR[s] || 'var(--warn, #e0a040)'}>
            {s.toUpperCase().replace(/_/g, ' ')}
          </Tag>
        ))}
      </div>
    </div>
  );
};

const FpSpoofedSource: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
    <div>
      <span className="dim" style={{ fontSize: '0.7rem' }}>CLAIMED: </span>
      <span style={{
        color: 'var(--warn, #e0a040)',
        fontFamily: 'monospace',
        fontSize: '0.85rem',
      }}>
        {p.claimed_ip || '—'}
      </span>
      <span className="dim" style={{ fontSize: '0.7rem', marginLeft: 8 }}>
        via {p.source_header}
      </span>
    </div>
    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
      {p.claim_category && (
        <Tag color="var(--warn, #e0a040)">
          {String(p.claim_category).toUpperCase()}
        </Tag>
      )}
      <Tag>WAF-BYPASS ATTEMPT</Tag>
    </div>
    {p.source_ip && (
      <div className="dim" style={{ fontSize: '0.7rem', fontFamily: 'monospace' }}>
        real source · {p.source_ip}
      </div>
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
        {typeof p.stable_count === 'number' && (
          <Tag>{p.stable_count} STABLE HEADERS</Tag>
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
            case 'tls_certificate':
            case 'tls_certificate_active':
            case 'tls_certificate_passive':
              return <FpCertificate key={i} p={p} />;
            case 'jarm': return <FpJarm key={i} p={p} />;
            case 'hassh_server': return <FpHassh key={i} p={p} />;
            case 'tcpfp': return <FpTcpStack key={i} p={p} />;
            case 'http_quirks': return <FpHttpQuirks key={i} p={p} />;
            case 'http_useragent': return <FpUserAgent key={i} p={p} />;
            case 'spoofed_source': return <FpSpoofedSource key={i} p={p} />;
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
  if (!fp || (!fp.window && !fp.mss && !fp.options_sig && fp.dscp == null && fp.ecn == null)) return null;
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
          {fp.dscp !== null && fp.dscp !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>DSCP </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem' }}>{fp.dscp}</span>
            </div>
          )}
          {fp.ecn !== null && fp.ecn !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>ECN </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem' }}>{fp.ecn}</span>
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
          {fp.ipid_class && fp.ipid_class !== 'unknown' && (
            <Tag color={seqClassColor(fp.ipid_class)}>IPID:{fp.ipid_class.toUpperCase()}</Tag>
          )}
          {fp.isn_class && fp.isn_class !== 'unknown' && (
            <Tag color={seqClassColor(fp.isn_class)}>
              {fp.isn_class !== 'random' && '⚠ '}
              ISN:{fp.isn_class.toUpperCase()}
            </Tag>
          )}
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

// ─── Behavioural primitives panel (BEHAVE-INTEGRATION Phase 5) ─────────────

// Day-one render priority per BEHAVE-INTEGRATION.md §441-454. These four
// primitives carry the highest discriminative value for the "is this the
// same operator class" hover story; everything else alphabetises.
const BEHAVIOUR_PRIORITY: ReadonlyArray<string> = [
  'motor.input_modality',
  'cognitive.feedback_loop_engagement',
  'cognitive.command_branch_diversity',
  'cognitive.inter_command_latency_class',
];

const BEHAVIOUR_DOMAIN_ORDER: ReadonlyArray<string> = [
  'motor', 'cognitive', 'temporal', 'operational',
  'environmental', 'emotional_valence',
];

const BEHAVIOUR_DOMAIN_LABELS: Record<string, string> = {
  motor: 'MOTOR',
  cognitive: 'COGNITIVE',
  temporal: 'TEMPORAL',
  operational: 'OPERATIONAL',
  environmental: 'ENVIRONMENTAL',
  emotional_valence: 'EMOTIONAL VALENCE',
};

const BEHAVIOUR_DOMAIN_ICONS: Record<string, React.ComponentType<{ size?: number; style?: React.CSSProperties }>> = {
  motor: Keyboard,
  cognitive: Cpu,
  temporal: Clock,
  operational: Activity,
  environmental: Globe,
  emotional_valence: Sparkles,
};

function _domainOf(primitive: string): string {
  return primitive.split('.', 1)[0];
}

function _leafOf(primitive: string): string {
  return primitive.split('.').slice(1).join('.');
}

function _comparePrimitives(a: string, b: string): number {
  const ai = BEHAVIOUR_PRIORITY.indexOf(a);
  const bi = BEHAVIOUR_PRIORITY.indexOf(b);
  if (ai !== -1 && bi !== -1) return ai - bi;
  if (ai !== -1) return -1;
  if (bi !== -1) return 1;
  return a.localeCompare(b);
}

function _renderValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

// Per-state badge styling. Five states, frozen vocabulary —
// matches decnet/correlation/attribution/aggregate.py. multi_actor is
// the loudest because the cross-primitive correlator (Phase 5) only
// fires multi_actor_suspected when >= 2 primitives flag it.
const ATTRIBUTION_STATE_STYLE: Record<
  AttributionPrimitiveState['state'],
  { label: string; bg: string; fg: string; border: string }
> = {
  stable:      { label: 'STABLE',      bg: 'rgba(64,224,128,0.12)',  fg: '#7fe9a4', border: '#3a8c5a' },
  drifting:    { label: 'DRIFTING',    bg: 'rgba(240,196,64,0.12)',  fg: '#f0c440', border: '#a08020' },
  conflicted:  { label: 'CONFLICTED',  bg: 'rgba(240,96,96,0.12)',   fg: '#f06060', border: '#a04040' },
  multi_actor: { label: 'MULTI-ACTOR', bg: 'rgba(180,96,240,0.16)',  fg: '#c896f6', border: '#7a4fb0' },
  unknown:     { label: 'UNKNOWN',     bg: 'transparent',            fg: 'var(--text-dim,#888)', border: 'var(--border-color)' },
};

const AttributionBadge: React.FC<{ state: AttributionPrimitiveState }> = ({ state }) => {
  const style = ATTRIBUTION_STATE_STYLE[state.state] ?? ATTRIBUTION_STATE_STYLE.unknown;
  return (
    <span
      className="attribution-badge"
      data-testid={`attribution-badge-${state.primitive}`}
      data-state={state.state}
      title={
        `${style.label} • confidence ${(state.confidence * 100).toFixed(0)}% ` +
        `over ${state.observation_count} observation${state.observation_count === 1 ? '' : 's'}`
      }
      style={{
        fontSize: '0.6rem',
        letterSpacing: '1px',
        fontFamily: 'monospace',
        padding: '1px 6px',
        borderRadius: '2px',
        background: style.bg,
        color: style.fg,
        border: `1px solid ${style.border}`,
        whiteSpace: 'nowrap',
      }}
    >
      {style.label}
    </span>
  );
};

export const BehaviouralPrimitivesPanel: React.FC<{
  observations: ReadonlyArray<BehaviouralObservation>;
  attribution?: ReadonlyMap<string, AttributionPrimitiveState>;
}> = ({ observations, attribution }) => {
  if (!observations.length) {
    return (
      <div className="info-banner" data-testid="behaviour-empty">
        <span className="dim">No behavioural observations yet — the profiler runs once a session ends.</span>
      </div>
    );
  }
  // Group by top-level domain, sort each group by the priority-then-alpha
  // comparator, then walk the canonical domain order.
  const groups = new Map<string, BehaviouralObservation[]>();
  for (const obs of observations) {
    const domain = _domainOf(obs.primitive);
    const list = groups.get(domain) ?? [];
    list.push(obs);
    groups.set(domain, list);
  }
  for (const list of groups.values()) {
    list.sort((a, b) => _comparePrimitives(a.primitive, b.primitive));
  }
  const orderedDomains = [
    ...BEHAVIOUR_DOMAIN_ORDER.filter((d) => groups.has(d)),
    ...Array.from(groups.keys()).filter((d) => !BEHAVIOUR_DOMAIN_ORDER.includes(d)).sort(),
  ];
  return (
    <div
      className="behaviour-panel"
      data-testid="behaviour-panel"
      style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}
    >
      {orderedDomains.map((domain) => {
        const Icon = BEHAVIOUR_DOMAIN_ICONS[domain] ?? Activity;
        const label = BEHAVIOUR_DOMAIN_LABELS[domain] ?? domain.toUpperCase();
        const rows = groups.get(domain)!;
        return (
          <div
            key={domain}
            className="behaviour-group"
            data-testid={`behaviour-group-${domain}`}
            style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <Icon size={14} style={{ opacity: 0.6 }} />
              <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
                {label}
              </span>
              <span className="dim" style={{ fontSize: '0.65rem', marginLeft: 'auto' }}>
                {rows.length} {rows.length === 1 ? 'PRIMITIVE' : 'PRIMITIVES'}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {rows.map((obs) => (
                <div
                  key={obs.primitive}
                  className="behaviour-row"
                  data-testid={`behaviour-row-${obs.primitive}`}
                  style={{ display: 'flex', gap: '12px', alignItems: 'baseline' }}
                >
                  <span
                    className="behaviour-leaf dim"
                    style={{
                      fontSize: '0.7rem',
                      letterSpacing: '1px',
                      minWidth: '180px',
                      textTransform: 'uppercase',
                    }}
                  >
                    {_leafOf(obs.primitive)}
                  </span>
                  <span
                    className="behaviour-value matrix-text"
                    style={{
                      fontFamily: 'monospace',
                      fontSize: '0.85rem',
                      flex: 1,
                      wordBreak: 'break-word',
                    }}
                  >
                    {_renderValue(obs.value)}
                  </span>
                  {attribution?.get(obs.primitive) ? (
                    <AttributionBadge state={attribution.get(obs.primitive)!} />
                  ) : null}
                  <span
                    className="behaviour-confidence dim"
                    style={{
                      fontSize: '0.65rem',
                      fontFamily: 'monospace',
                      letterSpacing: '1px',
                      border: '1px solid var(--border-color)',
                      borderRadius: '2px',
                      padding: '1px 6px',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {(obs.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ─── Threat-Intel Panel ─────────────────────────────────────────────────────

// Mirrors decnet/web/db/models/attacker_intel.py — server returns the row
// fields plus null gaps where a provider hasn't answered yet. We treat
// every column as optional on the wire.
type IntelRow = {
  attacker_uuid: string;
  attacker_ip: string;
  schema_version?: number;
  aggregate_verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown' | null;
  greynoise_classification?: string | null;
  greynoise_raw?: any;
  greynoise_queried_at?: string | null;
  abuseipdb_score?: number | null;
  abuseipdb_raw?: any;
  abuseipdb_queried_at?: string | null;
  feodo_listed?: boolean | null;
  feodo_raw?: any;
  feodo_queried_at?: string | null;
  threatfox_listed?: boolean | null;
  threatfox_raw?: any;
  threatfox_queried_at?: string | null;
  cached_at?: string | null;
  expires_at?: string | null;
};

const VERDICT_TONE: Record<string, { color: string; label: string }> = {
  malicious: { color: 'var(--alert)', label: 'MALICIOUS' },
  suspicious: { color: 'var(--warn)', label: 'SUSPICIOUS' },
  benign: { color: 'var(--ok)', label: 'BENIGN' },
  unknown: { color: 'var(--fg-4)', label: 'NO SIGNAL' },
};

const fmtTs = (iso?: string | null): string => {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

const ProviderRow: React.FC<{
  name: string;
  queriedAt?: string | null;
  detail: React.ReactNode;
}> = ({ name, queriedAt, detail }) => (
  <div style={{
    display: 'grid',
    gridTemplateColumns: '160px 1fr auto',
    gap: '12px',
    padding: '10px 16px',
    borderTop: '1px solid var(--matrix-tint-5)',
    alignItems: 'center',
    fontSize: '0.85rem',
  }}>
    <div style={{ letterSpacing: '1px', opacity: 0.7 }}>{name}</div>
    <div>{detail}</div>
    <div style={{ opacity: 0.4, fontSize: '0.7rem', whiteSpace: 'nowrap' }}>
      {queriedAt ? fmtTs(queriedAt) : 'pending'}
    </div>
  </div>
);

const IntelPanel: React.FC<{ uuid: string }> = ({ uuid }) => {
  const [intel, setIntel] = useState<IntelRow | null>(null);
  const [state, setState] = useState<'loading' | 'absent' | 'ok' | 'error'>('loading');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setState('loading');
      try {
        const res = await api.get(`/attackers/${encodeURIComponent(uuid)}/intel`);
        if (!cancelled) {
          setIntel(res.data);
          setState('ok');
        }
      } catch (err: any) {
        if (cancelled) return;
        if (err?.response?.status === 404) {
          setIntel(null);
          setState('absent');
        } else {
          setState('error');
        }
      }
    };
    load();
    return () => { cancelled = true; };
  }, [uuid]);

  if (state === 'loading') {
    return (
      <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
        QUERYING INTEL CACHE...
      </div>
    );
  }

  if (state === 'error') {
    return (
      <div style={{ padding: '24px', textAlign: 'center', opacity: 0.6, color: '#ff8080' }}>
        FAILED TO LOAD INTEL
      </div>
    );
  }

  if (state === 'absent' || !intel) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', opacity: 0.5 }}>
        NO INTEL CACHED YET — `decnet enrich` will populate within {' '}
        <span style={{ opacity: 0.7 }}>~1 poll cycle</span> of next observation.
      </div>
    );
  }

  const tone = VERDICT_TONE[intel.aggregate_verdict || 'unknown'];

  return (
    <div>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '14px 16px',
        borderBottom: '1px solid var(--matrix-tint-5)',
      }}>
        <Shield size={16} style={{ color: tone.color }} />
        <span style={{
          letterSpacing: '2px',
          fontWeight: 600,
          color: tone.color,
        }}>
          {tone.label}
        </span>
        <span style={{ opacity: 0.4, fontSize: '0.7rem' }}>
          aggregate verdict
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '16px', fontSize: '0.7rem', opacity: 0.5 }}>
          <span>cached {fmtTs(intel.cached_at)}</span>
          <span>expires {fmtTs(intel.expires_at)}</span>
        </div>
      </div>

      <ProviderRow
        name="GREYNOISE"
        queriedAt={intel.greynoise_queried_at}
        detail={
          intel.greynoise_classification ? (
            <span>
              classification: <span style={{ color: VERDICT_TONE[intel.greynoise_classification]?.color || 'inherit' }}>
                {intel.greynoise_classification}
              </span>
            </span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />

      <ProviderRow
        name="ABUSEIPDB"
        queriedAt={intel.abuseipdb_queried_at}
        detail={
          intel.abuseipdb_score !== null && intel.abuseipdb_score !== undefined ? (
            <span>
              abuse confidence:{' '}
              <span style={{
                color: intel.abuseipdb_score >= 75 ? VERDICT_TONE.malicious.color
                     : intel.abuseipdb_score >= 25 ? VERDICT_TONE.suspicious.color
                     : VERDICT_TONE.benign.color,
                fontWeight: 600,
              }}>
                {intel.abuseipdb_score}/100
              </span>
            </span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />

      <ProviderRow
        name="FEODO TRACKER"
        queriedAt={intel.feodo_queried_at}
        detail={
          intel.feodo_listed === true ? (
            <span style={{ color: VERDICT_TONE.malicious.color, fontWeight: 600 }}>
              <AlertTriangle size={12} style={{ verticalAlign: 'middle' }} /> known C2
              {intel.feodo_raw?.malware && (
                <span style={{ opacity: 0.7, marginLeft: '8px', fontWeight: 400 }}>
                  ({intel.feodo_raw.malware})
                </span>
              )}
            </span>
          ) : intel.feodo_listed === false ? (
            <span style={{ opacity: 0.5 }}>not on C2 blocklist</span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />

      <ProviderRow
        name="THREATFOX"
        queriedAt={intel.threatfox_queried_at}
        detail={
          intel.threatfox_listed === true ? (
            <span style={{ color: VERDICT_TONE.malicious.color, fontWeight: 600 }}>
              <Eye size={12} style={{ verticalAlign: 'middle' }} /> IOC match
              {Array.isArray(intel.threatfox_raw) && intel.threatfox_raw[0]?.malware && (
                <span style={{ opacity: 0.7, marginLeft: '8px', fontWeight: 400 }}>
                  ({intel.threatfox_raw[0].malware})
                </span>
              )}
            </span>
          ) : intel.threatfox_listed === false ? (
            <span style={{ opacity: 0.5 }}>no IOC match</span>
          ) : (
            <span style={{ opacity: 0.4 }}>no answer</span>
          )
        }
      />
    </div>
  );
};


// ─── Main component ─────────────────────────────────────────────────────────

const AttackerDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  // Data layer is owned by the hook: REST fetches, attribution table,
  // and per-attacker / per-identity SSE streams all live there.
  const {
    attacker,
    observations,
    attribution,
    loading,
    error,
    commands,
    cmdTotal,
    cmdPage,
    setCmdPage,
    serviceFilter,
    setServiceFilter,
    cmdLimit,
    artifacts,
    smtpTargets,
    mail,
    mailForbidden,
    sessions,
  } = useAttackerDetail(id);

  // Section collapse state
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    timeline: true,
    services: true,
    deckies: true,
    behavior: true,
    behavioural: true,
    commands: true,
    fingerprints: true,
    intel: true,
    artifacts: true,
    sessions: true,
    smtpTargets: true,
    mail: true,
  });

  // Drawer selection (ephemeral UI; data feeds come from the hook).
  const [artifact, setArtifact] = useState<{ decky: string; storedAs: string; fields: Record<string, any> } | null>(null);
  const [session, setSession] = useState<{ decky: string; sid: string; fields: Record<string, any> } | null>(null);
  const [mailItem, setMailItem] = useState<{ decky: string; storedAs: string; fields: Record<string, any> } | null>(null);

  const toggle = (key: string) => setOpenSections((prev) => ({ ...prev, [key]: !prev[key] }));

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
    <div className="dashboard page-scroll">
      {/* Back Button */}
      <button onClick={() => navigate('/attackers')} className="back-button">
        <ArrowLeft size={18} />
        <span>BACK TO PROFILES</span>
      </button>

      <AttackerHeader attacker={attacker} />

      <AttackerStats attacker={attacker} />

      {/* TTPs Observed (per-IP slice) — see TTP_TAGGING.md §"UI surface" */}
      <TTPsObservedSection scope="attacker" uuid={attacker.uuid} />

      <TimelineSection
        attacker={attacker}
        open={openSections.timeline}
        onToggle={() => toggle('timeline')}
      />

      <ServicesTargeted
        attacker={attacker}
        serviceFilter={serviceFilter}
        setServiceFilter={setServiceFilter}
        open={openSections.services}
        onToggle={() => toggle('services')}
      />

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

      {/* Behavioural primitives (BEHAVE-SHELL) */}
      <Section
        title="BEHAVE PRIMITIVES"
        open={openSections.behavioural}
        onToggle={() => toggle('behavioural')}
      >
        <BehaviouralPrimitivesPanel observations={observations} attribution={attribution} />
      </Section>

      <CommandsViewer
        commands={commands}
        cmdTotal={cmdTotal}
        cmdPage={cmdPage}
        cmdLimit={cmdLimit}
        setCmdPage={setCmdPage}
        serviceFilter={serviceFilter}
        open={openSections.commands}
        onToggle={() => toggle('commands')}
      />

      {/* Fingerprints — grouped by type */}
      {(() => {
        const filteredFps = serviceFilter
          ? attacker.fingerprints.filter((fp) => {
              const p = getPayload(fp);
              return p.service === serviceFilter;
            })
          : attacker.fingerprints;

        // Group fingerprints by type. tls_certificate is split on the
        // presence of target_ip — prober payloads carry it, sniffer
        // payloads do not — so each source ends up under the right
        // active/passive bucket below.
        const groups: Record<string, any[]> = {};
        filteredFps.forEach((fp) => {
          const p = getPayload(fp);
          let fpType: string = p.fingerprint_type || 'unknown';
          if (fpType === 'tls_certificate') {
            fpType = p.target_ip ? 'tls_certificate_active' : 'tls_certificate_passive';
          }
          if (!groups[fpType]) groups[fpType] = [];
          groups[fpType].push(fp);
        });

        // Active probes first, then passive, then unknown
        const activeTypes = ['jarm', 'hassh_server', 'tcpfp', 'tls_certificate_active'];
        const passiveTypes = ['ja3', 'ja4l', 'tls_resumption', 'tls_certificate_passive', 'http_useragent', 'http_quirks', 'spoofed_source', 'vnc_client_version'];
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

      {/* Threat-Intel Enrichment — UUID-keyed, fetches in parallel with the parent. */}
      <Section
        title={<><Globe size={14} style={{ verticalAlign: 'middle', marginRight: '6px' }} />THREAT INTEL</>}
        open={openSections.intel}
        onToggle={() => toggle('intel')}
      >
        <IntelPanel uuid={id!} />
      </Section>

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
                              backgroundColor: 'var(--warn-tint-10)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              border: '1px solid var(--warn)',
                              color: 'var(--warn)',
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
                  <th>DATE (attacker)</th>
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
                        {fields.from_hdr || fields.from_addr || fields.mail_from || '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace', whiteSpace: 'nowrap', fontSize: '0.75rem' }}>
                        {fields.date_hdr || '—'}
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
                              backgroundColor: 'var(--warn-tint-10)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              border: '1px solid var(--warn)',
                              color: 'var(--warn)',
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
                              backgroundColor: 'var(--info-tint-10)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              border: '1px solid var(--info)',
                              color: 'var(--info)',
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
