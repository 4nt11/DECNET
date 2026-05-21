import React from 'react';
import {
  Clock, Crosshair, FileKey, Fingerprint, Lock, Shield, Wifi,
} from '../../../icons';

export const fpTypeLabel: Record<string, string> = {
  ja3: 'TLS FINGERPRINT',
  ja4l: 'LATENCY (JA4L)',
  ja4h: 'JA4H (HTTP)',
  ja4_quic: 'JA4-QUIC',
  tls_resumption: 'SESSION RESUMPTION',
  tls_certificate: 'CERTIFICATE',
  tls_certificate_active: 'CERTIFICATE (ACTIVE PROBE)',
  tls_certificate_passive: 'CERTIFICATE',
  http_useragent: 'HTTP USER-AGENT',
  http_quirks: 'HTTP HEADER QUIRKS',
  http2_settings: 'HTTP/2 SETTINGS',
  http3_settings: 'HTTP/3 SETTINGS',
  spoofed_source: 'SPOOFED SOURCE IP',
  vnc_client_version: 'VNC CLIENT',
  jarm: 'JARM',
  hassh_server: 'HASSH SERVER',
  tcpfp: 'TCP/IP STACK',
  icmp_error: 'ICMP ERROR LEAK',
  icmp6_error: 'ICMPv6 ERROR LEAK',
};

export const fpTypeIcon: Record<string, React.ReactNode> = {
  ja3: <Fingerprint size={14} />,
  ja4l: <Clock size={14} />,
  ja4h: <Fingerprint size={14} />,
  ja4_quic: <Crosshair size={14} />,
  tls_resumption: <Wifi size={14} />,
  tls_certificate: <FileKey size={14} />,
  tls_certificate_active: <FileKey size={14} />,
  tls_certificate_passive: <FileKey size={14} />,
  http_useragent: <Shield size={14} />,
  http_quirks: <Fingerprint size={14} />,
  http2_settings: <Wifi size={14} />,
  http3_settings: <Wifi size={14} />,
  spoofed_source: <Crosshair size={14} />,
  vnc_client_version: <Lock size={14} />,
  jarm: <Crosshair size={14} />,
  hassh_server: <Lock size={14} />,
  tcpfp: <Wifi size={14} />,
  icmp_error: <Wifi size={14} />,
  icmp6_error: <Crosshair size={14} />,
};

export const UA_CATEGORY_COLOR: Record<string, string> = {
  scanner: 'var(--alert, #ff4d4d)',
  nonstandard: 'var(--warn, #e0a040)',
  empty: 'var(--warn, #e0a040)',
  bot: 'var(--violet)',
  cli: 'var(--matrix)',
  library: 'var(--matrix)',
  browser: 'var(--accent-color)',
};

export const UA_SIGNAL_COLOR: Record<string, string> = {
  injection_like: 'var(--alert, #ff4d4d)',
  nonprintable: 'var(--alert, #ff4d4d)',
  suspicious_long: 'var(--warn, #e0a040)',
  suspicious_short: 'var(--warn, #e0a040)',
};

/** Bounty payloads can be either a parsed object or a raw JSON string
 *  depending on producer; normalize before handing to the renderers. */
export function getPayload(bounty: unknown): Record<string, unknown> {
  const b = bounty as { payload?: unknown } | null | undefined;
  if (b?.payload && typeof b.payload === 'object') {
    return b.payload as Record<string, unknown>;
  }
  if (b?.payload && typeof b.payload === 'string') {
    try { return JSON.parse(b.payload) as Record<string, unknown>; }
    catch { return (bounty ?? {}) as Record<string, unknown>; }
  }
  return (bounty ?? {}) as Record<string, unknown>;
}

// Random ISN/IP-ID is the modern default; non-random patterns are
// fingerprinting gold (legacy stacks, custom raw-socket tools).
export const seqClassColor = (cls: string): string | undefined => {
  switch (cls) {
    case 'random':      return undefined;        // neutral, expected
    case 'incremental': return '#e5c07b';        // amber — uncommon
    case 'zero':
    case 'constant':    return '#98c379';        // green — strong signal
    default:            return undefined;
  }
};

export const HashRow: React.FC<{ label: string; value?: string | null }> = ({ label, value }) => {
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
