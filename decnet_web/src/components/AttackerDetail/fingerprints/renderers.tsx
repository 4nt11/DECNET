import React from 'react';
import { Fingerprint } from '../../../icons';
import { Tag } from '../ui';
import {
  fpTypeIcon, fpTypeLabel, getPayload, HashRow,
  UA_CATEGORY_COLOR, UA_SIGNAL_COLOR,
} from './helpers';

/* eslint-disable @typescript-eslint/no-explicit-any */

export const FpTlsHashes: React.FC<{ p: any }> = ({ p }) => (
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

export const FpLatency: React.FC<{ p: any }> = ({ p }) => (
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

export const FpResumption: React.FC<{ p: any }> = ({ p }) => {
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

export const FpCertificate: React.FC<{ p: any }> = ({ p }) => (
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

export const FpJarm: React.FC<{ p: any }> = ({ p }) => (
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

export const FpHassh: React.FC<{ p: any }> = ({ p }) => (
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

export const FpTcpStack: React.FC<{ p: any }> = ({ p }) => (
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

export const FpJa4h: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
    <HashRow label="JA4H" value={String(p.ja4h ?? '')} />
    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
      {p.protocol && <Tag>{String(p.protocol).toUpperCase()}</Tag>}
      {p.method && <Tag color="var(--accent-color)">{String(p.method).toUpperCase()}</Tag>}
      {p.path && <Tag>{String(p.path)}</Tag>}
      {p.remote_port && <Tag>:{p.remote_port}</Tag>}
    </div>
  </div>
);

export const FpHttpSettings: React.FC<{ p: any }> = ({ p }) => {
  let entries: [string, unknown][] = [];
  if (p.settings) {
    try {
      const parsed = typeof p.settings === 'string' ? JSON.parse(p.settings) : p.settings;
      entries = Object.entries(parsed as Record<string, unknown>);
    } catch { /* leave entries empty */ }
  }
  let frameOrder: string[] = [];
  if (p.frame_order) {
    try {
      const parsed = typeof p.frame_order === 'string' ? JSON.parse(p.frame_order) : p.frame_order;
      if (Array.isArray(parsed)) frameOrder = parsed.map(String);
    } catch { /* leave empty */ }
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        {p.protocol && <Tag>{String(p.protocol).toUpperCase()}</Tag>}
        {p.remote_port && <Tag>:{p.remote_port}</Tag>}
      </div>
      {entries.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
          {entries.map(([k, v]) => (
            <div key={k} style={{ display: 'flex', gap: '8px', alignItems: 'baseline' }}>
              <span className="dim" style={{ fontSize: '0.7rem', minWidth: '180px' }}>
                {k.replace(/_/g, ' ')}
              </span>
              <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                {String(v)}
              </span>
            </div>
          ))}
        </div>
      )}
      {frameOrder.length > 0 && (
        <details>
          <summary className="dim" style={{ fontSize: '0.7rem', cursor: 'pointer', letterSpacing: '1px' }}>
            FRAME ORDER
          </summary>
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
            {frameOrder.map((f, i) => <Tag key={i}>{f}</Tag>)}
          </div>
        </details>
      )}
    </div>
  );
};

export const FpJa4Quic: React.FC<{ p: any }> = ({ p }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
    <HashRow label="JA4-QUIC" value={String(p.ja4_quic ?? '')} />
    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
      {p.sni && <Tag color="var(--accent-color)">SNI: {p.sni}</Tag>}
      {p.alpn && <Tag>ALPN: {p.alpn}</Tag>}
    </div>
  </div>
);

export const FpGeneric: React.FC<{ p: any }> = ({ p }) => (
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

export const FpUserAgent: React.FC<{ p: any }> = ({ p }) => {
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

export const FpSpoofedSource: React.FC<{ p: any }> = ({ p }) => (
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

export const FpHttpQuirks: React.FC<{ p: any }> = ({ p }) => {
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

export const FingerprintGroup: React.FC<{ fpType: string; items: any[] }> = ({ fpType, items }) => {
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
            case 'ja4h': return <FpJa4h key={i} p={p} />;
            case 'http2_settings':
            case 'http3_settings':
              return <FpHttpSettings key={i} p={p} />;
            case 'ja4_quic': return <FpJa4Quic key={i} p={p} />;
            default: return <FpGeneric key={i} p={p} />;
          }
        })}
      </div>
    </div>
  );
};
