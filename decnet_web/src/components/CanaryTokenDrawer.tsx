import React, { useEffect, useRef, useState } from 'react';
import { X, Download, AlertTriangle, Trash2, Eye } from '../icons';
import api from '../utils/api';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';

export interface CanaryTokenRow {
  uuid: string;
  kind: 'http' | 'dns' | 'aws_passive';
  decky_name: string;
  // Set when the token targets a MazeNET topology decky.  Null/absent
  // for fleet tokens.  Drives the "scope" badge in the list and the
  // topology jump-link in the drawer.
  topology_id: string | null;
  blob_uuid: string | null;
  instrumenter: string | null;
  generator: string | null;
  placement_path: string;
  callback_token: string;
  placed_at: string;
  last_triggered_at: string | null;
  trigger_count: number;
  created_by: string;
  state: 'planted' | 'revoked' | 'failed';
  last_error: string | null;
}

interface CanaryTrigger {
  uuid: string;
  token_uuid: string;
  occurred_at: string;
  src_ip: string;
  user_agent: string | null;
  request_path: string | null;
  dns_qname: string | null;
  headers: Record<string, string>;
  attacker_id: string | null;
}

interface Props {
  token: CanaryTokenRow;
  onClose: () => void;
  onRevoked: (uuid: string) => void;
}

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div style={{ display: 'flex', gap: '12px', padding: '6px 0', borderBottom: '1px solid var(--matrix-tint-5)' }}>
    <div style={{ minWidth: '140px', color: 'var(--dim-color)', fontSize: '0.75rem', textTransform: 'uppercase' }}>{label}</div>
    <div style={{ flex: 1, fontSize: '0.85rem', wordBreak: 'break-all' }}>{value ?? <span style={{ opacity: 0.4 }}>—</span>}</div>
  </div>
);

function fmt(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const STATE_COLOR: Record<CanaryTokenRow['state'], string> = {
  planted: '#00ff88',
  revoked: 'var(--dim-color)',
  failed: '#ff5555',
};

const KIND_LABEL: Record<CanaryTokenRow['kind'], string> = {
  http: 'HTTP CALLBACK',
  dns: 'DNS CALLBACK',
  aws_passive: 'AWS PASSIVE',
};

const CanaryTokenDrawer: React.FC<Props> = ({ token, onClose, onRevoked }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  const [triggers, setTriggers] = useState<CanaryTrigger[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.get(`/canary/tokens/${encodeURIComponent(token.uuid)}/triggers?limit=200`)
      .then((res) => { if (!cancelled) setTriggers(res.data.triggers || []); })
      .catch((err) => {
        if (cancelled) return;
        const status = err?.response?.status;
        setError(
          status === 403 ? 'Viewer role required.' :
          status === 404 ? 'Token has been deleted.' :
          'Failed to load triggers.'
        );
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [token.uuid]);

  const handleDownloadPreview = async () => {
    setDownloading(true);
    setError(null);
    try {
      const res = await api.get(
        `/canary/tokens/${encodeURIComponent(token.uuid)}/preview`,
        { responseType: 'blob' },
      );
      const blobUrl = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = token.placement_path.split('/').pop() || `canary-${token.callback_token}.bin`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    } catch (err: any) {
      const status = err?.response?.status;
      setError(
        status === 403 ? 'Admin role required to preview.' :
        status === 409 ? 'Token has no preview-able bytes (passive aws_creds, or blob deleted).' :
        'Preview failed.'
      );
    } finally {
      setDownloading(false);
    }
  };

  const handleRevoke = async () => {
    if (!window.confirm(`Revoke canary token on ${token.decky_name}? This unlinks the file and stops the slug from resolving.`)) return;
    setRevoking(true);
    setError(null);
    try {
      await api.delete(`/canary/tokens/${encodeURIComponent(token.uuid)}`);
      onRevoked(token.uuid);
    } catch (err: any) {
      const status = err?.response?.status;
      setError(
        status === 403 ? 'Admin role required to revoke.' :
        status === 404 ? 'Token already gone.' :
        'Revoke failed.'
      );
    } finally {
      setRevoking(false);
    }
  };

  const previewable = token.kind !== 'aws_passive';
  const callbackUrl = token.kind === 'http'
    ? `<canary-host>/c/${token.callback_token}`
    : token.kind === 'dns'
      ? `${token.callback_token}.<dns-zone>`
      : '— (passive bait, no callback)';

  return (
    <div
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: 'fixed', inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex', justifyContent: 'flex-end',
        zIndex: 1000,
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        style={{
          width: 'min(640px, 100%)', height: '100%',
          backgroundColor: 'var(--bg-color, #0d1117)',
          borderLeft: '1px solid var(--border-color, #30363d)',
          padding: '24px', overflowY: 'auto',
          color: 'var(--text-color)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em' }}>
              CANARY TOKEN · {token.decky_name}
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 'bold', marginTop: '4px', wordBreak: 'break-all' }}>
              {token.placement_path}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-color)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '8px 12px', marginBottom: '16px',
          border: `1px solid ${STATE_COLOR[token.state]}33`,
          backgroundColor: `${STATE_COLOR[token.state]}11`,
          fontSize: '0.75rem', color: STATE_COLOR[token.state],
        }}>
          <AlertTriangle size={14} />
          {token.state.toUpperCase()} · {KIND_LABEL[token.kind]} · {token.trigger_count} {token.trigger_count === 1 ? 'hit' : 'hits'}
          {token.state === 'failed' && token.last_error && <span style={{ color: '#ff5555' }}>· {token.last_error}</span>}
        </div>

        <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', flexWrap: 'wrap' }}>
          {previewable && (
            <button
              onClick={handleDownloadPreview}
              disabled={downloading}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                padding: '8px 14px',
                border: '1px solid var(--text-color)',
                background: 'transparent', color: 'var(--text-color)',
                cursor: downloading ? 'wait' : 'pointer',
                opacity: downloading ? 0.5 : 1,
              }}
            >
              <Download size={14} /> {downloading ? 'DOWNLOADING…' : 'PREVIEW BYTES'}
            </button>
          )}
          {token.state === 'planted' && (
            <button
              onClick={handleRevoke}
              disabled={revoking}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                padding: '8px 14px',
                border: '1px solid #ff5555',
                background: 'transparent', color: '#ff5555',
                cursor: revoking ? 'wait' : 'pointer',
                opacity: revoking ? 0.5 : 1,
              }}
            >
              <Trash2 size={14} /> {revoking ? 'REVOKING…' : 'REVOKE'}
            </button>
          )}
        </div>
        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '16px' }}>{error}</div>
        )}

        <section style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
            METADATA
          </h3>
          <Row label="UUID" value={<code>{token.uuid}</code>} />
          <Row label="Decky" value={token.decky_name} />
          <Row
            label="Scope"
            value={token.topology_id ? (
              <a
                href={`/mazenet?topology=${encodeURIComponent(token.topology_id)}`}
                style={{ color: 'var(--accent-color, #00ff88)' }}
              >
                topology · {token.topology_id.slice(0, 8)}…
              </a>
            ) : (
              <span style={{ opacity: 0.6 }}>fleet</span>
            )}
          />
          <Row label="Kind" value={KIND_LABEL[token.kind]} />
          <Row label="Source" value={token.generator ? `generator: ${token.generator}` : token.instrumenter ? `instrumenter: ${token.instrumenter}` : '—'} />
          <Row label="Slug" value={<code>{token.callback_token}</code>} />
          <Row label="Callback" value={<code>{callbackUrl}</code>} />
          <Row label="Placed at" value={fmt(token.placed_at)} />
          <Row label="Last hit" value={fmt(token.last_triggered_at)} />
          <Row label="Trigger count" value={token.trigger_count} />
          <Row label="Created by" value={token.created_by} />
        </section>

        <section>
          <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
            <Eye size={14} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
            CALLBACK HISTORY ({triggers.length}{triggers.length === 200 ? '+' : ''})
          </h3>
          {loading && <div style={{ fontSize: '0.8rem', opacity: 0.6 }}>loading…</div>}
          {!loading && triggers.length === 0 && (
            <div style={{ fontSize: '0.8rem', opacity: 0.6 }}>
              No callbacks yet. The slug will start firing if the artifact gets exfiltrated and opened.
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {triggers.map((t) => (
              <div
                key={t.uuid}
                style={{
                  padding: '8px 12px',
                  border: '1px solid var(--matrix-tint-5)',
                  background: 'var(--matrix-tint-5)',
                  fontSize: '0.8rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontFamily: 'monospace' }}>
                  <span>{t.src_ip}</span>
                  <span style={{ color: 'var(--dim-color)' }}>{fmt(t.occurred_at)}</span>
                </div>
                {t.user_agent && (
                  <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    UA · {t.user_agent}
                  </div>
                )}
                {t.request_path && (
                  <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    HTTP · {t.request_path}
                  </div>
                )}
                {t.dns_qname && (
                  <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    DNS · {t.dns_qname}
                  </div>
                )}
                {t.attacker_id && (
                  <div style={{ fontSize: '0.7rem', color: '#00ff88', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    attacker · {t.attacker_id}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
};

export default CanaryTokenDrawer;
