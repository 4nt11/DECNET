import React, { useEffect, useRef, useState } from 'react';
import { X, Download, AlertTriangle } from '../icons';
import api from '../utils/api';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';

interface ArtifactDrawerProps {
  decky: string;
  storedAs: string;
  fields: Record<string, any>;
  onClose: () => void;
}

// Bulky nested structures are shipped as one base64-encoded JSON blob in
// `meta_json_b64` (see templates/ssh/emit_capture.py). All summary fields
// arrive as top-level SD params already present in `fields`.
function decodeMeta(fields: Record<string, any>): Record<string, any> | null {
  const b64 = fields.meta_json_b64;
  if (typeof b64 !== 'string' || !b64) return null;
  try {
    const json = atob(b64);
    return JSON.parse(json);
  } catch (err) {
    console.error('artifact: failed to decode meta_json_b64', err);
    return null;
  }
}

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div style={{ display: 'flex', gap: '12px', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
    <div style={{ minWidth: '140px', color: 'var(--dim-color)', fontSize: '0.75rem', textTransform: 'uppercase' }}>{label}</div>
    <div style={{ flex: 1, fontSize: '0.85rem', wordBreak: 'break-all' }}>{value ?? <span style={{ opacity: 0.4 }}>—</span>}</div>
  </div>
);

const ArtifactDrawer: React.FC<ArtifactDrawerProps> = ({ decky, storedAs, fields, onClose }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const meta = decodeMeta(fields);

  const handleDownload = async () => {
    setDownloading(true);
    setError(null);
    try {
      const res = await api.get(
        `/artifacts/${encodeURIComponent(decky)}/${encodeURIComponent(storedAs)}`,
        { responseType: 'blob' },
      );
      const blobUrl = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = storedAs;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    } catch (err: any) {
      const status = err?.response?.status;
      setError(
        status === 403 ? 'Admin role required to download artifacts.' :
        status === 404 ? 'Artifact not found on disk (may have been purged).' :
        status === 400 ? 'Server rejected the request (invalid parameters).' :
        'Download failed — see console.'
      );
      console.error('artifact download failed', err);
    } finally {
      setDownloading(false);
    }
  };

  const concurrent = meta?.concurrent_sessions;
  const ssSnapshot = meta?.ss_snapshot;

  return (
    <div
      onClick={onClose}
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
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(620px, 100%)', height: '100%',
          backgroundColor: 'var(--bg-color, #0d1117)',
          borderLeft: '1px solid var(--border-color, #30363d)',
          padding: '24px', overflowY: 'auto',
          color: 'var(--text-color)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em' }}>
              CAPTURED ARTIFACT · {decky}
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 'bold', marginTop: '4px', wordBreak: 'break-all' }}>
              {storedAs}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-color)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '8px 12px', marginBottom: '16px',
          border: '1px solid rgba(255, 170, 0, 0.3)',
          backgroundColor: 'rgba(255, 170, 0, 0.05)',
          fontSize: '0.75rem', color: '#ffaa00',
        }}>
          <AlertTriangle size={14} />
          Attacker-controlled content. Download at your own risk.
        </div>

        <button
          onClick={handleDownload}
          disabled={downloading}
          style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '8px 14px', marginBottom: '20px',
            border: '1px solid var(--text-color)',
            background: 'transparent', color: 'var(--text-color)',
            cursor: downloading ? 'wait' : 'pointer',
            opacity: downloading ? 0.5 : 1,
          }}
        >
          <Download size={14} /> {downloading ? 'DOWNLOADING…' : 'DOWNLOAD RAW'}
        </button>
        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '16px' }}>{error}</div>
        )}

        <section style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
            ORIGIN
          </h3>
          <Row label="Orig path" value={fields.orig_path} />
          <Row label="SHA-256" value={fields.sha256} />
          <Row label="Size" value={fields.size ? `${fields.size} bytes` : null} />
          <Row label="Mtime" value={fields.mtime} />
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
            ATTRIBUTION · {fields.attribution ?? 'unknown'}
          </h3>
          <Row label="SSH user" value={fields.ssh_user} />
          <Row label="Src IP" value={fields.src_ip} />
          <Row label="Src port" value={fields.src_port} />
          <Row label="SSH pid" value={fields.ssh_pid} />
          <Row label="Writer pid" value={fields.writer_pid} />
          <Row label="Writer comm" value={fields.writer_comm} />
          <Row label="Writer uid" value={fields.writer_uid} />
          <Row label="Writer cmdline" value={meta?.writer_cmdline} />
          <Row label="Writer loginuid" value={meta?.writer_loginuid} />
        </section>

        {Array.isArray(concurrent) && concurrent.length > 0 && (
          <section style={{ marginBottom: '24px' }}>
            <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
              CONCURRENT SESSIONS ({concurrent.length})
            </h3>
            <pre style={{ fontSize: '0.75rem', background: 'rgba(255,255,255,0.03)', padding: '8px', overflowX: 'auto' }}>
              {JSON.stringify(concurrent, null, 2)}
            </pre>
          </section>
        )}

        {Array.isArray(ssSnapshot) && ssSnapshot.length > 0 && (
          <section>
            <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
              SS SNAPSHOT ({ssSnapshot.length})
            </h3>
            <pre style={{ fontSize: '0.75rem', background: 'rgba(255,255,255,0.03)', padding: '8px', overflowX: 'auto' }}>
              {JSON.stringify(ssSnapshot, null, 2)}
            </pre>
          </section>
        )}
      </div>
    </div>
  );
};

export default ArtifactDrawer;
