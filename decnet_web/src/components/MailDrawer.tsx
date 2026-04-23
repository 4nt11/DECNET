import React, { useEffect, useRef, useState } from 'react';
import { X, Download, AlertTriangle, Paperclip } from 'lucide-react';
import api from '../utils/api';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';

interface MailDrawerProps {
  decky: string;
  storedAs: string;
  fields: Record<string, any>;
  onClose: () => void;
}

interface AttachmentManifest {
  filename?: string | null;
  content_type?: string | null;
  size?: number | null;
  sha256?: string | null;
}

function parseAttachments(fields: Record<string, any>): AttachmentManifest[] {
  const raw = fields.attachments_json;
  if (typeof raw !== 'string' || !raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('mail: failed to parse attachments_json', err);
    return [];
  }
}

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div style={{ display: 'flex', gap: '12px', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
    <div style={{ minWidth: '140px', color: 'var(--dim-color)', fontSize: '0.75rem', textTransform: 'uppercase' }}>{label}</div>
    <div style={{ flex: 1, fontSize: '0.85rem', wordBreak: 'break-all' }}>{value ?? <span style={{ opacity: 0.4 }}>—</span>}</div>
  </div>
);

const MailDrawer: React.FC<MailDrawerProps> = ({ decky, storedAs, fields, onClose }) => {
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
  const attachments = parseAttachments(fields);

  const handleDownload = async () => {
    setDownloading(true);
    setError(null);
    try {
      const res = await api.get(
        `/artifacts/${encodeURIComponent(decky)}/${encodeURIComponent(storedAs)}?service=smtp`,
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
        status === 403 ? 'Admin role required to download mail.' :
        status === 404 ? 'Message not found on disk (may have been purged).' :
        status === 400 ? 'Server rejected the request (invalid parameters).' :
        'Download failed — see console.'
      );
      console.error('mail download failed', err);
    } finally {
      setDownloading(false);
    }
  };

  const recipients = Array.isArray(fields.rcpts)
    ? fields.rcpts.join(', ')
    : (typeof fields.rcpts === 'string' ? fields.rcpts : null);

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
              STORED MESSAGE · {decky}
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 'bold', marginTop: '4px', wordBreak: 'break-all' }}>
              {fields.subject || storedAs}
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
          Attacker-controlled content. Phishing kits / malware likely.
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
          <Download size={14} /> {downloading ? 'DOWNLOADING…' : 'DOWNLOAD .EML'}
        </button>
        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '16px' }}>{error}</div>
        )}

        <section style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
            HEADERS
          </h3>
          <Row label="Subject" value={fields.subject} />
          <Row label="From" value={fields.from_addr ?? fields.from} />
          <Row label="To" value={recipients} />
          <Row label="Date" value={fields.date} />
          <Row label="Message-ID" value={fields.message_id} />
          <Row label="Mail from" value={fields.mail_from} />
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
            BODY
          </h3>
          <Row label="Size" value={fields.size ? `${fields.size} bytes` : null} />
          <Row label="SHA-256" value={fields.sha256} />
          <Row label="Truncated" value={fields.truncated ? 'yes (10 MB cap)' : 'no'} />
          <Row label="Stored as" value={storedAs} />
        </section>

        {attachments.length > 0 && (
          <section>
            <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
              ATTACHMENTS ({attachments.length})
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {attachments.map((att, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '8px 12px',
                    border: '1px solid rgba(255,255,255,0.08)',
                    background: 'rgba(255,255,255,0.02)',
                    fontSize: '0.8rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <Paperclip size={12} />
                    <span style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {att.filename || '(unnamed)'}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', fontFamily: 'monospace' }}>
                    {att.content_type ?? '?'} · {att.size != null ? `${att.size} B` : '? B'}
                  </div>
                  {att.sha256 && (
                    <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {att.sha256}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default MailDrawer;
