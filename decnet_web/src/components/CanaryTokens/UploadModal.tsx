// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useRef, useState } from 'react';
import { Upload, X, AlertTriangle } from '../../icons';
import api from '../../utils/api';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import type { BlobRow } from './types';
import { extractError, fmtBytes } from './helpers';
import { BTN_PRIMARY, BTN_GHOST } from './ui';

interface Props {
  onClose: () => void;
  onUploaded: (blob: BlobRow) => void;
}

/** Drop-or-browse upload of an operator-supplied artifact. The
 *  server keeps the original bytes on the master and injects the
 *  callback marker downstream — the warning banner repeats that to
 *  the operator before they hand over a sensitive document. */
export const UploadModal: React.FC<Props> = ({ onClose, onUploaded }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);

  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const handleSubmit = async () => {
    if (!file) return setError('Pick a file first.');
    setUploading(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await api.post('/canary/blobs', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      onUploaded(res.data);
    } catch (err) {
      setError(extractError(err, 'Upload failed.'));
    } finally {
      setUploading(false);
    }
  };

  return (
    <div
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: 'fixed', inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        zIndex: 1000,
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        style={{
          width: 'min(520px, 100%)',
          backgroundColor: 'var(--bg-color, #0d1117)',
          border: '1px solid var(--border-color, #30363d)',
          padding: '24px', color: 'var(--text-color)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ fontSize: '1rem', fontWeight: 'bold' }}>UPLOAD CANARY ARTIFACT</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-color)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files?.[0];
            if (f) setFile(f);
          }}
          style={{
            border: `2px dashed ${dragOver ? 'var(--accent-color, #00ff88)' : 'var(--border-color, #30363d)'}`,
            padding: '32px',
            textAlign: 'center',
            marginBottom: '16px',
            cursor: 'pointer',
            background: dragOver ? 'rgba(0, 255, 136, 0.05)' : 'transparent',
          }}
          onClick={() => document.getElementById('canary-blob-input')?.click()}
        >
          <Upload size={32} style={{ opacity: 0.5, marginBottom: '8px' }} />
          <div style={{ fontSize: '0.85rem' }}>
            {file ? `${file.name} (${fmtBytes(file.size)})` : 'Drop a file here or click to browse'}
          </div>
          {!file && (
            <div style={{ fontSize: '0.7rem', opacity: 0.6, marginTop: '6px' }}>
              DOCX · XLSX · PDF · HTML · PNG/JPEG · plain configs
            </div>
          )}
          <input
            id="canary-blob-input"
            type="file"
            style={{ display: 'none' }}
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '8px 12px', marginBottom: '16px',
          border: '1px solid var(--warn)',
          backgroundColor: 'var(--warn-tint-10)',
          fontSize: '0.75rem', color: 'var(--warn)',
        }}>
          <AlertTriangle size={14} />
          DECNET injects the callback server-side; the original bytes stay on the master.
        </div>

        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '12px' }}>{error}</div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={BTN_GHOST}>CANCEL</button>
          <button
            onClick={handleSubmit}
            disabled={!file || uploading}
            style={{ ...BTN_PRIMARY, opacity: (!file || uploading) ? 0.5 : 1, cursor: uploading ? 'wait' : 'pointer' }}
          >
            {uploading ? 'UPLOADING…' : 'UPLOAD'}
          </button>
        </div>
      </div>
    </div>
  );
};
