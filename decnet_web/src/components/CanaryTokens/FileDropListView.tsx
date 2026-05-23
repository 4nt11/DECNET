// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import type { FileDropEntry } from './FileDropModal';
import { fmt, fmtBytes } from './helpers';

interface Props {
  fileDrops: FileDropEntry[];
  onClear: () => void;
}

/** File-drops tab: local-only log of past drops (the server does not
 *  persist these; this is purely an operator memory aid). The CLEAR
 *  LIST button only wipes the browser-side history — actual dropped
 *  files remain on the targeted decky. */
export const FileDropListView: React.FC<Props> = ({ fileDrops, onClear }) => (
  <>
    <div style={{
      display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '12px',
      justifyContent: 'space-between',
    }}>
      <div style={{ fontSize: '0.75rem', opacity: 0.6 }}>
        Local log only — the server doesn't persist file drops.
        Cleared when you clear browser storage.
      </div>
      {fileDrops.length > 0 && (
        <button
          onClick={onClear}
          style={{
            padding: '4px 10px',
            border: '1px solid var(--dim-color)',
            background: 'transparent', color: 'var(--dim-color)',
            fontSize: '0.7rem', cursor: 'pointer',
            textTransform: 'uppercase',
          }}
        >
          CLEAR LIST
        </button>
      )}
    </div>
    {fileDrops.length === 0 && (
      <div style={{ textAlign: 'center', padding: '40px', opacity: 0.6, fontSize: '0.85rem' }}>
        No file drops in this browser yet. Click DROP FILE to send bytes to a decky.
      </div>
    )}
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {fileDrops.map((fd) => (
        <div
          key={fd.id}
          style={{
            display: 'grid',
            gridTemplateColumns: '80px 140px 1fr 90px 80px 140px',
            alignItems: 'center', gap: '12px',
            padding: '10px 14px',
            border: '1px solid var(--border-color, #30363d)',
            background: 'var(--matrix-tint-5)',
            fontSize: '0.8rem',
          }}
        >
          <span
            title={fd.topology_id ? `topology ${fd.topology_id}` : 'fleet'}
            style={{
              fontSize: '0.65rem', letterSpacing: '0.05em',
              padding: '2px 6px',
              border: `1px solid ${fd.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)'}`,
              color: fd.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)',
              textAlign: 'center',
              textTransform: 'uppercase',
            }}
          >
            {fd.topology_id ? 'topology' : 'fleet'}
          </span>
          <span style={{ fontFamily: 'monospace' }}>{fd.decky_name}</span>
          <span
            title={`${fd.filename} → ${fd.path}`}
            style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          >
            {fd.path}
          </span>
          <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmtBytes(fd.size_bytes)}</span>
          <span style={{ fontSize: '0.7rem', opacity: 0.7, fontFamily: 'monospace' }}>{fd.mode.toString(8)}</span>
          <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmt(fd.dropped_at)}</span>
        </div>
      ))}
    </div>
  </>
);
