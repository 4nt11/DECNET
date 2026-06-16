// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import type { BlobRow } from './types';
import { fmt, fmtBytes } from './helpers';

interface Props {
  blobs: BlobRow[];
  onDelete: (uuid: string) => void;
}

/** Blobs tab: flat row grid. The DELETE button stays disabled while
 *  any token still references the blob (the server would refuse the
 *  request anyway; we surface that to the operator preemptively). */
export const BlobListView: React.FC<Props> = ({ blobs, onDelete }) => (
  <>
    {blobs.length === 0 && (
      <div style={{ textAlign: 'center', padding: '40px', opacity: 0.6, fontSize: '0.85rem' }}>
        No uploaded artifacts. Click UPLOAD ARTIFACT to add one.
      </div>
    )}
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {blobs.map((b) => (
        <div
          key={b.uuid}
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 220px 90px 100px 80px',
            alignItems: 'center', gap: '12px',
            padding: '10px 14px',
            border: '1px solid var(--border-color, #30363d)',
            background: 'var(--matrix-tint-5)',
            fontSize: '0.8rem',
          }}
        >
          <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {b.filename}
          </span>
          <span style={{ fontSize: '0.7rem', opacity: 0.7, fontFamily: 'monospace' }}>{b.content_type}</span>
          <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmtBytes(b.size_bytes)}</span>
          <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>{fmt(b.uploaded_at)}</span>
          <button
            onClick={() => onDelete(b.uuid)}
            disabled={b.token_count > 0}
            title={b.token_count > 0 ? `${b.token_count} token(s) still reference this blob` : 'Delete'}
            style={{
              background: 'transparent', color: b.token_count > 0 ? 'var(--dim-color)' : '#ff5555',
              border: `1px solid ${b.token_count > 0 ? 'var(--dim-color)' : '#ff5555'}`,
              padding: '4px 8px', fontSize: '0.7rem',
              cursor: b.token_count > 0 ? 'not-allowed' : 'pointer',
              opacity: b.token_count > 0 ? 0.4 : 1,
            }}
          >
            {b.token_count > 0 ? `${b.token_count} REFS` : 'DELETE'}
          </button>
        </div>
      ))}
    </div>
  </>
);
