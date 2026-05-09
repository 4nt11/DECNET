import React, { useState } from 'react';
import { Package, Paperclip } from '../../../icons';
import EmptyState from '../../EmptyState/EmptyState';
import ArtifactDrawer from '../../ArtifactDrawer';
import { Section } from '../ui';
import type { ArtifactLog } from '../types';

interface Props {
  artifacts: ArtifactLog[];
  open: boolean;
  onToggle: () => void;
}

interface DrawerSelection {
  decky: string;
  storedAs: string;
  fields: Record<string, unknown>;
}

/** CAPTURED ARTIFACTS collapsible — file-drop log with inline
 *  preview button per row. The drawer's open/close state lives
 *  here; the artifact list itself is read from the data hook. */
export const ArtifactsPanel: React.FC<Props> = ({ artifacts, open, onToggle }) => {
  const [selected, setSelected] = useState<DrawerSelection | null>(null);

  return (
    <>
      <Section
        title={<>CAPTURED ARTIFACTS ({artifacts.length})</>}
        open={open}
        onToggle={onToggle}
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
                  let fields: Record<string, unknown> = {};
                  try {
                    fields = JSON.parse(row.fields || '{}');
                  } catch {
                    // malformed SD params — preview unavailable
                  }
                  const storedAs = fields.stored_as ? String(fields.stored_as) : null;
                  const sha = fields.sha256 ? String(fields.sha256) : '';
                  return (
                    <tr key={row.id}>
                      <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {new Date(row.timestamp).toLocaleString()}
                      </td>
                      <td className="violet-accent">{row.decky}</td>
                      <td
                        className="matrix-text"
                        style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
                      >
                        {(fields.orig_path as string | undefined) ?? storedAs ?? '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {fields.size ? `${fields.size} B` : '—'}
                      </td>
                      <td
                        className="dim"
                        style={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                      >
                        {sha ? `${sha.slice(0, 12)}…` : '—'}
                      </td>
                      <td>
                        {storedAs && (
                          <button
                            onClick={() => setSelected({ decky: row.decky, storedAs, fields })}
                            title="Inspect captured artifact"
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '6px',
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
          <EmptyState icon={Package} title="NO ARTIFACTS CAPTURED" size="compact" />
        )}
      </Section>

      {selected && (
        <ArtifactDrawer
          decky={selected.decky}
          storedAs={selected.storedAs}
          fields={selected.fields}
          onClose={() => setSelected(null)}
        />
      )}
    </>
  );
};
