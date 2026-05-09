import React, { useState } from 'react';
import { Mail } from '../../../icons';
import EmptyState from '../../EmptyState/EmptyState';
import MailDrawer from '../../MailDrawer';
import { Section } from '../ui';
import type { MailLog } from '../types';

interface Props {
  mail: MailLog[];
  mailForbidden: boolean;
  open: boolean;
  onToggle: () => void;
}

interface DrawerSelection {
  decky: string;
  storedAs: string;
  fields: Record<string, unknown>;
}

/** STORED MAIL collapsible — admin-gated (the bodies are
 *  attacker-controlled and never shown to lower roles). When the
 *  data hook reports `mailForbidden` from a 403 response the section
 *  renders an explicit "ADMIN ROLE REQUIRED" empty state instead of
 *  the generic "no rows" copy. */
export const MailLogPanel: React.FC<Props> = ({
  mail,
  mailForbidden,
  open,
  onToggle,
}) => {
  const [selected, setSelected] = useState<DrawerSelection | null>(null);

  return (
    <>
      <Section
        title={<>STORED MAIL ({mail.length})</>}
        open={open}
        onToggle={onToggle}
      >
        {mailForbidden ? (
          <EmptyState icon={Mail} title="ADMIN ROLE REQUIRED" size="compact" />
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
                  let fields: Record<string, unknown> = {};
                  try {
                    fields = JSON.parse(row.fields || '{}');
                  } catch {
                    // malformed SD params — preview unavailable
                  }
                  const storedAs = fields.stored_as ? String(fields.stored_as) : null;
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
                        {(fields.subject as string | undefined) || '—'}
                      </td>
                      <td
                        className="matrix-text"
                        style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
                      >
                        {(fields.from_hdr as string | undefined) ||
                          (fields.from_addr as string | undefined) ||
                          (fields.mail_from as string | undefined) ||
                          '—'}
                      </td>
                      <td
                        className="matrix-text"
                        style={{
                          fontFamily: 'monospace',
                          whiteSpace: 'nowrap',
                          fontSize: '0.75rem',
                        }}
                      >
                        {(fields.date_hdr as string | undefined) || '—'}
                      </td>
                      <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                        {fields.size ? `${fields.size} B` : '—'}
                      </td>
                      <td>
                        {storedAs && (
                          <button
                            onClick={() => setSelected({ decky: row.decky, storedAs, fields })}
                            title="Inspect stored message"
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
          <EmptyState icon={Mail} title="NO MAIL STORED" size="compact" />
        )}
      </Section>

      {selected && (
        <MailDrawer
          decky={selected.decky}
          storedAs={selected.storedAs}
          fields={selected.fields}
          onClose={() => setSelected(null)}
        />
      )}
    </>
  );
};
