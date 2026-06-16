// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import { ChevronLeft, ChevronRight, Terminal } from '../../../icons';
import EmptyState from '../../EmptyState/EmptyState';
import { Section } from '../ui';
import type { CommandRow } from '../types';

interface Props {
  commands: CommandRow[];
  cmdTotal: number;
  cmdPage: number;
  cmdLimit: number;
  setCmdPage: (n: number) => void;
  serviceFilter: string | null;
  open: boolean;
  onToggle: () => void;
}

/** COMMANDS collapsible — paginated table of captured shell commands.
 *  Pagination controls live in the Section's `right` slot so they
 *  share the header bar with the title; clicking them is filtered
 *  out of the toggle path by Section's stopPropagation. */
export const CommandsViewer: React.FC<Props> = ({
  commands,
  cmdTotal,
  cmdPage,
  cmdLimit,
  setCmdPage,
  serviceFilter,
  open,
  onToggle,
}) => {
  const cmdTotalPages = Math.ceil(cmdTotal / cmdLimit);
  const title = (
    <>
      COMMANDS ({cmdTotal}
      {serviceFilter ? ` ${serviceFilter.toUpperCase()}` : ''})
    </>
  );
  const right =
    open && cmdTotalPages > 1 ? (
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <span className="dim" style={{ fontSize: '0.8rem' }}>
          Page {cmdPage} of {cmdTotalPages}
        </span>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            disabled={cmdPage <= 1}
            onClick={() => setCmdPage(cmdPage - 1)}
            style={{
              padding: '4px',
              border: '1px solid var(--border-color)',
              opacity: cmdPage <= 1 ? 0.3 : 1,
            }}
          >
            <ChevronLeft size={16} />
          </button>
          <button
            disabled={cmdPage >= cmdTotalPages}
            onClick={() => setCmdPage(cmdPage + 1)}
            style={{
              padding: '4px',
              border: '1px solid var(--border-color)',
              opacity: cmdPage >= cmdTotalPages ? 0.3 : 1,
            }}
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    ) : undefined;

  return (
    <Section title={title} open={open} onToggle={onToggle} right={right}>
      {commands.length > 0 ? (
        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>SERVICE</th>
                <th>DECKY</th>
                <th>COMMAND</th>
              </tr>
            </thead>
            <tbody>
              {commands.map((cmd, i) => (
                <tr key={i}>
                  <td className="dim" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                    {cmd.timestamp ? new Date(cmd.timestamp).toLocaleString() : '-'}
                  </td>
                  <td>{cmd.service}</td>
                  <td className="violet-accent">{cmd.decky}</td>
                  <td className="matrix-text" style={{ fontFamily: 'monospace' }}>
                    {cmd.command}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          icon={Terminal}
          title={
            serviceFilter
              ? `NO ${serviceFilter.toUpperCase()} COMMANDS CAPTURED`
              : 'NO COMMANDS CAPTURED'
          }
          size="compact"
        />
      )}
    </Section>
  );
};
