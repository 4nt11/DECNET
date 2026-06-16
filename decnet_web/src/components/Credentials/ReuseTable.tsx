// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import { ChevronRight as ChevR, Target } from '../../icons';
import EmptyState from '../EmptyState/EmptyState';
import SortTh from './SortTh';
import type { CredentialReuseRow, SortDir } from './types';

interface Props {
  rows: CredentialReuseRow[];
  loading: boolean;
  sortCol: string;
  sortDir: SortDir;
  onSort: (col: string) => void;
  onSelect: (r: CredentialReuseRow) => void;
}

const ReuseTable: React.FC<Props> = ({
  rows, loading, sortCol, sortDir, onSort, onSelect,
}) => (
  <table className="logs-table">
    <thead>
      <tr>
        <SortTh col="seen" activeCol={sortCol} dir={sortDir} onSort={onSort}>LAST SEEN</SortTh>
        <SortTh col="principal" activeCol={sortCol} dir={sortDir} onSort={onSort}>PRINCIPAL</SortTh>
        <SortTh col="kind" activeCol={sortCol} dir={sortDir} onSort={onSort}>KIND</SortTh>
        <SortTh col="targets" activeCol={sortCol} dir={sortDir} onSort={onSort}>TARGETS</SortTh>
        <SortTh col="attempts" activeCol={sortCol} dir={sortDir} onSort={onSort}>ATTEMPTS</SortTh>
        <th>DECKIES</th>
        <th>SERVICES</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {rows.length > 0 ? rows.map((r) => {
        const isPlain = r.secret_kind === 'plaintext';
        const moreDeckies = Math.max(0, r.deckies.length - 3);
        const moreServices = Math.max(0, r.services.length - 3);
        return (
          <tr key={r.id} className="clickable" onClick={() => onSelect(r)}>
            <td className="dim" style={{ fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
              {new Date(r.last_seen).toLocaleTimeString()}
            </td>
            <td className="principal-cell">
              {r.principal ?? <span className="dim">—</span>}
            </td>
            <td>
              <span className={`chip ${isPlain ? 'matrix' : 'violet'}`}>
                {r.secret_kind.toUpperCase()}
              </span>
            </td>
            <td><span className="attempt-pill">{r.target_count}</span></td>
            <td><span className="attempt-pill">{r.attempt_count}</span></td>
            <td>
              {r.deckies.slice(0, 3).map((d) => (
                <span key={d} className="chip dim-chip" style={{ marginRight: 4 }}>{d}</span>
              ))}
              {moreDeckies > 0 && <span className="dim">+{moreDeckies}</span>}
            </td>
            <td>
              {r.services.slice(0, 3).map((s) => (
                <span key={s} className="chip dim-chip" style={{ marginRight: 4 }}>{s}</span>
              ))}
              {moreServices > 0 && <span className="dim">+{moreServices}</span>}
            </td>
            <td style={{ textAlign: 'right', opacity: 0.4 }}>
              <ChevR size={14} />
            </td>
          </tr>
        );
      }) : (
        <tr>
          <td colSpan={8}>
            <EmptyState
              icon={Target}
              title={loading ? 'RETRIEVING REUSE…' : 'NO REUSE FINDINGS YET'}
              hint={loading ? undefined : 'a credential captured on ≥2 deckies will land here'}
            />
          </td>
        </tr>
      )}
    </tbody>
  </table>
);

export default ReuseTable;
