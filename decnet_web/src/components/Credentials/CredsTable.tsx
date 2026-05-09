import React from 'react';
import { ChevronRight as ChevR, Target } from '../../icons';
import EmptyState from '../EmptyState/EmptyState';
import SortTh from './SortTh';
import { reuseKey, truncHash } from './helpers';
import type {
  CredentialEntry, ReuseMapEntry, SortDir,
} from './types';

interface Props {
  rows: CredentialEntry[];
  reuseMap: Map<string, ReuseMapEntry>;
  loading: boolean;
  sortCol: string;
  sortDir: SortDir;
  onSort: (col: string) => void;
  onSelectCred: (c: CredentialEntry) => void;
  onSelectAttacker: (ip: string) => void;
  onOpenReuse: (key: string) => void;
}

const CredsTable: React.FC<Props> = ({
  rows, reuseMap, loading, sortCol, sortDir, onSort,
  onSelectCred, onSelectAttacker, onOpenReuse,
}) => (
  <table className="logs-table">
    <thead>
      <tr>
        <SortTh col="seen" activeCol={sortCol} dir={sortDir} onSort={onSort}>LAST SEEN</SortTh>
        <SortTh col="decky" activeCol={sortCol} dir={sortDir} onSort={onSort}>DECKY</SortTh>
        <SortTh col="svc" activeCol={sortCol} dir={sortDir} onSort={onSort}>SVC</SortTh>
        <SortTh col="attacker" activeCol={sortCol} dir={sortDir} onSort={onSort}>ATTACKER</SortTh>
        <SortTh col="principal" activeCol={sortCol} dir={sortDir} onSort={onSort}>PRINCIPAL</SortTh>
        <th>SECRET</th>
        <SortTh col="kind" activeCol={sortCol} dir={sortDir} onSort={onSort}>KIND</SortTh>
        <SortTh col="hits" activeCol={sortCol} dir={sortDir} onSort={onSort}>HITS</SortTh>
        <th>REUSE</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {rows.length > 0 ? rows.map((c) => {
        const isPlain = c.secret_kind === 'plaintext';
        const secretText = isPlain
          ? (c.secret_printable ?? '—')
          : truncHash(c.secret_sha256, 16);
        const key = reuseKey(c.secret_sha256, c.secret_kind, c.principal);
        const reuseHit = reuseMap.get(key);
        return (
          <tr key={c.id} className="clickable" onClick={() => onSelectCred(c)}>
            <td className="dim" style={{ fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
              {new Date(c.last_seen).toLocaleTimeString()}
            </td>
            <td className="violet-accent">{c.decky_name}</td>
            <td><span className="chip dim-chip">{c.service}</span></td>
            <td>
              <span
                className="matrix-text attacker-link"
                onClick={(e) => { e.stopPropagation(); onSelectAttacker(c.attacker_ip); }}
              >
                {c.attacker_ip}
              </span>
            </td>
            <td className="principal-cell">
              {c.principal ?? <span className="dim">—</span>}
            </td>
            <td>
              <span className={`secret-cell${isPlain ? '' : ' hashed'}`} title={secretText}>
                {secretText}
              </span>
            </td>
            <td>
              <span className={`chip ${isPlain ? 'matrix' : 'violet'}`}>
                {c.secret_kind.toUpperCase()}
              </span>
            </td>
            <td>
              <span className="attempt-pill">{c.attempt_count}</span>
            </td>
            <td>
              {reuseHit ? (
                <span
                  className="attempt-pill"
                  style={{ cursor: 'pointer', color: 'var(--violet)' }}
                  title="Open reuse finding"
                  onClick={(e) => { e.stopPropagation(); onOpenReuse(key); }}
                >
                  ×{reuseHit.target_count}
                </span>
              ) : (
                <span className="dim">—</span>
              )}
            </td>
            <td style={{ textAlign: 'right', opacity: 0.4 }}>
              <ChevR size={14} />
            </td>
          </tr>
        );
      }) : (
        <tr>
          <td colSpan={10}>
            <EmptyState
              icon={Target}
              title={loading ? 'RETRIEVING CREDENTIALS…' : 'NO CREDENTIALS YET'}
              hint={loading ? undefined : 'captured auth attempts will land here'}
            />
          </td>
        </tr>
      )}
    </tbody>
  </table>
);

export default CredsTable;
