// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo } from 'react';
import { Search } from '../../icons';
import type { CanaryTokenRow } from '../CanaryTokenDrawer';
import { STATE_COLOR } from './types';
import { INPUT_STYLE } from './ui';

export type StateFilter = 'all' | 'planted' | 'revoked' | 'failed';
export type ScopeFilter = 'all' | 'fleet' | 'topology';

interface Props {
  tokens: CanaryTokenRow[];
  loading: boolean;
  error: string | null;
  filter: string;
  setFilter: (s: string) => void;
  stateFilter: StateFilter;
  setStateFilter: (s: StateFilter) => void;
  scopeFilter: ScopeFilter;
  setScopeFilter: (s: ScopeFilter) => void;
  onPick: (t: CanaryTokenRow) => void;
}

/** Tokens tab: text search + state/scope filter selectors over a
 *  flat row grid. Clicking a row passes the token up to the page,
 *  which opens the CanaryTokenDrawer. */
export const TokenListView: React.FC<Props> = ({
  tokens, loading, error,
  filter, setFilter,
  stateFilter, setStateFilter,
  scopeFilter, setScopeFilter,
  onPick,
}) => {
  const visibleTokens = useMemo(() => {
    return tokens.filter((t) => {
      if (stateFilter !== 'all' && t.state !== stateFilter) return false;
      if (scopeFilter === 'fleet' && t.topology_id) return false;
      if (scopeFilter === 'topology' && !t.topology_id) return false;
      if (!filter) return true;
      const f = filter.toLowerCase();
      return (
        t.decky_name.toLowerCase().includes(f) ||
        t.placement_path.toLowerCase().includes(f) ||
        t.callback_token.toLowerCase().includes(f) ||
        (t.generator || '').toLowerCase().includes(f) ||
        (t.instrumenter || '').toLowerCase().includes(f) ||
        (t.topology_id || '').toLowerCase().includes(f)
      );
    });
  }, [tokens, filter, stateFilter, scopeFilter]);

  return (
    <>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: '1 1 300px' }}>
          <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', opacity: 0.5 }} />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by decky / path / slug / generator…"
            style={{ ...INPUT_STYLE, paddingLeft: '32px', marginBottom: 0 }}
          />
        </div>
        <select
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value as StateFilter)}
          style={{ ...INPUT_STYLE, marginBottom: 0, width: 'auto' }}
        >
          <option value="all">all states</option>
          <option value="planted">planted</option>
          <option value="revoked">revoked</option>
          <option value="failed">failed</option>
        </select>
        <select
          value={scopeFilter}
          onChange={(e) => setScopeFilter(e.target.value as ScopeFilter)}
          style={{ ...INPUT_STYLE, marginBottom: 0, width: 'auto' }}
        >
          <option value="all">all scopes</option>
          <option value="fleet">fleet only</option>
          <option value="topology">topology only</option>
        </select>
      </div>

      {loading && <div style={{ opacity: 0.6 }}>loading…</div>}
      {error && <div style={{ color: '#ff5555', marginBottom: '16px' }}>{error}</div>}
      {!loading && visibleTokens.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px', opacity: 0.6, fontSize: '0.85rem' }}>
          {tokens.length === 0
            ? 'No canary tokens yet. Click NEW TOKEN to plant one, or UPLOAD ARTIFACT to start with an operator-supplied document.'
            : 'No tokens match the current filter.'}
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {visibleTokens.map((t) => (
          <button
            key={t.uuid}
            onClick={() => onPick(t)}
            style={{
              display: 'grid',
              gridTemplateColumns: '110px 80px 140px 1fr 100px 110px 80px',
              alignItems: 'center', gap: '12px',
              padding: '10px 14px',
              border: '1px solid var(--border-color, #30363d)',
              background: 'var(--matrix-tint-5)',
              color: 'var(--text-color)',
              cursor: 'pointer',
              textAlign: 'left',
              fontSize: '0.8rem',
            }}
          >
            <span style={{
              color: STATE_COLOR[t.state], fontFamily: 'monospace',
              fontSize: '0.7rem', letterSpacing: '0.05em',
            }}>
              ● {t.state.toUpperCase()}
            </span>
            <span
              title={t.topology_id ? `topology ${t.topology_id}` : 'fleet'}
              style={{
                fontSize: '0.65rem', letterSpacing: '0.05em',
                padding: '2px 6px',
                border: `1px solid ${t.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)'}`,
                color: t.topology_id ? 'var(--accent-color, #00ff88)' : 'var(--dim-color)',
                textAlign: 'center',
                textTransform: 'uppercase',
              }}
            >
              {t.topology_id ? 'topology' : 'fleet'}
            </span>
            <span style={{ fontFamily: 'monospace' }}>{t.decky_name}</span>
            <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {t.placement_path}
            </span>
            <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>
              {t.kind === 'aws_passive' ? 'aws-passive' : t.kind}
            </span>
            <span style={{ fontSize: '0.7rem', opacity: 0.7, fontFamily: 'monospace' }}>
              {t.generator || t.instrumenter || '?'}
            </span>
            <span style={{ textAlign: 'right', fontFamily: 'monospace', color: t.trigger_count > 0 ? '#00ff88' : 'var(--dim-color)' }}>
              {t.trigger_count} {t.trigger_count === 1 ? 'hit' : 'hits'}
            </span>
          </button>
        ))}
      </div>
    </>
  );
};
