import React from 'react';
import { PlusCircle } from '../../icons';
import type { FilterKey } from './types';

interface Props {
  filter: FilterKey;
  setFilter: (k: FilterKey) => void;
  counts: Record<FilterKey, number>;
  isAdmin: boolean;
  onDeploy: () => void;
}

const FILTER_BUTTONS: ReadonlyArray<readonly [FilterKey, string]> = [
  ['all', 'ALL'],
  ['active', 'ACTIVE'],
  ['hot', 'HOT'],
  ['idle', 'IDLE'],
];

/** Filter pill row + DEPLOY DECKIES action used in the page header.
 *  Counts feed badge text inside each pill so users can see fleet
 *  health without filtering first. */
export const DeckyFilters: React.FC<Props> = ({
  filter, setFilter, counts, isAdmin, onDeploy,
}) => (
  <div className="actions">
    <div className="fleet-filter-group">
      {FILTER_BUTTONS.map(([v, l]) => (
        <button
          key={v}
          onClick={() => setFilter(v)}
          className={`fleet-filter-btn ${filter === v ? 'active' : ''}`}
        >
          {l} {counts[v]}
        </button>
      ))}
    </div>
    {isAdmin && (
      <button className="btn violet" onClick={onDeploy}>
        <PlusCircle size={12} /> DEPLOY DECKIES
      </button>
    )}
  </div>
);
