// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import { PlusCircle, Server } from '../../icons';

interface Props {
  /** True when the underlying fleet itself is empty (vs. just filtered down). */
  fleetEmpty: boolean;
  isAdmin: boolean;
  onDeploy: () => void;
}

/** Empty-state shown inside the grid when no cards match. Distinguishes
 *  a genuinely empty fleet (offers a DEPLOY shortcut for admins) from a
 *  filter that hid everything (just nudges the user to widen). */
export const DeckyGridEmpty: React.FC<Props> = ({ fleetEmpty, isAdmin, onDeploy }) => (
  <div className="fleet-empty">
    <Server size={32} className="dim" />
    <span className="dim">
      {fleetEmpty
        ? 'NO DECOYS DEPLOYED IN THIS SECTOR'
        : 'NO DECOYS MATCH CURRENT FILTER'}
    </span>
    {isAdmin && fleetEmpty && (
      <button className="btn violet" onClick={onDeploy}>
        <PlusCircle size={12} /> DEPLOY DECKIES
      </button>
    )}
  </div>
);
