// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import type { AttackerData } from '../types';

interface Props {
  attacker: AttackerData;
}

/** Top-line counters: events / bounties / credentials / services / deckies,
 *  plus a 2-up scan-vs-interact card when the activity rollup has any
 *  signal. The activity row stays hidden when both arrays are empty so
 *  scan-only attackers without enrichment data don't render dead cards. */
export const AttackerStats: React.FC<Props> = ({ attacker }) => {
  const activity = attacker.service_activity;
  const showActivity =
    !!activity && (activity.scanned.length > 0 || activity.interacted.length > 0);

  return (
    <>
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card">
          <div className="stat-value matrix-text">{attacker.event_count}</div>
          <div className="stat-label">EVENTS</div>
        </div>
        <div className="stat-card">
          <div className="stat-value violet-accent">{attacker.bounty_count}</div>
          <div className="stat-label">BOUNTIES</div>
        </div>
        <div className="stat-card">
          <div className="stat-value violet-accent">{attacker.credential_count}</div>
          <div className="stat-label">CREDENTIALS</div>
        </div>
        <div className="stat-card">
          <div className="stat-value matrix-text">{attacker.service_count}</div>
          <div className="stat-label">SERVICES</div>
        </div>
        <div className="stat-card">
          <div className="stat-value matrix-text">{attacker.decky_count}</div>
          <div className="stat-label">DECKIES</div>
        </div>
      </div>

      {showActivity && activity && (
        <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)' }}>
          <div
            className="stat-card"
            title={
              activity.scanned.length > 0
                ? `Services: ${activity.scanned.join(', ')}`
                : 'No services were scanned without engagement.'
            }
          >
            <div className="stat-value matrix-text">{activity.scanned.length}</div>
            <div className="stat-label">SCANNED · SERVICES</div>
          </div>
          <div
            className="stat-card"
            title={
              activity.interacted.length > 0
                ? `Services: ${activity.interacted.join(', ')}`
                : 'No services were interacted with — scan-only attacker.'
            }
          >
            <div className="stat-value violet-accent">{activity.interacted.length}</div>
            <div className="stat-label">INTERACTED WITH · SERVICES</div>
          </div>
        </div>
      )}
    </>
  );
};
