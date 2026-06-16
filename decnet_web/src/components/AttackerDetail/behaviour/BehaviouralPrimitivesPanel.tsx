// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import EmptyState from '../../EmptyState/EmptyState';
import { Activity } from '../../../icons';
import type { AttributionPrimitiveState, BehaviouralObservation } from '../types';
import { AttributionBadge } from './pieces';
import {
  BEHAVIOUR_DOMAIN_ICONS, BEHAVIOUR_DOMAIN_LABELS, BEHAVIOUR_DOMAIN_ORDER,
  comparePrimitives, domainOf, leafOf, renderValue,
} from './lookups';

export const BehaviouralPrimitivesPanel: React.FC<{
  observations: ReadonlyArray<BehaviouralObservation>;
  attribution?: ReadonlyMap<string, AttributionPrimitiveState>;
}> = ({ observations, attribution }) => {
  if (!observations.length) {
    return (
      <div data-testid="behaviour-empty">
        <EmptyState
          icon={Activity}
          title="NO BEHAVIOURAL OBSERVATIONS YET"
          hint="The profiler runs once a session ends."
        />
      </div>
    );
  }
  // Group by top-level domain, sort each group by the priority-then-alpha
  // comparator, then walk the canonical domain order.
  const groups = new Map<string, BehaviouralObservation[]>();
  for (const obs of observations) {
    const domain = domainOf(obs.primitive);
    const list = groups.get(domain) ?? [];
    list.push(obs);
    groups.set(domain, list);
  }
  for (const list of groups.values()) {
    list.sort((a, b) => comparePrimitives(a.primitive, b.primitive));
  }
  const orderedDomains = [
    ...BEHAVIOUR_DOMAIN_ORDER.filter((d) => groups.has(d)),
    ...Array.from(groups.keys()).filter((d) => !BEHAVIOUR_DOMAIN_ORDER.includes(d)).sort(),
  ];
  return (
    <div
      className="behaviour-panel"
      data-testid="behaviour-panel"
      style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}
    >
      {orderedDomains.map((domain) => {
        const Icon = BEHAVIOUR_DOMAIN_ICONS[domain] ?? Activity;
        const label = BEHAVIOUR_DOMAIN_LABELS[domain] ?? domain.toUpperCase();
        const rows = groups.get(domain)!;
        return (
          <div
            key={domain}
            className="behaviour-group"
            data-testid={`behaviour-group-${domain}`}
            style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <Icon size={14} style={{ opacity: 0.6 }} />
              <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
                {label}
              </span>
              <span className="dim" style={{ fontSize: '0.65rem', marginLeft: 'auto' }}>
                {rows.length} {rows.length === 1 ? 'PRIMITIVE' : 'PRIMITIVES'}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {rows.map((obs) => (
                <div
                  key={obs.primitive}
                  className="behaviour-row"
                  data-testid={`behaviour-row-${obs.primitive}`}
                  style={{ display: 'flex', gap: '12px', alignItems: 'baseline' }}
                >
                  <span
                    className="behaviour-leaf dim"
                    style={{
                      fontSize: '0.7rem',
                      letterSpacing: '1px',
                      minWidth: '180px',
                      textTransform: 'uppercase',
                    }}
                  >
                    {leafOf(obs.primitive)}
                  </span>
                  <span
                    className="behaviour-value matrix-text"
                    style={{
                      fontFamily: 'monospace',
                      fontSize: '0.85rem',
                      flex: 1,
                      wordBreak: 'break-word',
                    }}
                  >
                    {renderValue(obs.value)}
                  </span>
                  {attribution?.get(obs.primitive) ? (
                    <AttributionBadge state={attribution.get(obs.primitive)!} />
                  ) : null}
                  <span
                    className="behaviour-confidence dim"
                    style={{
                      fontSize: '0.65rem',
                      fontFamily: 'monospace',
                      letterSpacing: '1px',
                      border: '1px solid var(--border-color)',
                      borderRadius: '2px',
                      padding: '1px 6px',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {(obs.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};
