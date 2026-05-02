import React, { useEffect, useState } from 'react';
import { Crosshair, Download, Target } from '../icons';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import TTPInspector from './TTPInspector';

/*
 * TTPsObservedSection — shared between IdentityDetail (primary) and
 * AttackerDetail (per-IP slice). Renders the tactic → technique tree
 * with counts and confidence-weighted bars per TTP_TAGGING.md
 * §"UI surface". Empty state is the literal "No techniques observed
 * yet." per the design doc — no spinner, no fallback list.
 *
 * Admin-only rule-state controls live in :class:`RuleStateControls`,
 * not here — the analyst-facing rollup is a separate concern from
 * operator rule administration.
 */

interface TechniqueRow {
  technique_id: string;
  sub_technique_id: string | null;
  tactic: string;
  count: number;
  first_seen: string;
  last_seen: string;
  confidence_max: number;
}

const TACTIC_LABEL: Record<string, string> = {
  TA0043: 'RECONNAISSANCE',
  TA0042: 'RESOURCE DEVELOPMENT',
  TA0001: 'INITIAL ACCESS',
  TA0002: 'EXECUTION',
  TA0003: 'PERSISTENCE',
  TA0004: 'PRIVILEGE ESCALATION',
  TA0005: 'DEFENSE EVASION',
  TA0006: 'CREDENTIAL ACCESS',
  TA0007: 'DISCOVERY',
  TA0008: 'LATERAL MOVEMENT',
  TA0009: 'COLLECTION',
  TA0011: 'COMMAND AND CONTROL',
  TA0010: 'EXFILTRATION',
  TA0040: 'IMPACT',
};

const tacticOrder = (id: string): number => {
  const order = ['TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004',
                 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011',
                 'TA0010', 'TA0040'];
  const idx = order.indexOf(id);
  return idx >= 0 ? idx : 99;
};

interface Props {
  scope: 'identity' | 'attacker';
  uuid: string;
}

const TTPsObservedSection: React.FC<Props> = ({ scope, uuid }) => {
  const [rows, setRows] = useState<TechniqueRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<TechniqueRow | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetchRollup = async () => {
      try {
        const res = await api.get(`/ttp/by-${scope}/${uuid}`);
        if (cancelled) return;
        setRows(Array.isArray(res.data) ? res.data : []);
        setError(null);
      } catch {
        if (cancelled) return;
        setRows([]);
        setError('FAILED TO LOAD TTPs');
      } finally {
        if (!cancelled) setLoaded(true);
      }
    };
    fetchRollup();
    return () => { cancelled = true; };
  }, [scope, uuid]);

  // Group by tactic in fixed UKC-aligned order.
  const byTactic = rows.reduce<Record<string, TechniqueRow[]>>((acc, r) => {
    (acc[r.tactic] ??= []).push(r);
    return acc;
  }, {});
  const tacticIds = Object.keys(byTactic).sort(
    (a, b) => tacticOrder(a) - tacticOrder(b),
  );

  const handleNavigatorExport = async () => {
    if (scope !== 'identity') return;
    try {
      const res = await api.get(`/ttp/export/navigator/identity/${uuid}`);
      const blob = new Blob([JSON.stringify(res.data, null, 2)],
                           { type: 'application/json' });
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = `navigator-identity-${uuid.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(href);
    } catch {
      // best-effort download; surface nothing
    }
  };

  return (
    <div className="logs-section">
      <div className="section-header">
        <div className="section-title">
          <Target size={14} />
          <span>TTPs OBSERVED</span>
        </div>
        {scope === 'identity' && rows.length > 0 && (
          <button
            type="button"
            className="btn"
            onClick={handleNavigatorExport}
            title="Download MITRE ATT&CK Navigator JSON layer for this Identity"
          >
            <Download size={12} />
            <span style={{ marginLeft: 6 }}>NAVIGATOR</span>
          </button>
        )}
      </div>
      <div className="logs-table-container" style={{ padding: 12 }}>
        {!loaded ? null : error ? (
          <EmptyState icon={Crosshair} title={error} />
        ) : rows.length === 0 ? (
          // Literal empty-state text from TTP_TAGGING.md §"UI surface
          // — Empty state": "No techniques observed yet." No spinner.
          <EmptyState icon={Crosshair} title="NO TECHNIQUES OBSERVED YET" />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {tacticIds.map((tid) => (
              <div key={tid} className="fp-group">
                <div className="fp-group-label">
                  <span>{TACTIC_LABEL[tid] ?? tid}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {byTactic[tid].map((r) => (
                    <TechniqueBar
                      key={`${r.technique_id}-${r.sub_technique_id ?? ''}`}
                      row={r}
                      onClick={() => setSelected(r)}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      {selected && (
        <TTPInspector
          scope={scope}
          uuid={uuid}
          techniqueId={selected.technique_id}
          subTechniqueId={selected.sub_technique_id}
          tactic={selected.tactic}
          count={selected.count}
          confidenceMax={selected.confidence_max}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
};

const TechniqueBar: React.FC<{
  row: TechniqueRow;
  onClick: () => void;
}> = ({ row, onClick }) => {
  // Confidence bar: 0..1 mapped to 0..100% width. Values below 0.3
  // can never appear (repo confidence floor) so the bar always shows
  // some non-trivial fill.
  const pct = Math.round(Math.max(0, Math.min(1, row.confidence_max)) * 100);
  const label = row.sub_technique_id ?? row.technique_id;
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick();
        }
      }}
      title="Click to inspect underlying tags + evidence"
      style={{
        display: 'grid',
        gridTemplateColumns: '160px 1fr 60px',
        gap: 8,
        alignItems: 'center',
        cursor: 'pointer',
        padding: '2px 4px',
        borderRadius: 2,
      }}
      onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(155,135,245,0.06)'; }}
      onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
    >
      <span className="matrix-text">{label}</span>
      <div
        style={{
          height: 6,
          background: 'var(--surface-2, #1a1a1a)',
          borderRadius: 2,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${pct}%`,
            height: '100%',
            background: 'var(--violet-accent, #9b87f5)',
          }}
          title={`confidence ${row.confidence_max.toFixed(2)}`}
        />
      </div>
      <span className="dim" style={{ textAlign: 'right' }}>×{row.count}</span>
    </div>
  );
};

export default TTPsObservedSection;
