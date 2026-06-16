// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import {
  Activity, Crosshair, Radio, Timer, Wifi,
} from '../../../icons';
import { Tag } from '../ui';
import { seqClassColor } from '../fingerprints';
import type { AttackerBehavior, AttributionPrimitiveState } from '../types';
import {
  ATTRIBUTION_STATE_STYLE, BEHAVIOR_COLORS, BEHAVIOR_LABELS,
  C2_TOOLS, OS_LABELS, TOOL_LABELS, fmtOpt, fmtSecs,
} from './lookups';

export const StatBlock: React.FC<{ label: string; value: React.ReactNode; color?: string }> = ({
  label, value, color,
}) => (
  <div className="stat-card">
    <div className="stat-value" style={{ color: color || 'var(--text-color)' }}>
      {value}
    </div>
    <div className="stat-label">{label}</div>
  </div>
);

export const KeyValueRow: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div style={{ display: 'flex', gap: '12px', alignItems: 'baseline' }}>
    <span className="dim" style={{ fontSize: '0.7rem', letterSpacing: '1px', minWidth: '120px' }}>
      {label}
    </span>
    <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
      {value}
    </span>
  </div>
);

export const BehaviorHeadline: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const osLabel = b.os_guess ? (OS_LABELS[b.os_guess] || b.os_guess.toUpperCase()) : '—';
  const behaviorLabel = b.behavior_class
    ? (BEHAVIOR_LABELS[b.behavior_class] || b.behavior_class.toUpperCase())
    : 'UNKNOWN';
  const behaviorColor = b.behavior_class ? BEHAVIOR_COLORS[b.behavior_class] : undefined;
  return (
    <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
      <StatBlock label="OS GUESS" value={osLabel} />
      <StatBlock label="HOP DISTANCE" value={fmtOpt(b.hop_distance)} />
      <StatBlock label="ATTACK PATTERN" value={behaviorLabel} color={behaviorColor} />
    </div>
  );
};

export const DetectedToolsBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const tools = b.tool_guesses && b.tool_guesses.length > 0 ? b.tool_guesses : null;
  if (!tools) return null;
  return (
    <div style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Crosshair size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          DETECTED TOOLS
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {tools.map((t) => (
          <div key={t} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span
              style={{
                fontSize: '0.8rem',
                fontFamily: 'monospace',
                fontWeight: 'bold',
                color: '#ff6b6b',
                minWidth: '160px',
              }}
            >
              {TOOL_LABELS[t] || t.toUpperCase()}
            </span>
            <span
              style={{
                fontSize: '0.65rem',
                fontFamily: 'monospace',
                letterSpacing: '1px',
                color: 'var(--dim-color)',
                border: '1px solid var(--border-color)',
                borderRadius: '2px',
                padding: '1px 6px',
              }}
            >
              {C2_TOOLS.has(t) ? 'BEACON TIMING' : 'HTTP HEADER'}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export const BeaconBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  if (b.behavior_class !== 'beaconing' || b.beacon_interval_s === null) return null;
  return (
    <div style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Radio size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          BEACON CADENCE
        </span>
      </div>
      <div style={{ display: 'flex', gap: '32px', alignItems: 'baseline' }}>
        <div>
          <span className="dim" style={{ fontSize: '0.7rem' }}>INTERVAL </span>
          <span className="matrix-text" style={{ fontSize: '1.3rem', fontWeight: 'bold' }}>
            {fmtSecs(b.beacon_interval_s)}
          </span>
        </div>
        {b.beacon_jitter_pct !== null && (
          <div>
            <span className="dim" style={{ fontSize: '0.7rem' }}>JITTER </span>
            <span className="matrix-text" style={{ fontSize: '1.3rem', fontWeight: 'bold' }}>
              {b.beacon_jitter_pct.toFixed(1)}%
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

export const TcpStackBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const fp = b.tcp_fingerprint;
  if (!fp || (!fp.window && !fp.mss && !fp.options_sig && fp.dscp == null && fp.ecn == null)) return null;
  return (
    <div style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Wifi size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          TCP STACK (PASSIVE)
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
          {fp.window !== null && fp.window !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>WIN </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>{fp.window}</span>
            </div>
          )}
          {fp.wscale !== null && fp.wscale !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>WSCALE </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>{fp.wscale}</span>
            </div>
          )}
          {fp.mss !== null && fp.mss !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>MSS </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem' }}>{fp.mss}</span>
            </div>
          )}
          {fp.dscp !== null && fp.dscp !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>DSCP </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem' }}>{fp.dscp}</span>
            </div>
          )}
          {fp.ecn !== null && fp.ecn !== undefined && (
            <div>
              <span className="dim" style={{ fontSize: '0.7rem' }}>ECN </span>
              <span className="matrix-text" style={{ fontSize: '1.1rem' }}>{fp.ecn}</span>
            </div>
          )}
          <div>
            <span className="dim" style={{ fontSize: '0.7rem' }}>RETRANSMITS </span>
            <span
              className="matrix-text"
              style={{
                fontSize: '1.1rem',
                fontWeight: 'bold',
                color: b.retransmit_count > 0 ? '#e5c07b' : undefined,
              }}
            >
              {b.retransmit_count}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {fp.has_sack && <Tag>SACK</Tag>}
          {fp.has_timestamps && <Tag>TS</Tag>}
          {fp.ipid_class && fp.ipid_class !== 'unknown' && (
            <Tag color={seqClassColor(fp.ipid_class)}>IPID:{fp.ipid_class.toUpperCase()}</Tag>
          )}
          {fp.isn_class && fp.isn_class !== 'unknown' && (
            <Tag color={seqClassColor(fp.isn_class)}>
              {fp.isn_class !== 'random' && '⚠ '}
              ISN:{fp.isn_class.toUpperCase()}
            </Tag>
          )}
        </div>
        {fp.options_sig && (
          <div>
            <span className="dim" style={{ fontSize: '0.7rem' }}>OPTS: </span>
            <span className="matrix-text" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {fp.options_sig}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

export const TimingStatsBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const s = b.timing_stats;
  if (!s || !s.event_count || s.event_count < 2) return null;
  return (
    <div style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Timer size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          INTER-EVENT TIMING
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <KeyValueRow label="EVENT COUNT" value={s.event_count ?? '—'} />
        <KeyValueRow label="DURATION" value={fmtSecs(s.duration_s)} />
        <KeyValueRow label="MEAN IAT" value={fmtSecs(s.mean_iat_s)} />
        <KeyValueRow label="MEDIAN IAT" value={fmtSecs(s.median_iat_s)} />
        <KeyValueRow label="STDEV IAT" value={fmtSecs(s.stdev_iat_s)} />
        <KeyValueRow
          label="MIN / MAX IAT"
          value={`${fmtSecs(s.min_iat_s)} / ${fmtSecs(s.max_iat_s)}`}
        />
        <KeyValueRow
          label="CV (JITTER)"
          value={s.cv !== null && s.cv !== undefined ? s.cv.toFixed(3) : '—'}
        />
      </div>
    </div>
  );
};

export const PhaseSequenceBlock: React.FC<{ b: AttackerBehavior }> = ({ b }) => {
  const p = b.phase_sequence;
  if (!p || (!p.recon_end_ts && !p.exfil_start_ts && !p.large_payload_count)) return null;
  return (
    <div style={{ border: '1px solid var(--border-color)', padding: '12px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <Activity size={14} style={{ opacity: 0.6 }} />
        <span style={{ fontSize: '0.75rem', letterSpacing: '2px', fontWeight: 'bold' }}>
          PHASE SEQUENCE
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <KeyValueRow
          label="RECON END"
          value={p.recon_end_ts ? new Date(p.recon_end_ts).toLocaleString() : '—'}
        />
        <KeyValueRow
          label="EXFIL START"
          value={p.exfil_start_ts ? new Date(p.exfil_start_ts).toLocaleString() : '—'}
        />
        <KeyValueRow label="RECON→EXFIL LATENCY" value={fmtSecs(p.exfil_latency_s)} />
        <KeyValueRow
          label="LARGE PAYLOADS"
          value={p.large_payload_count ?? 0}
        />
      </div>
    </div>
  );
};

export const AttributionBadge: React.FC<{ state: AttributionPrimitiveState }> = ({ state }) => {
  const style = ATTRIBUTION_STATE_STYLE[state.state] ?? ATTRIBUTION_STATE_STYLE.unknown;
  return (
    <span
      className="attribution-badge"
      data-testid={`attribution-badge-${state.primitive}`}
      data-state={state.state}
      title={
        `${style.label} • confidence ${(state.confidence * 100).toFixed(0)}% ` +
        `over ${state.observation_count} observation${state.observation_count === 1 ? '' : 's'}`
      }
      style={{
        fontSize: '0.6rem',
        letterSpacing: '1px',
        fontFamily: 'monospace',
        padding: '1px 6px',
        borderRadius: '2px',
        background: style.bg,
        color: style.fg,
        border: `1px solid ${style.border}`,
        whiteSpace: 'nowrap',
      }}
    >
      {style.label}
    </span>
  );
};
