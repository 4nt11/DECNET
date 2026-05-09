/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';

import { BehaviouralPrimitivesPanel } from './BehaviouralPrimitivesPanel';
import type {
  AttributionPrimitiveState, BehaviouralObservation,
} from '../types';

const _attr = (
  primitive: string,
  state: AttributionPrimitiveState['state'],
  confidence = 0.85,
  observation_count = 6,
): AttributionPrimitiveState => ({
  primitive,
  current_value: 'x',
  state,
  confidence,
  observation_count,
  last_change_ts: 1714000000,
  last_observation_ts: 1714000300,
});

const _obs = (
  primitive: string,
  value: unknown,
  confidence = 0.85,
): BehaviouralObservation => ({
  primitive,
  value,
  confidence,
  ts: 1714521660.456,
  source: 'test',
});

describe('BehaviouralPrimitivesPanel', () => {
  it('renders an empty-state placeholder when no observations', () => {
    render(<BehaviouralPrimitivesPanel observations={[]} />);
    expect(screen.getByTestId('behaviour-empty')).toBeInTheDocument();
  });

  it('places day-one priority primitives at the top of their group', () => {
    const observations: BehaviouralObservation[] = [
      _obs('motor.keystroke_cadence', 'steady'),
      _obs('cognitive.tool_vocabulary', 'broad'),
      _obs('motor.input_modality', 'typed'),
      _obs('cognitive.feedback_loop_engagement', 'closed_loop'),
      _obs('cognitive.command_branch_diversity', 'adaptive_branching'),
      _obs('cognitive.inter_command_latency_class', 'typing_speed'),
      _obs('motor.error_correction', 'immediate'),
    ];
    render(<BehaviouralPrimitivesPanel observations={observations} />);

    const motorRows = Array.from(
      document.querySelectorAll('[data-testid^="behaviour-row-motor."]'),
    ).map((el) => el.getAttribute('data-testid')!);
    expect(motorRows[0]).toBe('behaviour-row-motor.input_modality');

    const cogRows = Array.from(
      document.querySelectorAll('[data-testid^="behaviour-row-cognitive."]'),
    ).map((el) => el.getAttribute('data-testid')!);
    expect(cogRows.slice(0, 3)).toEqual([
      'behaviour-row-cognitive.feedback_loop_engagement',
      'behaviour-row-cognitive.command_branch_diversity',
      'behaviour-row-cognitive.inter_command_latency_class',
    ]);
  });

  it('renders the primitive value and a confidence badge', () => {
    const observations: BehaviouralObservation[] = [
      _obs('motor.input_modality', 'pasted', 0.91),
    ];
    render(<BehaviouralPrimitivesPanel observations={observations} />);
    const row = screen.getByTestId('behaviour-row-motor.input_modality');
    expect(row.textContent).toContain('input_modality');
    expect(row.textContent).toContain('pasted');
    expect(row.textContent).toContain('91%');
  });

  it('renders attribution badges only for primitives in the map', () => {
    const observations: BehaviouralObservation[] = [
      _obs('motor.input_modality', 'pasted', 0.91),
      _obs('cognitive.feedback_loop_engagement', 'closed_loop', 0.88),
    ];
    const attribution = new Map<string, AttributionPrimitiveState>([
      ['motor.input_modality', _attr('motor.input_modality', 'stable', 0.95)],
    ]);
    render(
      <BehaviouralPrimitivesPanel
        observations={observations}
        attribution={attribution}
      />,
    );
    const badge = screen.getByTestId('attribution-badge-motor.input_modality');
    expect(badge.textContent).toBe('STABLE');
    expect(badge.getAttribute('data-state')).toBe('stable');
    expect(
      screen.queryByTestId(
        'attribution-badge-cognitive.feedback_loop_engagement',
      ),
    ).toBeNull();
  });

  it('renders each of the five frozen states with a distinct label', () => {
    const cases: [AttributionPrimitiveState['state'], string][] = [
      ['stable', 'STABLE'],
      ['drifting', 'DRIFTING'],
      ['conflicted', 'CONFLICTED'],
      ['multi_actor', 'MULTI-ACTOR'],
      ['unknown', 'UNKNOWN'],
    ];
    const observations: BehaviouralObservation[] = cases.map((_pair, i) =>
      _obs(`motor.synthetic_${i}`, 'x'),
    );
    const attribution = new Map(
      cases.map(([state], i) => [
        `motor.synthetic_${i}`,
        _attr(`motor.synthetic_${i}`, state),
      ]),
    );
    render(
      <BehaviouralPrimitivesPanel
        observations={observations}
        attribution={attribution}
      />,
    );
    for (const [state, label] of cases) {
      const idx = cases.findIndex(([s]) => s === state);
      const badge = screen.getByTestId(
        `attribution-badge-motor.synthetic_${idx}`,
      );
      expect(badge.textContent).toBe(label);
      expect(badge.getAttribute('data-state')).toBe(state);
    }
  });

  it('does not render badges when no attribution prop is provided', () => {
    const observations: BehaviouralObservation[] = [
      _obs('motor.input_modality', 'pasted'),
    ];
    render(<BehaviouralPrimitivesPanel observations={observations} />);
    expect(
      screen.queryByTestId('attribution-badge-motor.input_modality'),
    ).toBeNull();
  });

  it('groups by top-level domain in the canonical order', () => {
    const observations: BehaviouralObservation[] = [
      _obs('emotional_valence.arousal', 'medium_engaged'),
      _obs('temporal.session_duration', 'medium'),
      _obs('motor.input_modality', 'typed'),
      _obs('cognitive.cognitive_load', 'medium'),
    ];
    render(<BehaviouralPrimitivesPanel observations={observations} />);
    const groups = Array.from(
      document.querySelectorAll('[data-testid^="behaviour-group-"]'),
    ).map((el) => el.getAttribute('data-testid')!);
    expect(groups).toEqual([
      'behaviour-group-motor',
      'behaviour-group-cognitive',
      'behaviour-group-temporal',
      'behaviour-group-emotional_valence',
    ]);
  });
});
