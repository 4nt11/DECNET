import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';

import {
  BehaviouralPrimitivesPanel,
  type BehaviouralObservation,
} from './AttackerDetail';

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
    // Mix priority + non-priority primitives in arbitrary input order.
    const observations: BehaviouralObservation[] = [
      _obs('motor.keystroke_cadence', 'steady'),
      _obs('cognitive.tool_vocabulary', 'broad'),
      _obs('motor.input_modality', 'typed'), // priority #1
      _obs('cognitive.feedback_loop_engagement', 'closed_loop'), // priority #2
      _obs('cognitive.command_branch_diversity', 'adaptive_branching'), // #3
      _obs('cognitive.inter_command_latency_class', 'typing_speed'), // #4
      _obs('motor.error_correction', 'immediate'),
    ];
    render(<BehaviouralPrimitivesPanel observations={observations} />);

    // motor group: input_modality must precede the alphabetised rest.
    const motorRows = Array.from(
      document.querySelectorAll('[data-testid^="behaviour-row-motor."]'),
    ).map((el) => el.getAttribute('data-testid')!);
    expect(motorRows[0]).toBe('behaviour-row-motor.input_modality');

    // cognitive group: the three priority primitives must be in the
    // documented order at the top.
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
