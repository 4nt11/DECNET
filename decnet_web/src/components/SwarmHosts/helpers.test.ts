// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import {
  AGENT_NAME_RE, bundleSecondsLeft, formatMmSs, shortFp,
} from './helpers';

describe('shortFp', () => {
  it('truncates long fingerprints with an ellipsis', () => {
    expect(shortFp('a'.repeat(64))).toBe('aaaaaaaaaaaaaaaa…');
  });

  it('returns em-dash for empty input', () => {
    expect(shortFp('')).toBe('—');
  });
});

describe('AGENT_NAME_RE', () => {
  it('accepts lowercase / digits / dashes within 1..63 chars', () => {
    expect(AGENT_NAME_RE.test('agent-1')).toBe(true);
    expect(AGENT_NAME_RE.test('a')).toBe(true);
    expect(AGENT_NAME_RE.test('1')).toBe(true);
  });

  it('rejects uppercase, leading dash, and oversized names', () => {
    expect(AGENT_NAME_RE.test('Agent-1')).toBe(false);
    expect(AGENT_NAME_RE.test('-leading')).toBe(false);
    expect(AGENT_NAME_RE.test('a'.repeat(64))).toBe(false);
    expect(AGENT_NAME_RE.test('')).toBe(false);
  });
});

describe('bundleSecondsLeft', () => {
  it('returns the floor of (expires - now) / 1000 in seconds', () => {
    const now = new Date('2026-05-09T08:00:00Z').getTime();
    const exp = new Date('2026-05-09T08:04:30Z').toISOString();
    expect(bundleSecondsLeft(exp, now)).toBe(270);
  });

  it('clamps to zero when already expired', () => {
    const now = new Date('2026-05-09T08:10:00Z').getTime();
    expect(bundleSecondsLeft('2026-05-09T08:05:00Z', now)).toBe(0);
  });

  it('returns 0 for unparseable timestamps', () => {
    expect(bundleSecondsLeft('not-a-date', Date.now())).toBe(0);
  });
});

describe('formatMmSs', () => {
  it('zero-pads minutes and seconds', () => {
    expect(formatMmSs(75)).toEqual({ mm: '01', ss: '15' });
    expect(formatMmSs(9)).toEqual({ mm: '00', ss: '09' });
    expect(formatMmSs(0)).toEqual({ mm: '00', ss: '00' });
  });
});
