import { describe, it, expect } from 'vitest';
import {
  BLANK_FORM, deriveSimpleEvents, formatDate, formToPayload,
} from './helpers';

describe('deriveSimpleEvents', () => {
  it('returns the matching preset names when patterns are an exact union', () => {
    expect(deriveSimpleEvents(['attacker.>'])).toEqual(['AttackerDetail']);
    expect(deriveSimpleEvents(['decky.*.state', 'decky.*.traffic']))
      .toEqual(['DeckyStatus']);
    expect(deriveSimpleEvents(['attacker.>', 'system.>']).sort())
      .toEqual(['AttackerDetail', 'SystemStatus']);
  });

  it('returns [] when any extra pattern leaks past the presets', () => {
    expect(deriveSimpleEvents(['attacker.>', 'custom.topic'])).toEqual([]);
  });

  it('returns [] when a preset is partially matched', () => {
    expect(deriveSimpleEvents(['decky.*.state'])).toEqual([]);
  });

  it('returns [] for empty input', () => {
    expect(deriveSimpleEvents([])).toEqual([]);
  });
});

describe('formatDate', () => {
  it('returns em-dash for null/empty', () => {
    expect(formatDate(null)).toBe('—');
  });

  it('returns the raw string for unparseable input', () => {
    expect(formatDate('not-a-date')).toBe('not-a-date');
  });

  it('renders YYYY-MM-DD HH:MM for a valid ISO string', () => {
    const out = formatDate('2026-03-05T08:09:00Z');
    expect(out).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
  });
});

describe('formToPayload', () => {
  it('trims name/url and splits topic_patterns by newline', () => {
    const payload = formToPayload({
      ...BLANK_FORM,
      name: '  shuffle  ',
      url: ' https://x/y ',
      topic_patterns: 'attacker.>\n\n  decky.*.state  \n',
      simple_events: ['SystemStatus'],
    });
    expect(payload.name).toBe('shuffle');
    expect(payload.url).toBe('https://x/y');
    expect(payload.topic_patterns).toEqual(['attacker.>', 'decky.*.state']);
    expect(payload.simple_events).toEqual(['SystemStatus']);
  });

  it('omits secret when blank, includes it when set', () => {
    expect(formToPayload({ ...BLANK_FORM, secret: '' }).secret).toBeUndefined();
    expect(formToPayload({ ...BLANK_FORM, secret: 'topsecret' }).secret).toBe('topsecret');
  });
});
