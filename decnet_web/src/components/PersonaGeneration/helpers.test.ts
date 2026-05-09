import { describe, it, expect } from 'vitest';
import { coercePersona, mergePersonas, validate, BLANK } from './helpers';
import type { EmailPersona } from './types';

const persona = (over: Partial<EmailPersona> = {}): EmailPersona => ({
  ...BLANK, name: 'Jane', email: 'jane@example.com', role: 'admin', ...over,
});

describe('validate', () => {
  it('rejects missing required fields', () => {
    expect(validate({ ...BLANK })).toBe('name is required');
    expect(validate(persona({ email: '' }))).toBe('email is required');
    expect(validate(persona({ email: 'bad' }))).toMatch(/user@domain/);
    expect(validate(persona({ role: '' }))).toBe('role is required');
  });

  it('requires tone_custom when tone=custom', () => {
    expect(validate(persona({ tone: 'custom' }))).toMatch(/custom tone/);
    expect(validate(persona({ tone: 'custom', tone_custom: 'wry' }))).toBeNull();
  });

  it('caps mannerisms at 12', () => {
    const many = Array.from({ length: 13 }, (_, i) => `m${i}`);
    expect(validate(persona({ mannerisms: many }))).toMatch(/at most 12/);
  });

  it('returns null for a valid persona', () => {
    expect(validate(persona())).toBeNull();
  });
});

describe('coercePersona', () => {
  it('rejects non-objects and missing fields', () => {
    expect(coercePersona(null)).toEqual({ error: 'entry is not an object' });
    expect(coercePersona({})).toEqual({ error: 'missing name' });
    expect(coercePersona({ name: 'a' })).toEqual({ error: 'missing email' });
    expect(coercePersona({ name: 'a', email: 'a@b.c' })).toEqual({ error: 'missing role' });
  });

  it('rejects invalid emails', () => {
    const r = coercePersona({ name: 'a', email: 'noat', role: 'r' });
    expect('error' in r && r.error).toMatch(/invalid email/);
  });

  it('clamps mannerisms and slices long tone_custom', () => {
    const long = 'x'.repeat(200);
    const r = coercePersona({
      name: 'a', email: 'a@b.c', role: 'r',
      tone: 'custom', tone_custom: long,
      mannerisms: Array.from({ length: 20 }, (_, i) => `m${i}`).concat([42, null]),
    });
    expect('ok' in r).toBe(true);
    if ('ok' in r) {
      expect(r.ok.tone_custom?.length).toBe(128);
      expect(r.ok.mannerisms.length).toBe(12);
      expect(r.ok.mannerisms.every((m) => typeof m === 'string')).toBe(true);
    }
  });

  it('falls back tone/reply_latency to defaults on bad input', () => {
    const r = coercePersona({
      name: 'a', email: 'a@b.c', role: 'r',
      tone: 'bogus', reply_latency: 'wat',
    });
    expect('ok' in r).toBe(true);
    if ('ok' in r) {
      expect(r.ok.tone).toBe('formal');
      expect(r.ok.reply_latency).toBe('normal');
    }
  });

  it('rejects tone=custom without tone_custom', () => {
    const r = coercePersona({
      name: 'a', email: 'a@b.c', role: 'r', tone: 'custom',
    });
    expect('error' in r && r.error).toMatch(/tone="custom"/);
  });
});

describe('mergePersonas', () => {
  it('adds new and replaces by lowercased email', () => {
    const current = [persona({ email: 'A@x.com', name: 'old' })];
    const incoming = [persona({ email: 'a@x.com', name: 'new' }), persona({ email: 'b@x.com' })];
    const r = mergePersonas(current, incoming);
    expect(r.added).toBe(1);
    expect(r.replaced).toBe(1);
    expect(r.merged.find((p) => p.email.toLowerCase() === 'a@x.com')?.name).toBe('new');
  });
});
