// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { validateNewPassword, MIN_LENGTH, MAX_BYTES, MIN_CLASSES } from './passwordPolicy';

describe('validateNewPassword', () => {
  it('exports the expected constants', () => {
    expect(MIN_LENGTH).toBe(12);
    expect(MAX_BYTES).toBe(72);
    expect(MIN_CLASSES).toBe(3);
  });

  it('empty string — length and class checks fail, ok=false', () => {
    const r = validateNewPassword('');
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.id === 'min-length')!.passed).toBe(false);
    expect(r.checks.find((c) => c.id === 'char-classes')!.passed).toBe(false);
    // max-bytes trivially passes (0 <= 72), but ok is still false
    expect(r.checks.find((c) => c.id === 'max-bytes')!.passed).toBe(true);
    expect(r.classes).toEqual({ lower: false, upper: false, digit: false, special: false });
  });

  it('11 characters — fails length check', () => {
    const r = validateNewPassword('aB1!aB1!aB1'); // 11 chars, 3 classes
    const lengthCheck = r.checks.find((c) => c.id === 'min-length')!;
    expect(lengthCheck.passed).toBe(false);
    expect(r.ok).toBe(false);
  });

  it('exactly 12 characters — passes length check', () => {
    const r = validateNewPassword('aB1!aB1!aB1!'); // 12 chars
    const lengthCheck = r.checks.find((c) => c.id === 'min-length')!;
    expect(lengthCheck.passed).toBe(true);
  });

  it('multibyte: <=72 chars but >72 bytes — fails byte check', () => {
    // Each '€' is 3 bytes in UTF-8. 25 × '€' = 75 bytes but only 25 chars.
    // Pad with ASCII so length >=12 and classes >=3 to isolate the byte check.
    const emoji = '€'.repeat(20) + 'aB1!'; // 24 chars, 20×3+4 = 64 bytes → passes
    const r1 = validateNewPassword(emoji);
    const byteCheck1 = r1.checks.find((c) => c.id === 'max-bytes')!;
    expect(byteCheck1.passed).toBe(true);

    // 25 × '€' (75 bytes) + 'aB1!' → 79 bytes → fails
    const tooBig = '€'.repeat(25) + 'aB1!'; // 29 chars, 79 bytes
    const r2 = validateNewPassword(tooBig);
    const byteCheck2 = r2.checks.find((c) => c.id === 'max-bytes')!;
    expect(byteCheck2.passed).toBe(false);
    expect(r2.ok).toBe(false);
  });

  it('1 class (lowercase only) — class check fails', () => {
    const r = validateNewPassword('abcdefghijkl'); // 12 chars, 1 class
    const cls = r.checks.find((c) => c.id === 'char-classes')!;
    expect(cls.passed).toBe(false);
    expect(r.classes.lower).toBe(true);
    expect(r.classes.upper).toBe(false);
  });

  it('2 classes (lower + upper) — class check fails', () => {
    const r = validateNewPassword('AbcdefGhijkl'); // 12 chars, 2 classes
    const cls = r.checks.find((c) => c.id === 'char-classes')!;
    expect(cls.passed).toBe(false);
    expect(r.classes.lower).toBe(true);
    expect(r.classes.upper).toBe(true);
    expect(r.classes.digit).toBe(false);
  });

  it('3 classes (lower + upper + digit) — class check passes', () => {
    const r = validateNewPassword('AbcdefGhij12'); // 12 chars, 3 classes
    const cls = r.checks.find((c) => c.id === 'char-classes')!;
    expect(cls.passed).toBe(true);
  });

  it('4 classes — class check passes', () => {
    const r = validateNewPassword('AbcdefGh1!23'); // 12 chars, all 4 classes
    const cls = r.checks.find((c) => c.id === 'char-classes')!;
    expect(cls.passed).toBe(true);
    expect(r.classes).toEqual({ lower: true, upper: true, digit: true, special: true });
  });

  it('fully valid strong password — ok=true', () => {
    const r = validateNewPassword('Tr0ub4dor&3xY'); // long, all classes
    expect(r.ok).toBe(true);
    r.checks.forEach((c) => expect(c.passed).toBe(true));
  });
});
