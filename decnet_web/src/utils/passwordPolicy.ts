// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Client-side password policy mirror.
// NOTE: This is advisory UX only — the API remains the enforcement boundary.
// Keep constants in sync with decnet/web/db/models/auth.py ChangePasswordRequest.

export const MIN_LENGTH = 12;
export const MAX_BYTES = 72;
export const MIN_CLASSES = 3;

export interface PasswordCheck {
  id: string;
  label: string;
  passed: boolean;
}

export interface PasswordResult {
  checks: PasswordCheck[];
  /** True when every check passes. */
  ok: boolean;
  /** Individual character-class flags exposed for richer UI hints. */
  classes: {
    lower: boolean;
    upper: boolean;
    digit: boolean;
    special: boolean;
  };
}

export function validateNewPassword(pw: string): PasswordResult {
  const lower = /[a-z]/.test(pw);
  const upper = /[A-Z]/.test(pw);
  const digit = /[0-9]/.test(pw);
  const special = /[^a-zA-Z0-9]/.test(pw);
  const classCount = [lower, upper, digit, special].filter(Boolean).length;

  const byteLen = new TextEncoder().encode(pw).length;

  const checks: PasswordCheck[] = [
    {
      id: 'min-length',
      label: `At least ${MIN_LENGTH} characters`,
      passed: pw.length >= MIN_LENGTH,
    },
    {
      id: 'max-bytes',
      label: `${MAX_BYTES} bytes or fewer (bcrypt limit)`,
      passed: byteLen <= MAX_BYTES,
    },
    {
      id: 'char-classes',
      label: `At least ${MIN_CLASSES} of 4 character classes (lowercase, uppercase, digit, special)`,
      passed: classCount >= MIN_CLASSES,
    },
  ];

  return {
    checks,
    ok: checks.every((c) => c.passed),
    classes: { lower, upper, digit, special },
  };
}
